//! Multi-part URs: the fountain (Luby transform) code of BCR-2020-005.
//!
//! A message is cut into `seq_len` fragments of equal length, the last one
//! padded with zeros. Part `seq_num` is the XOR of a set of fragments that
//! both sides derive from `seq_num`, `seq_len` and the message checksum: the
//! one fragment `seq_num - 1` up to `seq_len`, then a pseudo-random set. Which
//! set is a matter of reproducing the reference implementation to the bit,
//! floating-point arithmetic included.

use super::bytewords::{self, Style};
use super::{Error, Ur, crc32, validate_type};
use crate::cbor::{read_head, write_head};
use crate::hash::sha256_once;
use crate::prelude::*;

/// The Xoshiro256** generator, seeded from a SHA-256 digest.
struct Xoshiro256([u64; 4]);

impl Xoshiro256 {
    fn new(seed: &[u8]) -> Self {
        let digest = sha256_once(seed);
        let mut state = [0u64; 4];
        for (word, bytes) in state.iter_mut().zip(digest.as_chunks::<8>().0) {
            *word = u64::from_be_bytes(*bytes);
        }
        Xoshiro256(state)
    }

    fn next(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// A number in `[0, 1)`, from the 53 high bits: dividing all 64 by 2^64,
    /// as the reference does, rounds its largest values up to 1.0, which
    /// would index one past the end of what is being picked from.
    fn next_double(&mut self) -> f64 {
        const SCALE: f64 = 1.0 / (1u64 << 53) as f64;
        (self.next() >> 11) as f64 * SCALE
    }

    /// A number in `0..count`.
    fn next_index(&mut self, count: usize) -> usize {
        (self.next_double() * count as f64) as usize
    }
}

/// Picks how many fragments a part mixes: degree `d` with a probability
/// proportional to `1/d`, sampled with Vose's alias method. It only depends on
/// `seq_len`, so it is built once per message.
struct DegreeSampler {
    probs: Vec<f64>,
    aliases: Vec<u32>,
}

impl DegreeSampler {
    fn new(seq_len: u32) -> Self {
        let n = seq_len as usize;
        let mut sum = 0.0;
        for degree in 1..=n {
            sum += 1.0 / degree as f64;
        }
        let mut weights: Vec<f64> = (1..=n)
            .map(|degree| 1.0 / degree as f64 * n as f64 / sum)
            .collect();

        let (mut small, mut large) = (Vec::new(), Vec::new());
        for i in (0..n).rev() {
            if weights[i] < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }

        let mut probs = vec![0.0; n];
        let mut aliases = vec![0u32; n];
        while let (Some(&a), Some(&g)) = (small.last(), large.last()) {
            small.pop();
            large.pop();
            probs[a] = weights[a];
            aliases[a] = g as u32;
            weights[g] += weights[a] - 1.0;
            if weights[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }
        // `small` is only left with entries through rounding errors.
        for i in large.into_iter().chain(small) {
            probs[i] = 1.0;
        }
        DegreeSampler { probs, aliases }
    }

    fn next(&self, rng: &mut Xoshiro256) -> usize {
        let r1 = rng.next_double();
        let r2 = rng.next_double();
        let i = (self.probs.len() as f64 * r1) as usize;
        let index = if r2 < self.probs[i] {
            i
        } else {
            self.aliases[i] as usize
        };
        index + 1
    }
}

/// The indexes of the fragments XORed into part `seq_num`, in ascending order.
fn choose_fragments(
    seq_num: u32,
    seq_len: u32,
    checksum: u32,
    sampler: &mut Option<DegreeSampler>,
) -> Vec<u32> {
    if seq_num <= seq_len {
        return vec![seq_num - 1];
    }
    let mut seed = [0u8; 8];
    seed[..4].copy_from_slice(&seq_num.to_be_bytes());
    seed[4..].copy_from_slice(&checksum.to_be_bytes());
    let mut rng = Xoshiro256::new(&seed);

    let sampler = sampler.get_or_insert_with(|| DegreeSampler::new(seq_len));
    let degree = sampler.next(&mut rng);
    // The reference shuffles all the indexes, by picking them at random one
    // after the other, and keeps the first `degree`: stop there.
    let mut remaining: Vec<u32> = (0..seq_len).collect();
    let mut chosen: Vec<u32> = (0..degree)
        .map(|_| remaining.remove(rng.next_index(remaining.len())))
        .collect();
    chosen.sort_unstable();
    chosen
}

fn xor_into(target: &mut [u8], source: &[u8]) {
    for (t, s) in target.iter_mut().zip(source) {
        *t ^= s;
    }
}

/// Produces the parts of a multi-part UR.
///
/// The first [`fragment_count`](Self::fragment_count) parts hold the message
/// in order, and are all a receiver needs when it misses none. The parts after
/// them mix fragments at random, and there is no end to them: keep showing
/// parts until the receiver is done. A message that fits in one fragment comes
/// out as a plain single-part UR.
///
/// The encoder is also an endless [`Iterator`] over its parts.
pub struct Encoder {
    ur_type: String,
    /// The message, padded with zeros to a whole number of fragments.
    message: Vec<u8>,
    message_len: u32,
    fragment_len: usize,
    seq_len: u32,
    seq_num: u32,
    checksum: u32,
    sampler: Option<DegreeSampler>,
}

impl Encoder {
    /// Prepares `cbor`, the CBOR payload of a UR of type `ur_type`, to be sent
    /// as fragments of at most `max_fragment_len` bytes each. The fragments
    /// are all of the same length, the shortest that keeps their number.
    ///
    /// A part is about `2 * fragment_len + 50` characters long: each byte
    /// takes two, plus the type, the sequence and the part header.
    pub fn new(ur_type: &str, cbor: &[u8], max_fragment_len: usize) -> Result<Self, Error> {
        validate_type(ur_type, false)?;
        if cbor.is_empty() {
            return Err(Error::EmptyMessage);
        }
        if max_fragment_len == 0 {
            return Err(Error::InvalidFragmentLen);
        }
        let message_len = u32::try_from(cbor.len()).map_err(|_| Error::TooLarge)?;
        let fragment_len = cbor.len().div_ceil(cbor.len().div_ceil(max_fragment_len));
        let seq_len = cbor.len().div_ceil(fragment_len);

        let mut message = cbor.to_vec();
        message.resize(seq_len * fragment_len, 0);
        Ok(Encoder {
            ur_type: ur_type.to_string(),
            message,
            message_len,
            fragment_len,
            seq_len: seq_len as u32,
            seq_num: 0,
            checksum: crc32(cbor),
            sampler: None,
        })
    }

    /// The number of fragments the message is cut into.
    pub fn fragment_count(&self) -> usize {
        self.seq_len as usize
    }

    /// The length of each fragment, in bytes.
    pub fn fragment_len(&self) -> usize {
        self.fragment_len
    }

    /// Whether the message fits a single-part UR, which every call to
    /// [`next_part`](Self::next_part) then returns.
    pub fn is_single_part(&self) -> bool {
        self.seq_len == 1
    }

    /// The sequence number of the last part produced, 0 before the first.
    pub fn current_sequence(&self) -> u32 {
        self.seq_num
    }

    /// Whether every fragment has been produced once, which is all a receiver
    /// that missed none needs.
    pub fn is_complete(&self) -> bool {
        self.seq_num >= self.seq_len
    }

    /// Produces the next part.
    pub fn next_part(&mut self) -> String {
        // Sequence numbers start at 1, and start over in the unlikely event
        // that they run out.
        self.seq_num = self.seq_num.checked_add(1).unwrap_or(1);
        if self.is_single_part() {
            let cbor = &self.message[..self.message_len as usize];
            let body = bytewords::encode(cbor, Style::Minimal);
            return format!("ur:{}/{body}", self.ur_type);
        }

        let indexes =
            choose_fragments(self.seq_num, self.seq_len, self.checksum, &mut self.sampler);
        let mut data = vec![0u8; self.fragment_len];
        for index in indexes {
            let start = index as usize * self.fragment_len;
            xor_into(&mut data, &self.message[start..start + self.fragment_len]);
        }

        let mut part = Vec::with_capacity(self.fragment_len + 24);
        write_head(&mut part, 4, 5);
        write_head(&mut part, 0, self.seq_num as u64);
        write_head(&mut part, 0, self.seq_len as u64);
        write_head(&mut part, 0, self.message_len as u64);
        write_head(&mut part, 0, self.checksum as u64);
        write_head(&mut part, 2, data.len() as u64);
        part.extend_from_slice(&data);

        let body = bytewords::encode(&part, Style::Minimal);
        format!(
            "ur:{}/{}-{}/{body}",
            self.ur_type, self.seq_num, self.seq_len
        )
    }
}

impl Iterator for Encoder {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        Some(self.next_part())
    }
}

/// A decoded fountain part: `[seq_num, seq_len, message_len, checksum, data]`.
struct Part<'a> {
    seq_num: u32,
    seq_len: u32,
    message_len: u32,
    checksum: u32,
    data: &'a [u8],
}

impl<'a> Part<'a> {
    fn parse(cbor: &'a [u8]) -> Result<Self, Error> {
        let mut pos = 0;
        let mut head = |major: u8| match read_head(cbor, &mut pos) {
            Ok((m, arg, false)) if m == major => Ok(arg),
            _ => Err(Error::InvalidPart),
        };
        if head(4)? != 5 {
            return Err(Error::InvalidPart);
        }
        let mut uint = || u32::try_from(head(0)?).map_err(|_| Error::InvalidPart);
        let (seq_num, seq_len, message_len, checksum) = (uint()?, uint()?, uint()?, uint()?);
        let data_len = head(2)?;
        match cbor.get(pos..) {
            Some(data) if data.len() as u64 == data_len => Ok(Part {
                seq_num,
                seq_len,
                message_len,
                checksum,
                data,
            }),
            _ => Err(Error::InvalidPart),
        }
    }
}

/// What every part of a message agrees on.
#[derive(PartialEq, Eq)]
struct Shape {
    seq_len: u32,
    message_len: u32,
    checksum: u32,
    fragment_len: usize,
}

/// A part that still mixes several unknown fragments.
struct Mixed {
    /// Which fragments, a bit each: bit `index % 64` of word `index / 64`.
    /// That is `seq_len / 8` bytes whatever the part mixes, where a list of
    /// indexes takes up to `4 * seq_len`.
    bits: Vec<u64>,
    /// How many: two or more for a part on hold.
    count: usize,
    data: Vec<u8>,
}

impl Mixed {
    fn new(indexes: &[u32], seq_len: usize, data: Vec<u8>) -> Self {
        let mut bits = vec![0u64; seq_len.div_ceil(64)];
        for &index in indexes {
            bits[index as usize / 64] |= 1 << (index % 64);
        }
        Mixed {
            bits,
            count: indexes.len(),
            data,
        }
    }

    fn has(&self, index: usize) -> bool {
        self.bits[index / 64] & (1 << (index % 64)) != 0
    }

    /// The lowest fragment mixed in.
    fn first(&self) -> Option<usize> {
        let word = self.bits.iter().position(|&word| word != 0)?;
        Some(word * 64 + self.bits[word].trailing_zeros() as usize)
    }

    /// Whether every fragment of `other` is in this part too.
    fn covers(&self, other: &Mixed) -> bool {
        self.bits
            .iter()
            .zip(&other.bits)
            .all(|(mine, theirs)| theirs & !mine == 0)
    }

    /// XORs out one fragment that this part mixes.
    fn remove_fragment(&mut self, index: usize, fragment: &[u8]) {
        self.bits[index / 64] &= !(1 << (index % 64));
        self.count -= 1;
        xor_into(&mut self.data, fragment);
    }

    /// XORs out `other`, which this part [`covers`](Self::covers).
    fn remove_part(&mut self, other: &Mixed) {
        for (mine, theirs) in self.bits.iter_mut().zip(&other.bits) {
            *mine &= !theirs;
        }
        self.count -= other.count;
        xor_into(&mut self.data, &other.data);
    }
}

/// Parts on hold are XORed out of those that cover them up to this many
/// fragments. That saves a receiver of a typical message, of ten or twenty
/// fragments, one part in five. It saves nothing past a couple of hundred,
/// where looking for such parts is what takes ever longer.
const MAX_FRAGMENTS_FOR_SUBSETS: usize = 256;

/// What the parts on hold may take on top of twice the message: their sets
/// of fragments, mostly. Up to the default limit on fragments, that is about
/// what twice as many parts as fragments need.
const HELD_ALLOWANCE: usize = 4 << 20;

/// Puts the parts of a UR back together, in whatever order they come, however
/// many times, and whichever got lost.
///
/// Feed it each scanned string with [`receive`](Self::receive) until it is
/// complete: single-part URs are after the first. A decoder handles one
/// message: once it has seen a part, parts of another message are an error,
/// and [`reset`](Self::reset) starts over.
///
/// What parts claim is not trusted: a message cannot be longer than
/// [`DEFAULT_MAX_MESSAGE_LEN`](Self::DEFAULT_MAX_MESSAGE_LEN) nor have more
/// than [`DEFAULT_MAX_FRAGMENTS`](Self::DEFAULT_MAX_FRAGMENTS) fragments
/// unless [`with_limits`](Self::with_limits) says otherwise.
///
/// # Memory and time
///
/// A decoder holds the message, padded to a whole number of fragments (less
/// than one byte per fragment), and the parts it cannot make use of yet. Those
/// are dropped past twice the number of fragments, and past what fits in
/// twice the padded message plus 4 MiB: whatever is sent, a decoder allocates
/// about three times the length of the message it was told of, plus 4 MiB,
/// and no more than that. A dropped part costs nothing but the wait for
/// another one. Only messages of thousands of fragments, more than the
/// default limit allows unless they are of a few bytes each, have that budget
/// hold fewer parts than twice their fragments.
///
/// A part takes the time to pick its fragments, which grows with the number
/// of fragments squared, and to compare it with the parts on hold. A part
/// that reveals a fragment is then XORed out of the parts on hold that mix
/// it, each of which may reveal another: that is one fragment's worth of work
/// for each fragment a part on hold mixes, once. All the parts of a message
/// together thus cost at most the length of what is on hold times the number
/// of fragments, most of it in the part that lets the bulk of the message
/// unravel. That is what decoding takes, and why the limits are worth
/// lowering to what the application expects.
pub struct Decoder {
    max_message_len: usize,
    max_fragments: usize,
    /// How many parts may be on hold, once the message is known.
    max_held: usize,
    ur_type: Option<String>,
    shape: Option<Shape>,
    /// The fragments, each in its place once known.
    message: Vec<u8>,
    known: Vec<bool>,
    known_count: usize,
    mixed: Vec<Mixed>,
    sampler: Option<DegreeSampler>,
    complete: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// The longest message accepted by default: 8 MiB.
    pub const DEFAULT_MAX_MESSAGE_LEN: usize = 8 << 20;
    /// The most fragments accepted by default: far more than anyone would
    /// sit through, and few enough for picking the fragments of the worst
    /// part to take milliseconds. The way the specification has it, that
    /// takes a time that grows with their number, squared.
    pub const DEFAULT_MAX_FRAGMENTS: usize = 4096;

    /// Creates a decoder with the default limits.
    pub fn new() -> Self {
        Self::with_limits(Self::DEFAULT_MAX_MESSAGE_LEN, Self::DEFAULT_MAX_FRAGMENTS)
    }

    /// Creates a decoder that refuses, with [`Error::TooLarge`], messages of
    /// more than `max_message_len` bytes or `max_fragments` fragments. The
    /// memory and time a message can cost follow from both: see
    /// [`Decoder`].
    pub fn with_limits(max_message_len: usize, max_fragments: usize) -> Self {
        Decoder {
            max_message_len,
            max_fragments,
            max_held: 0,
            ur_type: None,
            shape: None,
            message: Vec::new(),
            known: Vec::new(),
            known_count: 0,
            mixed: Vec::new(),
            sampler: None,
            complete: false,
        }
    }

    /// Forgets everything received, keeping the limits.
    pub fn reset(&mut self) {
        *self = Self::with_limits(self.max_message_len, self.max_fragments);
    }

    /// Whether the whole message has been received.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The UR type, in lowercase, once a part has been received.
    ///
    /// Check it before making anything of the [`message`](Self::message): it
    /// says what the CBOR is, and any well-formed UR completes a decoder.
    pub fn ur_type(&self) -> Option<&str> {
        self.ur_type.as_deref()
    }

    /// The message, a CBOR payload of type [`ur_type`](Self::ur_type), once
    /// complete.
    pub fn message(&self) -> Option<&[u8]> {
        self.complete.then_some(&self.message[..])
    }

    /// The number of fragments in the message, 0 until a part has been
    /// received.
    pub fn fragment_count(&self) -> usize {
        self.known.len()
    }

    /// The number of fragments recovered so far.
    pub fn received_fragment_count(&self) -> usize {
        self.known_count
    }

    /// Takes in a UR string. Returns whether the message is now complete.
    ///
    /// Parts already seen, and any part once complete, are ignored. An error
    /// leaves the decoder as it was, except for [`Error::BadChecksum`] on the
    /// reassembled message, after which it is [`reset`](Self::reset).
    pub fn receive(&mut self, text: &str) -> Result<bool, Error> {
        if self.complete {
            return Ok(true);
        }
        let ur = Ur::parse(text)?;
        if let Some(ur_type) = &self.ur_type
            && !ur_type.eq_ignore_ascii_case(ur.ur_type)
        {
            return Err(Error::TypeMismatch);
        }
        let body = ur.decode()?;

        let Some((seq_num, seq_len)) = ur.sequence else {
            if self.shape.is_some() {
                return Err(Error::InconsistentPart);
            }
            if body.len() > self.max_message_len {
                return Err(Error::TooLarge);
            }
            self.ur_type = Some(ur.ur_type.to_ascii_lowercase());
            self.known = vec![true];
            self.known_count = 1;
            self.message = body;
            self.complete = true;
            return Ok(true);
        };

        let part = Part::parse(&body)?;
        if (part.seq_num, part.seq_len) != (seq_num, seq_len) {
            return Err(Error::InvalidSequence);
        }
        let shape = Shape {
            seq_len,
            message_len: part.message_len,
            checksum: part.checksum,
            fragment_len: part.data.len(),
        };
        match &self.shape {
            Some(expected) if *expected != shape => return Err(Error::InconsistentPart),
            Some(_) => {}
            None => self.start(shape)?,
        }
        if self.ur_type.is_none() {
            self.ur_type = Some(ur.ur_type.to_ascii_lowercase());
        }

        let indexes = choose_fragments(seq_num, seq_len, part.checksum, &mut self.sampler);
        self.reduce(Mixed::new(&indexes, seq_len as usize, part.data.to_vec()));
        if self.known_count == self.known.len() {
            self.finish()?;
        }
        Ok(self.complete)
    }

    /// Checks the first part of a message, and makes room for the message.
    fn start(&mut self, shape: Shape) -> Result<(), Error> {
        let message_len = shape.message_len as usize;
        let seq_len = shape.seq_len as usize;
        if message_len == 0 || shape.fragment_len == 0 {
            return Err(Error::InvalidPart);
        }
        // Fragments are of equal length and only the last one is padded, so
        // their number follows from the lengths.
        if message_len.div_ceil(shape.fragment_len) != seq_len {
            return Err(Error::InvalidPart);
        }
        // And they are as short as that number allows, which is what encoders
        // pick: told of a longest fragment, they make them all shorter rather
        // than pad the last one more than it takes. That has the padding
        // below one byte per fragment, when a lone fragment of any length
        // could otherwise claim to hold a message of one byte.
        if shape.fragment_len != message_len.div_ceil(seq_len) {
            return Err(Error::InvalidPart);
        }
        if message_len > self.max_message_len || seq_len > self.max_fragments {
            return Err(Error::TooLarge);
        }
        let padded_len = seq_len
            .checked_mul(shape.fragment_len)
            .ok_or(Error::TooLarge)?;

        // Parts on hold are only worth so much memory. Past twice the
        // fragments, a sender that makes sense would have had the message
        // through already. And each takes a fragment and a bit per fragment,
        // which for a message in very many, very short fragments is far more
        // than the message: no more of them than fit in twice the message
        // and a fixed allowance, then.
        let held_len = Self::held_len(seq_len, shape.fragment_len);
        let budget = padded_len.saturating_mul(2).saturating_add(HELD_ALLOWANCE);
        self.max_held = (budget / held_len).min(seq_len.saturating_mul(2).saturating_add(16));

        self.message = vec![0; padded_len];
        self.known = vec![false; seq_len];
        self.shape = Some(shape);
        Ok(())
    }

    /// The memory a part on hold takes.
    fn held_len(seq_len: usize, fragment_len: usize) -> usize {
        core::mem::size_of::<Mixed>() + seq_len.div_ceil(64) * 8 + fragment_len
    }

    fn fragment_len(&self) -> usize {
        self.shape.as_ref().map_or(0, |shape| shape.fragment_len)
    }

    /// Takes a part in: XORs out of it what is known, then either it is down
    /// to one fragment, which is now known and may in turn simplify the parts
    /// on hold, or it is put on hold.
    ///
    /// Parts on hold never mix a known fragment. Those that get simpler do
    /// so where they are, and those the queue takes are moved to it: nothing
    /// here copies a part, nor the parts on hold.
    fn reduce(&mut self, part: Mixed) {
        let fragment_len = self.fragment_len();
        let with_subsets = self.known.len() <= MAX_FRAGMENTS_FOR_SUBSETS;
        let mut queue = vec![part];
        while let Some(mut part) = queue.pop() {
            for word in 0..part.bits.len() {
                let mut left = part.bits[word];
                while left != 0 {
                    let index = word * 64 + left.trailing_zeros() as usize;
                    left &= left - 1;
                    if self.known[index] {
                        let start = index * fragment_len;
                        part.remove_fragment(index, &self.message[start..start + fragment_len]);
                    }
                }
            }
            // A part on hold that this one covers can be XORed out of it too.
            for held in self.mixed.iter().filter(|_| with_subsets) {
                if held.count < part.count && part.covers(held) {
                    part.remove_part(held);
                }
            }

            match (part.count, part.first()) {
                (0, _) | (_, None) => {}
                (1, Some(index)) => {
                    let start = index * fragment_len;
                    self.message[start..start + fragment_len].copy_from_slice(&part.data);
                    self.known[index] = true;
                    self.known_count += 1;
                    // Parts on hold that mix this fragment get simpler. Those
                    // down to one fragment are done with, and any of them may
                    // now be covered by another, or cover one.
                    queue.extend(self.mixed.extract_if(.., |held| {
                        if !held.has(index) {
                            return false;
                        }
                        held.remove_fragment(index, &part.data);
                        held.count == 1 || with_subsets
                    }));
                }
                _ => {
                    if self
                        .mixed
                        .iter()
                        .any(|held| held.count == part.count && held.bits == part.bits)
                    {
                        continue;
                    }
                    // Parts on hold that cover this one get simpler, once it
                    // is on hold itself: taking them out makes room for it.
                    if with_subsets {
                        queue.extend(
                            self.mixed.extract_if(.., |held| {
                                held.count > part.count && held.covers(&part)
                            }),
                        );
                    }
                    if self.mixed.len() < self.max_held {
                        self.mixed.push(part);
                    }
                }
            }
        }
    }

    /// Checks the reassembled message.
    fn finish(&mut self) -> Result<(), Error> {
        let (message_len, checksum) = match &self.shape {
            Some(shape) => (shape.message_len as usize, shape.checksum),
            None => return Ok(()),
        };
        let padding_is_zero = self.message[message_len..].iter().all(|&b| b == 0);
        self.message.truncate(message_len);
        if !padding_is_zero || crc32(&self.message) != checksum {
            self.reset();
            return Err(Error::BadChecksum);
        }
        self.mixed = Vec::new();
        self.sampler = None;
        self.complete = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Known answers from the reference implementations (BlockchainCommons
    //! bc-ur, and its Rust port ur-rs).

    use super::*;

    /// The reference test message: `len` bytes out of the generator.
    fn make_message(seed: &str, len: usize) -> Vec<u8> {
        let mut rng = Xoshiro256::new(seed.as_bytes());
        (0..len).map(|_| rng.next_index(256) as u8).collect()
    }

    #[test]
    fn xoshiro_vectors() {
        let mut rng = Xoshiro256::new(b"Wolf");
        let expected = [
            42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88, 37, 25, 82,
            13, 69, 59, 30, 39, 11, 82, 19, 99, 45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4,
            92, 44, 68, 92, 69, 1, 42, 89, 50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98, 82, 89, 24,
            43, 85, 39, 15, 3, 99, 29, 20, 42, 27, 10, 85, 66, 50, 35, 69, 70, 70, 74, 30, 13, 72,
            54, 11, 5, 70, 55, 91, 52, 10, 43, 43, 52,
        ];
        for e in expected {
            assert_eq!(rng.next() % 100, e);
        }

        let mut rng = Xoshiro256::new(b"Wolf");
        let expected = [
            6, 5, 8, 4, 10, 5, 7, 10, 4, 9, 10, 9, 7, 7, 1, 1, 2, 9, 9, 2, 6, 4, 5, 7, 8, 5, 4, 2,
            3, 8, 7, 4, 5, 1, 10, 9, 3, 10, 2, 6, 8, 5, 7, 9, 3, 1, 5, 2, 7, 1, 4, 4, 4, 4, 9, 4,
            5, 5, 6, 9, 5, 1, 2, 8, 3, 3, 2, 8, 4, 3, 2, 1, 10, 8, 9, 3, 10, 8, 5, 5, 6, 7, 10, 5,
            8, 9, 4, 6, 4, 2, 10, 2, 1, 7, 9, 6, 7, 4, 2, 5,
        ];
        for e in expected {
            assert_eq!(rng.next_index(10) + 1, e);
        }
    }

    #[test]
    fn degree_vectors() {
        let sampler = DegreeSampler::new(11);
        let expected = [
            11, 3, 6, 5, 2, 1, 2, 11, 1, 3, 9, 10, 10, 4, 2, 1, 1, 2, 1, 1, 5, 2, 4, 10, 3, 2, 1,
            1, 3, 11, 2, 6, 2, 9, 9, 2, 6, 7, 2, 5, 2, 4, 3, 1, 6, 11, 2, 11, 3, 1, 6, 3, 1, 4, 5,
            3, 6, 1, 1, 3, 1, 2, 2, 1, 4, 5, 1, 1, 9, 1, 1, 6, 4, 1, 5, 1, 2, 2, 3, 1, 1, 5, 2, 6,
            1, 7, 11, 1, 8, 1, 5, 1, 1, 2, 2, 6, 4, 10, 1, 2, 5, 5, 5, 1, 1, 4, 1, 1, 1, 3, 5, 5,
            5, 1, 4, 3, 3, 5, 1, 11, 3, 2, 8, 1, 2, 1, 1, 4, 5, 2, 1, 1, 1, 5, 6, 11, 10, 7, 4, 7,
            1, 5, 3, 1, 1, 9, 1, 2, 5, 5, 2, 2, 3, 10, 1, 3, 2, 3, 3, 1, 1, 2, 1, 3, 2, 2, 1, 3, 8,
            4, 1, 11, 6, 3, 1, 1, 1, 1, 1, 3, 1, 2, 1, 10, 1, 1, 8, 2, 7, 1, 2, 1, 9, 2, 10, 2, 1,
            3, 4, 10,
        ];
        for (nonce, e) in expected.into_iter().enumerate() {
            let mut rng = Xoshiro256::new(format!("Wolf-{}", nonce + 1).as_bytes());
            assert_eq!(sampler.next(&mut rng), e, "nonce {}", nonce + 1);
        }
    }

    #[test]
    fn fragment_choice_vectors() {
        let message = make_message("Wolf", 1024);
        let checksum = crc32(&message);
        let expected: [&[u32]; 30] = [
            &[0],
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[8],
            &[9],
            &[10],
            &[9],
            &[2, 5, 6, 8, 9, 10],
            &[8],
            &[1, 5],
            &[1],
            &[0, 2, 4, 5, 8, 10],
            &[5],
            &[2],
            &[2],
            &[0, 1, 3, 4, 5, 7, 9, 10],
            &[0, 1, 2, 3, 5, 6, 8, 9, 10],
            &[0, 2, 4, 5, 7, 8, 9, 10],
            &[3, 5],
            &[4],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            &[0, 1, 3, 4, 5, 6, 7, 9, 10],
            &[6],
            &[5, 6],
            &[7],
        ];
        let mut sampler = None;
        for (i, e) in expected.into_iter().enumerate() {
            let chosen = choose_fragments(i as u32 + 1, 11, checksum, &mut sampler);
            assert_eq!(chosen, e, "part {}", i + 1);
        }
    }

    #[test]
    fn encoder_vectors() {
        let cbor = crate::bcur::bytes_to_cbor(&make_message("Wolf", 256));
        let mut encoder = Encoder::new("bytes", &cbor, 30).unwrap();
        assert_eq!(encoder.fragment_count(), 9);
        assert_eq!(encoder.fragment_len(), 29);
        assert!(!encoder.is_single_part());
        let expected = [
            "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
            "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
            "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
            "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
            "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
            "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
            "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
            "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
            "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
            "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
            "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
            "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
            "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
            "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
            "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
            "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
            "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
            "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
            "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
            "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
        ];
        for (i, e) in expected.into_iter().enumerate() {
            assert_eq!(encoder.current_sequence() as usize, i);
            assert_eq!(encoder.is_complete(), i >= 9);
            assert_eq!(encoder.next_part(), e);
        }
    }

    #[test]
    fn fragment_lengths() {
        let len = |message_len: usize, max: usize| {
            let encoder = Encoder::new("bytes", &vec![1; message_len], max).unwrap();
            (encoder.fragment_len(), encoder.fragment_count())
        };
        assert_eq!(len(12345, 1955), (1764, 7));
        assert_eq!(len(12345, 30000), (12345, 1));
        assert_eq!(len(10, 4), (4, 3));
        assert_eq!(len(10, 5), (5, 2));
        assert_eq!(len(10, 6), (5, 2));
        assert_eq!(len(10, 10), (10, 1));
        assert_eq!(len(10, 1), (1, 10));

        assert_eq!(
            Encoder::new("bytes", &[], 10).err(),
            Some(Error::EmptyMessage)
        );
        assert_eq!(
            Encoder::new("bytes", &[1], 0).err(),
            Some(Error::InvalidFragmentLen)
        );
        assert_eq!(
            Encoder::new("Bytes", &[1], 10).err(),
            Some(Error::InvalidType)
        );
        assert_eq!(Encoder::new("", &[1], 10).err(), Some(Error::InvalidType));
    }

    #[test]
    fn decodes_in_order() {
        let cbor = crate::bcur::bytes_to_cbor(&make_message("Wolf", 32767));
        let mut encoder = Encoder::new("bytes", &cbor, 1000).unwrap();
        let mut decoder = Decoder::new();
        assert_eq!(decoder.fragment_count(), 0);
        for part in encoder.by_ref().take(33) {
            assert!(!decoder.is_complete());
            assert_eq!(decoder.message(), None);
            decoder.receive(&part).unwrap();
        }
        assert!(decoder.is_complete());
        assert_eq!(decoder.fragment_count(), 33);
        assert_eq!(decoder.received_fragment_count(), 33);
        assert_eq!(decoder.ur_type(), Some("bytes"));
        assert_eq!(decoder.message(), Some(&cbor[..]));
        // more parts change nothing
        assert_eq!(decoder.receive(&encoder.next_part()), Ok(true));
        assert_eq!(decoder.receive("garbage"), Ok(true));
    }

    /// Whatever gets lost, the parts that do arrive end up being enough.
    #[test]
    fn decodes_lossy_streams() {
        let cbor = crate::bcur::bytes_to_cbor(&make_message("Wolf", 3000));
        for (keep, skip) in [(1, 1), (2, 1), (1, 3), (3, 2)] {
            let mut decoder = Decoder::new();
            // from part 20 on: no fragment comes on its own
            let parts = Encoder::new("crypto-psbt", &cbor, 100).unwrap().skip(19);
            let mut used = 0;
            for (i, part) in parts.enumerate() {
                assert!(i < 2000, "keep {keep} skip {skip}: no progress");
                if i % (keep + skip) >= keep {
                    continue;
                }
                used += 1;
                // QR codes carry them in uppercase, and see them many times
                let part = part.to_ascii_uppercase();
                decoder.receive(&part).unwrap();
                if decoder.receive(&part).unwrap() {
                    break;
                }
            }
            assert_eq!(decoder.message(), Some(&cbor[..]));
            assert_eq!(decoder.ur_type(), Some("crypto-psbt"));
            // 30 fragments: a fountain code needs few more parts than that
            assert!(used < 60, "keep {keep} skip {skip}: {used} parts");
        }
    }

    #[test]
    fn decodes_reverse_order() {
        let cbor = make_message("Wolf", 500);
        let mut parts: Vec<String> = Encoder::new("bytes", &cbor, 50).unwrap().take(10).collect();
        parts.reverse();
        let mut decoder = Decoder::new();
        for (i, part) in parts.iter().enumerate() {
            assert_eq!(decoder.receive(part), Ok(i == 9));
            assert_eq!(decoder.received_fragment_count(), i + 1);
        }
        assert_eq!(decoder.message(), Some(&cbor[..]));
    }

    #[test]
    fn single_part_messages() {
        let cbor = make_message("Wolf", 50);
        let mut encoder = Encoder::new("bytes", &cbor, 100).unwrap();
        assert!(encoder.is_single_part());
        let part = encoder.next_part();
        assert_eq!(part, crate::bcur::encode("bytes", &cbor).unwrap());
        assert_eq!(encoder.next_part(), part);

        let mut decoder = Decoder::new();
        assert_eq!(decoder.receive(&part), Ok(true));
        assert_eq!(decoder.message(), Some(&cbor[..]));
        assert_eq!(
            (decoder.fragment_count(), decoder.received_fragment_count()),
            (1, 1)
        );

        // other encoders send them as a one-fragment multi-part UR, and then
        // as "mixes" of that one fragment
        for seq_num in [1, 2, 7] {
            let mut decoder = Decoder::new();
            let part = forged_part(seq_num, 1, 50, crc32(&cbor), &cbor);
            assert_eq!(decoder.receive(&part), Ok(true));
            assert_eq!(decoder.message(), Some(&cbor[..]));
        }
    }

    #[test]
    fn rejects_inconsistent_parts() {
        let a = make_message("Wolf", 500);
        let b = make_message("Fox", 500);
        let part_a = |n: usize| Encoder::new("bytes", &a, 50).unwrap().nth(n).unwrap();

        let mut decoder = Decoder::new();
        assert_eq!(decoder.receive(&part_a(0)), Ok(false));
        // another message, another type, another fragment length, a single part
        let other = Encoder::new("bytes", &b, 50).unwrap().next_part();
        assert_eq!(decoder.receive(&other), Err(Error::InconsistentPart));
        let other = Encoder::new("psbt", &a, 50).unwrap().next_part();
        assert_eq!(decoder.receive(&other), Err(Error::TypeMismatch));
        let other = Encoder::new("bytes", &a, 25).unwrap().next_part();
        assert_eq!(decoder.receive(&other), Err(Error::InconsistentPart));
        let other = crate::bcur::encode("bytes", &a).unwrap();
        assert_eq!(decoder.receive(&other), Err(Error::InconsistentPart));
        // the sequence in the string must be the one in the part
        let other = part_a(1).replace("/2-10/", "/3-10/");
        assert_eq!(decoder.receive(&other), Err(Error::InvalidSequence));
        assert_eq!(
            decoder.receive("ur:bytes/2-10/aeadaolazmjendeoti"),
            Err(Error::InvalidPart)
        );
        assert_eq!(
            decoder.receive("bytes/2-10/aeadaolazmjendeoti"),
            Err(Error::InvalidScheme)
        );

        // none of which got in the way
        assert_eq!(decoder.received_fragment_count(), 1);
        for n in 1..10 {
            assert_eq!(decoder.receive(&part_a(n)), Ok(n == 9));
        }
        assert_eq!(decoder.message(), Some(&a[..]));

        decoder.reset();
        assert_eq!(decoder.ur_type(), None);
        assert_eq!(decoder.receive(&other_message_part(&b)), Ok(false));
    }

    fn other_message_part(message: &[u8]) -> String {
        Encoder::new("bytes", message, 50).unwrap().next_part()
    }

    /// Builds a part by hand, to claim whatever.
    fn forged_part(
        seq_num: u32,
        seq_len: u32,
        message_len: u32,
        checksum: u32,
        data: &[u8],
    ) -> String {
        let mut part = Vec::new();
        write_head(&mut part, 4, 5);
        for value in [seq_num, seq_len, message_len, checksum] {
            write_head(&mut part, 0, value as u64);
        }
        write_head(&mut part, 2, data.len() as u64);
        part.extend_from_slice(data);
        let body = bytewords::encode(&part, Style::Minimal);
        format!("ur:bytes/{seq_num}-{seq_len}/{body}")
    }

    #[test]
    fn bounds_what_parts_claim() {
        let mut decoder = Decoder::new();
        // 4 GiB in fragments of one byte
        let part = forged_part(1, u32::MAX, u32::MAX, 0, &[0]);
        assert_eq!(decoder.receive(&part), Err(Error::TooLarge));
        // a fragment count that does not follow from the lengths
        let part = forged_part(1, 1000, 10, 0, &[0; 5]);
        assert_eq!(decoder.receive(&part), Err(Error::InvalidPart));
        let part = forged_part(1, 0, 0, 0, &[]);
        assert_eq!(decoder.receive(&part), Err(Error::InvalidSequence));
        let part = forged_part(1, 1, 0, 0, &[]);
        assert_eq!(decoder.receive(&part), Err(Error::InvalidPart));

        let mut decoder = Decoder::with_limits(100, 10);
        assert_eq!(
            decoder.receive(&forged_part(1, 1, 101, 0, &[0; 101])),
            Err(Error::TooLarge)
        );
        assert_eq!(
            decoder.receive(&forged_part(1, 11, 11, 0, &[0])),
            Err(Error::TooLarge)
        );
        assert_eq!(
            decoder.receive(&crate::bcur::encode("bytes", &[0; 101]).unwrap()),
            Err(Error::TooLarge)
        );
        assert_eq!(
            decoder.receive(&forged_part(1, 10, 100, 0, &[0; 10])),
            Ok(false)
        );

        // a message that does not add up to its checksum, or with padding
        let mut decoder = Decoder::new();
        assert_eq!(
            decoder.receive(&forged_part(1, 1, 3, 1234, &[1, 2, 3])),
            Err(Error::BadChecksum)
        );
        assert_eq!(decoder.fragment_count(), 0);
        let checksum = crc32(&[1, 2, 3]);
        assert_eq!(
            decoder.receive(&forged_part(1, 2, 3, checksum, &[1, 2])),
            Ok(false)
        );
        assert_eq!(
            decoder.receive(&forged_part(2, 2, 3, checksum, &[3, 9])),
            Err(Error::BadChecksum)
        );
        assert_eq!(
            decoder.receive(&forged_part(1, 2, 3, checksum, &[1, 2])),
            Ok(false)
        );
        assert_eq!(
            decoder.receive(&forged_part(2, 2, 3, checksum, &[3, 0])),
            Ok(true)
        );
        assert_eq!(decoder.message(), Some(&[1, 2, 3][..]));
    }

    /// Fragments are as short as their number allows: a part cannot have a
    /// short message allocated as long fragments.
    #[test]
    fn rejects_oversized_fragments() {
        // one byte, said to come in a fragment of 4 KiB: past the limit on
        // the message, which it used to get around
        let mut decoder = Decoder::with_limits(100, 10);
        let checksum = crc32(&[7]);
        let mut data = vec![0u8; 4096];
        data[0] = 7;
        for seq_num in [1, 2] {
            assert_eq!(
                decoder.receive(&forged_part(seq_num, 1, 1, checksum, &data)),
                Err(Error::InvalidPart)
            );
        }
        assert_eq!(decoder.fragment_count(), 0);
        assert!(decoder.message.is_empty());
        assert_eq!(
            decoder.receive(&forged_part(1, 1, 1, checksum, &[7, 0])),
            Err(Error::InvalidPart)
        );
        // 9 bytes in 3 fragments are 3 bytes each, not 4
        assert_eq!(
            decoder.receive(&forged_part(1, 3, 9, 0, &[0; 4])),
            Err(Error::InvalidPart)
        );
        assert_eq!(
            decoder.receive(&forged_part(1, 3, 9, 0, &[0; 3])),
            Ok(false)
        );
        assert_eq!(decoder.message.len(), 9);

        let mut decoder = Decoder::with_limits(100, 10);
        assert_eq!(
            decoder.receive(&forged_part(1, 1, 1, checksum, &[7])),
            Ok(true)
        );
        assert_eq!(decoder.message(), Some(&[7][..]));

        // what the encoder picks is always accepted, padding included
        for message_len in 1..200usize {
            for max_fragment_len in [1, 2, 3, 7, 16, 50, 199, 200, 1000] {
                let message = make_message("Wolf", message_len);
                let mut encoder = Encoder::new("bytes", &message, max_fragment_len).unwrap();
                let mut decoder = Decoder::new();
                let count = encoder.fragment_count();
                for part in encoder.by_ref().take(count) {
                    decoder.receive(&part).unwrap();
                }
                assert_eq!(
                    decoder.message(),
                    Some(&message[..]),
                    "{message_len} bytes in fragments of {max_fragment_len}"
                );
            }
        }
    }

    /// The memory the parts on hold take: what each allocates, and itself.
    fn held_memory(decoder: &Decoder) -> usize {
        decoder
            .mixed
            .iter()
            .map(|held| {
                core::mem::size_of::<Mixed>() + held.bits.capacity() * 8 + held.data.capacity()
            })
            .sum()
    }

    /// The parts past the first `seq_len` that mix two fragments or more.
    fn mixed_parts<'a>(
        encoder: &'a mut Encoder,
        checksum: u32,
    ) -> impl Iterator<Item = String> + 'a {
        let seq_len = encoder.fragment_count() as u32;
        let mut sampler = None;
        encoder
            .by_ref()
            .skip(seq_len as usize)
            .enumerate()
            .filter_map(move |(i, part)| {
                let seq_num = seq_len + 1 + i as u32;
                (choose_fragments(seq_num, seq_len, checksum, &mut sampler).len() > 1)
                    .then_some(part)
            })
    }

    /// Nothing but mixed parts of a message in as many fragments as the
    /// default limits allow, of one byte each: what is put on hold stays
    /// within the budget, and what follows stays fast.
    #[test]
    fn bounds_parts_on_hold() {
        let seq_len = Decoder::DEFAULT_MAX_FRAGMENTS;
        let message = make_message("Wolf", seq_len);
        let checksum = crc32(&message);
        let budget = 2 * message.len() + HELD_ALLOWANCE;

        let mut encoder = Encoder::new("bytes", &message, 1).unwrap();
        assert_eq!(encoder.fragment_count(), seq_len);
        let mut decoder = Decoder::new();
        // Garbage for data: the parts never add up to anything, which is
        // what keeps the most of them on hold.
        let mut sent = 0;
        for (i, part) in mixed_parts(&mut encoder, checksum)
            .take(3 * seq_len)
            .enumerate()
        {
            let seq_num: u32 = part
                .split('/')
                .nth(1)
                .unwrap()
                .split('-')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let forged = forged_part(
                seq_num,
                seq_len as u32,
                seq_len as u32,
                checksum,
                &[i as u8],
            );
            assert_eq!(decoder.receive(&forged), Ok(false));
            assert!(decoder.mixed.len() <= decoder.max_held);
            assert!(held_memory(&decoder) <= budget);
            sent += 1;
        }
        assert_eq!(sent, 3 * seq_len);
        // full, and it used to be 115 MB
        assert_eq!(decoder.mixed.len(), decoder.max_held);
        assert!(decoder.max_held >= seq_len);
        assert!(held_memory(&decoder) <= budget);
        assert!(held_memory(&decoder) <= 5 << 20);
        assert_eq!(decoder.received_fragment_count(), 0);

        // Each fragment that now comes on its own is XORed out of the parts
        // on hold, and those take whole cascades with them: it used to be
        // more than half a second for each, for a minute and a half in all.
        let start = std::time::Instant::now();
        let mut slowest = core::time::Duration::ZERO;
        for (i, &byte) in message.iter().enumerate() {
            let part = forged_part(
                i as u32 + 1,
                seq_len as u32,
                seq_len as u32,
                checksum,
                &[byte],
            );
            let before = std::time::Instant::now();
            // the garbage may well have the message come out wrong
            match decoder.receive(&part) {
                Ok(_) | Err(Error::BadChecksum) => {}
                Err(e) => panic!("part {}: {e:?}", i + 1),
            }
            slowest = slowest.max(before.elapsed());
            assert!(held_memory(&decoder) <= budget);
            if decoder.is_complete() || decoder.fragment_count() == 0 {
                break;
            }
        }
        // a tenth of a second and half a second, unoptimized
        assert!(slowest < core::time::Duration::from_secs(2), "{slowest:?}");
        assert!(start.elapsed() < core::time::Duration::from_secs(20));
    }

    /// The budget is the tighter bound past the default limits.
    #[test]
    fn budget_follows_the_message() {
        let mut decoder = Decoder::with_limits(1 << 20, 1 << 20);
        let seq_len = 1 << 18;
        assert_eq!(
            decoder.receive(&forged_part(seq_len + 1, seq_len, seq_len, 0, &[0])),
            Ok(false)
        );
        let held_len = Decoder::held_len(seq_len as usize, 1);
        assert!(decoder.max_held < seq_len as usize);
        assert!(decoder.max_held * held_len <= 2 * seq_len as usize + HELD_ALLOWANCE);

        // and never in the way of a message that makes sense
        let mut decoder = Decoder::new();
        let part = Encoder::new("bytes", &[1; 30000], 100).unwrap().next_part();
        assert_eq!(decoder.receive(&part), Ok(false));
        assert_eq!(decoder.max_held, 2 * 300 + 16);
    }

    /// The parts past the first `seq_len` alone get a message through,
    /// whether or not parts on hold are XORed out of one another, and with no
    /// more of them than it took when parts on hold were lists of indexes.
    #[test]
    fn decodes_mixed_only_streams() {
        for (message_len, fragment_len, expected) in [
            (600, 50, 13),
            (3000, 20, 329),
            (12000, 30, 1000),
            (2000, 2, 3156),
        ] {
            let message = make_message("Wolf", message_len);
            let mut encoder = Encoder::new("bytes", &message, fragment_len).unwrap();
            let seq_len = encoder.fragment_count();
            let mut decoder = Decoder::new();
            let mut used = 0;
            for part in encoder.by_ref().skip(seq_len) {
                used += 1;
                assert!(used <= expected, "{seq_len} fragments: no progress");
                if decoder.receive(&part).unwrap() {
                    break;
                }
                assert!(decoder.mixed.len() <= decoder.max_held);
                if used % 50 != 0 {
                    continue;
                }
                // no part on hold mixes a fragment that is known
                assert!(decoder.mixed.iter().all(|held| {
                    held.count >= 2
                        && held.count
                            == held
                                .bits
                                .iter()
                                .map(|w| w.count_ones() as usize)
                                .sum::<usize>()
                        && (0..seq_len).all(|i| !(held.has(i) && decoder.known[i]))
                }));
            }
            assert_eq!(decoder.message(), Some(&message[..]), "{seq_len} fragments");
        }
    }
}
