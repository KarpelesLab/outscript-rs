//! The 25-word mnemonic of a wallet seed (the "Electrum-style" words of the
//! reference wallet), in English.
//!
//! Every four bytes of the 32-byte seed become three words out of 1626, and
//! a 25th word repeats one of the 24 as a checksum: the one a CRC-32 of
//! their three-letter prefixes points at. A word is identified by its first
//! three letters.

use purecrypto::zeroize::Zeroizing;

use super::Error;
use super::mnemonic_words::ENGLISH;

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The number of words of a mnemonic.
pub const MNEMONIC_WORDS: usize = 25;

/// The number of words in the list.
const N: u64 = ENGLISH.len() as u64;
/// The letters that identify a word.
const PREFIX_LEN: usize = 3;

/// CRC-32 (IEEE 802.3), bit by bit: the input is 72 bytes.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// The position, among the 24 words with these indices, of the one the
/// checksum repeats.
fn checksum_position(indices: &[u16; 24]) -> usize {
    let mut prefixes = Zeroizing::new([0u8; 24 * PREFIX_LEN]);
    for (chunk, index) in prefixes.chunks_mut(PREFIX_LEN).zip(indices) {
        let word = ENGLISH.get(usize::from(*index)).copied().unwrap_or("");
        for (c, b) in chunk.iter_mut().zip(word.bytes()) {
            *c = b;
        }
    }
    (crc32(&*prefixes) % 24) as usize
}

/// The index of the word starting with the same three letters as `word`
/// (ASCII case is ignored).
fn word_index(word: &str) -> Option<u16> {
    let prefix = word.as_bytes().get(..PREFIX_LEN)?;
    let position = ENGLISH.iter().position(|candidate| {
        candidate
            .as_bytes()
            .iter()
            .zip(prefix)
            .all(|(a, b)| *a == b.to_ascii_lowercase())
    })?;
    u16::try_from(position).ok()
}

/// The indices of the 24 words that encode `seed`.
fn seed_indices(seed: &[u8; 32]) -> Zeroizing<[u16; 24]> {
    let mut indices = Zeroizing::new([0u16; 24]);
    for (words, bytes) in indices.chunks_mut(3).zip(seed.as_chunks::<4>().0) {
        let value = u64::from(u32::from_le_bytes(*bytes));
        let w1 = value % N;
        let w2 = (value / N + w1) % N;
        let w3 = (value / N / N + w2) % N;
        // Each is below N = 1626.
        for (slot, w) in words.iter_mut().zip([w1, w2, w3]) {
            *slot = w as u16;
        }
    }
    indices
}

/// The 25 words of the mnemonic for `seed`.
///
/// The words are as secret as the seed: whoever reads them owns the wallet.
pub fn seed_to_mnemonic_words(seed: &[u8; 32]) -> [&'static str; MNEMONIC_WORDS] {
    let indices = seed_indices(seed);
    let mut words = [""; MNEMONIC_WORDS];
    for (word, index) in words.iter_mut().zip(indices.iter()) {
        *word = ENGLISH.get(usize::from(*index)).copied().unwrap_or("");
    }
    let checksum = words
        .get(checksum_position(&indices))
        .copied()
        .unwrap_or("");
    if let Some(last) = words.last_mut() {
        *last = checksum;
    }
    words
}

/// The mnemonic for `seed`: its 25 words separated by spaces.
///
/// The text is as secret as the seed, and wiped when dropped.
#[cfg(feature = "alloc")]
pub fn seed_to_mnemonic(seed: &[u8; 32]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(MNEMONIC_WORDS * 10));
    for (i, word) in seed_to_mnemonic_words(seed).iter().enumerate() {
        if i != 0 {
            text.push(' ');
        }
        text.push_str(word);
    }
    text
}

/// Decodes a 25-word English mnemonic into the wallet seed, to be given to
/// [`AccountKeys::from_seed`](super::AccountKeys::from_seed).
///
/// The words are separated by whitespace and matched by their first three
/// letters, ASCII case ignored, as in the reference wallet.
///
/// Fails with [`Error::InvalidMnemonic`] unless there are exactly 25 words,
/// all of them in the list, the last one being the checksum of the others,
/// and each group of three encoding a 32-bit value.
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut indices = Zeroizing::new([0u16; 24]);
    let mut checksum = None;
    let mut count = 0usize;
    for word in mnemonic.split_whitespace() {
        let index = word_index(word).ok_or(Error::InvalidMnemonic)?;
        match indices.get_mut(count) {
            Some(slot) => *slot = index,
            None if count == 24 => checksum = Some(index),
            None => return Err(Error::InvalidMnemonic),
        }
        count += 1;
    }
    let expected = indices.get(checksum_position(&indices)).copied();
    if count != MNEMONIC_WORDS || checksum.is_none() || checksum != expected {
        return Err(Error::InvalidMnemonic);
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    for (bytes, words) in seed.chunks_mut(4).zip(indices.as_chunks::<3>().0) {
        let [w1, w2, w3] = words.map(u64::from);
        let value = w1 + N * ((N - w1 + w2) % N) + N * N * ((N - w2 + w3) % N);
        // Three words hold a little more than 32 bits.
        let value = u32::try_from(value).map_err(|_| Error::InvalidMnemonic)?;
        for (b, v) in bytes.iter_mut().zip(value.to_le_bytes()) {
            *b = v;
        }
    }
    Ok(seed)
}
