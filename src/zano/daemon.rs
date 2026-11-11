//! Decoding what the daemon serves a wallet that picks decoys: the reply of
//! `getrandom_outs3` (`COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS3`).
//!
//! Nothing here talks to a daemon; these are the decoders of what it
//! answers.

use crate::prelude::*;

use super::Error;
use super::transfer::RingMember;

/// `RANDOM_OUTPUTS_FOR_AMOUNTS_FLAGS_COINBASE`: the output is one of the
/// first transaction of a block.
pub const RANDOM_OUT_FLAG_COINBASE: u64 = 1;
/// `RANDOM_OUTPUTS_FOR_AMOUNTS_FLAGS_NOT_ALLOWED`: the daemon refuses the
/// output asked for as a decoy (spent in the open, still locked, burnt, not
/// to be mixed); the rest of the entry is zero.
pub const RANDOM_OUT_FLAG_NOT_ALLOWED: u64 = 2;
/// `RANDOM_OUTPUTS_FOR_AMOUNTS_FLAGS_POS_COINBASE`: the output is one of the
/// first transaction of a proof-of-stake block.
pub const RANDOM_OUT_FLAG_POS_COINBASE: u64 = 4;

/// The size of an `out_entry` in the reply: the global index, four keys and
/// the flags.
const RANDOM_OUT_SIZE: usize = 144;

/// One output of a `getrandom_outs3` reply (`out_entry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RandomOut {
    /// The output. For a transparent output (a non-zero amount) only the
    /// global index and the stealth address are set.
    pub member: RingMember,
    /// The `RANDOM_OUT_FLAG_*` flags.
    pub flags: u64,
}

impl RandomOut {
    /// Whether the daemon gave the output (it did not flag it
    /// [`RANDOM_OUT_FLAG_NOT_ALLOWED`]).
    pub fn is_allowed(&self) -> bool {
        self.flags & RANDOM_OUT_FLAG_NOT_ALLOWED == 0
    }
}

/// The outputs the daemon gave for one entry of the request
/// (`outs_for_amount`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RandomOuts {
    /// The amount asked for: zero for confidential outputs.
    pub amount: u64,
    /// The outputs. For a zero amount there is one per global index asked,
    /// in the order asked; those the daemon refuses are flagged
    /// [`RANDOM_OUT_FLAG_NOT_ALLOWED`].
    pub outs: Vec<RandomOut>,
}

/// Decodes the `outs` blob of an `outs_for_amount`: entries of 144 bytes —
/// the global index, the stealth address, the concealing point, the amount
/// commitment and the blinded asset id (the three times `1/8`, as on
/// chain), then the flags.
///
/// Fails with [`Error::InvalidEncoding`] if the length is not a multiple of
/// the entry size. The keys are not checked to be points.
pub fn decode_random_outs(blob: &[u8]) -> Result<Vec<RandomOut>, Error> {
    let (entries, rest) = blob.as_chunks::<RANDOM_OUT_SIZE>();
    if !rest.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    let mut outs = Vec::with_capacity(entries.len());
    for entry in entries {
        let word = |at: usize| -> u64 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&entry[at..at + 8]);
            u64::from_le_bytes(bytes)
        };
        let key = |n: usize| -> [u8; 32] {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&entry[8 + 32 * n..40 + 32 * n]);
            bytes
        };
        outs.push(RandomOut {
            member: RingMember {
                global_index: word(0),
                stealth_address: key(0),
                concealing_point: key(1),
                amount_commitment: key(2),
                blinded_asset_id: key(3),
            },
            flags: word(136),
        });
    }
    Ok(outs)
}

/// How deep the JSON of a reply may nest.
const MAX_JSON_DEPTH: u8 = 16;

/// A JSON value of a daemon reply, strings as bytes.
#[derive(Debug)]
enum Json {
    /// `null`, `true`, `false` or a number that is not a 64-bit unsigned
    /// integer.
    Other,
    Number(u64),
    String(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
}

impl Json {
    fn get(&self, name: &[u8]) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(key, _)| key == name).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// A cursor over the bytes of a JSON text.
struct JsonReader<'a> {
    data: &'a [u8],
    depth: u8,
}

impl JsonReader<'_> {
    fn skip_space(&mut self) {
        while let [b' ' | b'\t' | b'\r' | b'\n', rest @ ..] = self.data {
            self.data = rest;
        }
    }

    fn next(&mut self) -> Result<u8, Error> {
        let (first, rest) = self.data.split_first().ok_or(Error::UnexpectedEof)?;
        self.data = rest;
        Ok(*first)
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.next()? == byte {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    /// The body of a string, after its opening quote.
    fn string(&mut self) -> Result<Vec<u8>, Error> {
        let end = string_end(self.data).ok_or(Error::UnexpectedEof)?;
        let (body, rest) = self.data.split_at(end);
        self.data = rest.get(1..).unwrap_or_default();
        json_binary_string(body)
    }

    fn value(&mut self) -> Result<Json, Error> {
        self.skip_space();
        match self.next()? {
            b'"' => Ok(Json::String(self.string()?)),
            open @ (b'[' | b'{') => {
                if self.depth >= MAX_JSON_DEPTH {
                    return Err(Error::TooDeep);
                }
                self.depth += 1;
                let value = if open == b'[' {
                    self.array()?
                } else {
                    self.object()?
                };
                self.depth -= 1;
                Ok(value)
            }
            b',' | b']' | b'}' | b':' => Err(Error::InvalidEncoding),
            first => {
                // A number or a literal: up to the next delimiter.
                let mut number = first.is_ascii_digit().then(|| u64::from(first - b'0'));
                while let [byte, rest @ ..] = self.data {
                    if matches!(byte, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n') {
                        break;
                    }
                    number = match (number, byte.is_ascii_digit()) {
                        (Some(n), true) => n
                            .checked_mul(10)
                            .and_then(|n| n.checked_add(u64::from(byte - b'0'))),
                        _ => None,
                    };
                    self.data = rest;
                }
                Ok(number.map_or(Json::Other, Json::Number))
            }
        }
    }

    fn array(&mut self) -> Result<Json, Error> {
        let mut items = Vec::new();
        self.skip_space();
        if let [b']', rest @ ..] = self.data {
            self.data = rest;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_space();
            match self.next()? {
                b',' => {}
                b']' => return Ok(Json::Array(items)),
                _ => return Err(Error::InvalidEncoding),
            }
        }
    }

    fn object(&mut self) -> Result<Json, Error> {
        let mut members = Vec::new();
        self.skip_space();
        if let [b'}', rest @ ..] = self.data {
            self.data = rest;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_space();
            self.expect(b'"')?;
            let key = self.string()?;
            self.skip_space();
            self.expect(b':')?;
            members.push((key, self.value()?));
            self.skip_space();
            match self.next()? {
                b',' => {}
                b'}' => return Ok(Json::Object(members)),
                _ => return Err(Error::InvalidEncoding),
            }
        }
    }
}

/// Where the string that starts at `data` ends: the index of its closing
/// quote.
fn string_end(data: &[u8]) -> Option<usize> {
    let mut escaped = false;
    data.iter().position(|byte| {
        if escaped {
            escaped = false;
            false
        } else {
            escaped = *byte == b'\\';
            *byte == b'"'
        }
    })
}

/// Decodes the body of a JSON string the daemon wrote binary data into
/// (what is between the quotes): epee writes the bytes as they are, but for
/// the quote, the backslash and the slash, which it escapes, and the
/// control characters, which it writes `\b`, `\f`, `\n`, `\r`, `\t` or
/// `\u00XX`. The result is not UTF-8 in general, which is why a JSON
/// library cannot read these replies.
///
/// Fails with [`Error::InvalidEncoding`] for an escape that is not one of
/// those, an unescaped quote, or a `\u` escape above `00ff`.
pub fn json_binary_string(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while let [byte, tail @ ..] = rest {
        rest = tail;
        match byte {
            b'"' => return Err(Error::InvalidEncoding),
            b'\\' => {
                let (escape, tail) = rest.split_first().ok_or(Error::InvalidEncoding)?;
                rest = tail;
                out.push(match escape {
                    b'"' | b'\\' | b'/' => *escape,
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        let (digits, tail) = rest
                            .split_first_chunk::<4>()
                            .ok_or(Error::InvalidEncoding)?;
                        rest = tail;
                        let mut value = 0u32;
                        for digit in digits {
                            let digit = char::from(*digit)
                                .to_digit(16)
                                .ok_or(Error::InvalidEncoding)?;
                            value = value * 16 + digit;
                        }
                        u8::try_from(value).map_err(|_| Error::InvalidEncoding)?
                    }
                    _ => return Err(Error::InvalidEncoding),
                });
            }
            byte => out.push(*byte),
        }
    }
    Ok(out)
}

/// Parses the reply of the daemon's `getrandom_outs3` (or `getrandom_outs`)
/// JSON-RPC method, as the bytes it sent: the whole JSON-RPC envelope or
/// its `result` alone.
///
/// The reply cannot go through a JSON library first: its `outs` strings
/// hold raw bytes ([`json_binary_string`]).
///
/// Fails with [`Error::InvalidEncoding`] if the text is not the JSON of
/// such a reply or its status is not `OK`, [`Error::TooDeep`] if it nests
/// deeper than a reply does.
///
/// ```
/// use outscript::zano::parse_random_outs_reply;
///
/// // One entry of 144 bytes: global index 5, four keys, no flags.
/// let mut reply = br#"{"result":{"outs":[{"amount":0,"outs":"\u0005"#.to_vec();
/// reply.extend_from_slice(&[b'A'; 143]);
/// reply.extend_from_slice(br#""}],"status":"OK"}}"#);
/// let outs = parse_random_outs_reply(&reply)?;
/// assert_eq!(outs[0].amount, 0);
/// assert_eq!(outs[0].outs[0].member.global_index, 0x4141_4141_4141_4105);
/// # Ok::<(), outscript::Error>(())
/// ```
pub fn parse_random_outs_reply(json: &[u8]) -> Result<Vec<RandomOuts>, Error> {
    let mut reader = JsonReader {
        data: json,
        depth: 0,
    };
    let root = reader.value()?;
    reader.skip_space();
    if !reader.data.is_empty() {
        return Err(Error::TrailingData);
    }
    let result = root.get(b"result").unwrap_or(&root);
    if !matches!(result.get(b"status"), Some(Json::String(status)) if status == b"OK") {
        return Err(Error::InvalidEncoding);
    }
    let Some(Json::Array(entries)) = result.get(b"outs") else {
        return Err(Error::InvalidEncoding);
    };
    let mut all = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(Json::Number(amount)) = entry.get(b"amount") else {
            return Err(Error::InvalidEncoding);
        };
        let outs = match entry.get(b"outs") {
            Some(Json::String(blob)) => decode_random_outs(blob)?,
            // epee leaves an empty container out.
            None => Vec::new(),
            Some(_) => return Err(Error::InvalidEncoding),
        };
        all.push(RandomOuts {
            amount: *amount,
            outs,
        });
    }
    Ok(all)
}
