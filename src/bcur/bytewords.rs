//! Bytewords (BCR-2020-012): every byte maps to a four-letter English word,
//! and a CRC-32 of the payload is appended as four more words.
//!
//! Three styles share the word list: [`Style::Standard`] separates whole words
//! with spaces, [`Style::Uri`] with hyphens, and [`Style::Minimal`] keeps only
//! the first and last letter of each word with no separator, which is what
//! `ur:` strings carry. Encoding produces lowercase; decoding ignores ASCII
//! case, as QR codes usually carry URs in uppercase.

#[cfg(feature = "alloc")]
use crate::prelude::*;

use super::{Crc32, Error};

/// The 256 words, four letters each, in byte order. They are sorted, and the
/// (first, last) letter pairs are unique, which is what [`Style::Minimal`]
/// and the decoder's lookup rely on.
const WORDS: &[u8; 1024] = b"\
    ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabias\
    bluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcost\
    cruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdull\
    dutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfish\
    fizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglow\
    goodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhope\
    hornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowl\
    judojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamb\
    lavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany\
    mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnote\
    numbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose\
    puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinruns\
    rustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask\
    taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuser\
    vastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebs\
    whatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom\
";

/// Byte value by `(first letter, last letter)`, or -1 when no word has them.
const LOOKUP: [i16; 26 * 26] = {
    let mut table = [-1i16; 26 * 26];
    let mut i = 0;
    while i < 256 {
        let first = (WORDS[4 * i] - b'a') as usize;
        let last = (WORDS[4 * i + 3] - b'a') as usize;
        table[first * 26 + last] = i as i16;
        i += 1;
    }
    table
};

/// How the words are written out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// Whole words separated by spaces: `able acid also`.
    Standard,
    /// Whole words separated by hyphens: `able-acid-also`.
    Uri,
    /// The first and last letter of each word, unseparated: `aeadao`.
    Minimal,
}

impl Style {
    fn separator(self) -> Option<u8> {
        match self {
            Style::Standard => Some(b' '),
            Style::Uri => Some(b'-'),
            Style::Minimal => None,
        }
    }
}

/// The encoded length of `n` bytes, checksum included.
pub const fn encoded_len(n: usize, style: Style) -> usize {
    let words = n + 4;
    match style {
        Style::Minimal => words * 2,
        Style::Standard | Style::Uri => words * 5 - 1,
    }
}

/// An upper bound on the decoded length of `n` characters.
pub const fn decoded_len_bound(n: usize, style: Style) -> usize {
    let words = match style {
        Style::Minimal => n / 2,
        Style::Standard | Style::Uri => n.div_ceil(5),
    };
    words.saturating_sub(4)
}

/// Encodes `data` and its checksum into `out`, returning the number of
/// (ASCII) bytes written.
pub fn encode_to_slice(data: &[u8], style: Style, out: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(data.len(), style);
    let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    let checksum = super::crc32(data).to_be_bytes();
    let separator = style.separator();
    let mut pos = 0;
    for (i, &byte) in data.iter().chain(&checksum).enumerate() {
        let word = &WORDS[4 * byte as usize..][..4];
        match separator {
            None => {
                out[pos] = word[0];
                out[pos + 1] = word[3];
                pos += 2;
            }
            Some(sep) => {
                if i > 0 {
                    out[pos] = sep;
                    pos += 1;
                }
                out[pos..pos + 4].copy_from_slice(word);
                pos += 4;
            }
        }
    }
    Ok(len)
}

/// The byte a word (four letters) or minimal word (two letters) stands for.
fn word_value(word: &[u8]) -> Option<u8> {
    let letter = |c: u8| {
        let c = c.to_ascii_lowercase();
        c.is_ascii_lowercase().then(|| (c - b'a') as usize)
    };
    let (&first, &last) = (word.first()?, word.last()?);
    let value = LOOKUP[letter(first)? * 26 + letter(last)?];
    let value = u8::try_from(value).ok()?;
    if let [_, middle @ .., _] = word {
        let expected = &WORDS[4 * value as usize + 1..][..2];
        if word.len() == 4 && !middle.eq_ignore_ascii_case(expected) {
            return None;
        }
    }
    Some(value)
}

/// Decodes `text` into `out`, verifying and dropping the checksum. Returns the
/// number of bytes written.
pub fn decode_to_slice(text: &str, style: Style, out: &mut [u8]) -> Result<usize, Error> {
    let text = text.as_bytes();
    // The last four bytes are the checksum, and must not reach `out`: bytes
    // go through a four-byte delay line on their way there.
    let mut delay = [0u8; 4];
    let mut count = 0usize;
    let mut crc = Crc32::new();
    let mut push = |byte: u8| -> Result<(), Error> {
        if count >= 4 {
            let oldest = delay[count % 4];
            *out.get_mut(count - 4).ok_or(Error::BufferTooSmall)? = oldest;
            crc.update(&[oldest]);
        }
        delay[count % 4] = byte;
        count += 1;
        Ok(())
    };

    match style.separator() {
        None => {
            if !text.len().is_multiple_of(2) {
                return Err(Error::InvalidLength);
            }
            for word in text.chunks(2) {
                push(word_value(word).ok_or(Error::InvalidWord)?)?;
            }
        }
        Some(sep) => {
            for word in text.split(|&c| c == sep) {
                if word.len() != 4 {
                    return Err(Error::InvalidWord);
                }
                push(word_value(word).ok_or(Error::InvalidWord)?)?;
            }
        }
    }

    if count < 4 {
        return Err(Error::InvalidLength);
    }
    // Unroll the delay line: the oldest of the four bytes comes first.
    let mut checksum = [0u8; 4];
    for (i, byte) in checksum.iter_mut().enumerate() {
        *byte = delay[(count + i) % 4];
    }
    if crc.finish().to_be_bytes() != checksum {
        return Err(Error::BadChecksum);
    }
    Ok(count - 4)
}

/// Encodes `data` and its checksum as a string.
#[cfg(feature = "alloc")]
pub fn encode(data: &[u8], style: Style) -> String {
    let mut buf = vec![0u8; encoded_len(data.len(), style)];
    encode_to_slice(data, style, &mut buf).expect("buffer sized by encoded_len");
    String::from_utf8(buf).expect("bytewords are ASCII")
}

/// Decodes `text`, verifying and dropping the checksum.
#[cfg(feature = "alloc")]
pub fn decode(text: &str, style: Style) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; decoded_len_bound(text.len(), style)];
    let n = decode_to_slice(text, style, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
