//! The 25-word mnemonic of a wallet seed (the "Electrum-style" words of the
//! reference wallet), in the languages of its word lists
//! (`src/mnemonics` of the Monero source).
//!
//! Every four bytes of the 32-byte seed become three words out of 1626, and
//! a 25th word repeats one of the 24 as a checksum: the one a CRC-32 of
//! their prefixes points at. A word is identified by its first few letters —
//! three in English, one to four in the other languages
//! ([`MnemonicLanguage::prefix_len`]).

use purecrypto::zeroize::Zeroizing;

use super::Error;

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// The number of words of a mnemonic.
pub const MNEMONIC_WORDS: usize = 25;

/// The number of words in a list.
const LIST_LEN: usize = 1626;
/// The same, for the arithmetic.
const N: u64 = LIST_LEN as u64;

/// A word list: its words, one per line, and where each starts.
struct WordList {
    text: &'static str,
    /// The offset of each word in `text`, and the length of `text`.
    offsets: [u16; LIST_LEN + 1],
}

impl WordList {
    /// Indexes a list of [`LIST_LEN`] newline-terminated words. Evaluated
    /// at compile time, where a malformed list is an error.
    const fn new(text: &'static str) -> WordList {
        let bytes = text.as_bytes();
        assert!(bytes.len() <= u16::MAX as usize);
        let mut offsets = [0u16; LIST_LEN + 1];
        let mut count = 0;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\n' {
                count += 1;
                assert!(count <= LIST_LEN);
                offsets[count] = (i + 1) as u16;
            }
            i += 1;
        }
        assert!(count == LIST_LEN && offsets[LIST_LEN] as usize == bytes.len());
        WordList { text, offsets }
    }

    /// The word number `index`.
    fn word(&self, index: usize) -> Option<&'static str> {
        let start = usize::from(*self.offsets.get(index)?);
        let end = usize::from(*self.offsets.get(index + 1)?);
        // Without the newline, nor the carriage return a checkout that
        // converts line endings puts before it.
        let word = self.text.get(start..end.checked_sub(1)?)?;
        Some(word.strip_suffix('\r').unwrap_or(word))
    }

    /// The words, in order.
    fn words(&self) -> impl Iterator<Item = &'static str> {
        (0..LIST_LEN).filter_map(|index| self.word(index))
    }
}

macro_rules! word_lists {
    ($($name:ident = $file:literal;)*) => {
        $(static $name: WordList = WordList::new(include_str!($file));)*
    };
}

word_lists! {
    ENGLISH = "wordlists/english.txt";
    SPANISH = "wordlists/spanish.txt";
    FRENCH = "wordlists/french.txt";
    GERMAN = "wordlists/german.txt";
    ITALIAN = "wordlists/italian.txt";
    PORTUGUESE = "wordlists/portuguese.txt";
    RUSSIAN = "wordlists/russian.txt";
    JAPANESE = "wordlists/japanese.txt";
    CHINESE_SIMPLIFIED = "wordlists/chinese_simplified.txt";
    DUTCH = "wordlists/dutch.txt";
    ESPERANTO = "wordlists/esperanto.txt";
    LOJBAN = "wordlists/lojban.txt";
}

/// A language of the mnemonic word lists.
///
/// The lists are those of the reference wallet. Its deprecated "English
/// (old)" list, of the 24-word mnemonics without a checksum that predate
/// 2014, is not here.
///
/// ```
/// use outscript::monero::MnemonicLanguage;
///
/// let language = MnemonicLanguage::Spanish;
/// assert_eq!(language.name(), "Español");
/// assert_eq!(language.english_name(), "Spanish");
/// assert_eq!(language.prefix_len(), 4);
/// assert_eq!(language.word(0), Some("ábaco"));
/// // A word is found by its first letters, whatever its case.
/// assert_eq!(language.word_index("ÁBAC"), Some(0));
/// assert_eq!(language.word_index("abbey"), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MnemonicLanguage {
    /// English.
    English,
    /// Spanish (Español).
    Spanish,
    /// French (Français).
    French,
    /// German (Deutsch).
    German,
    /// Italian (Italiano).
    Italian,
    /// Portuguese (Português).
    Portuguese,
    /// Russian (русский язык).
    Russian,
    /// Japanese (日本語).
    Japanese,
    /// Simplified Chinese (简体中文).
    ChineseSimplified,
    /// Dutch (Nederlands).
    Dutch,
    /// Esperanto.
    Esperanto,
    /// Lojban.
    Lojban,
}

impl MnemonicLanguage {
    /// Every language, in the order the reference wallet tries them when it
    /// has to guess the language of a mnemonic
    /// ([`seed_from_mnemonic_any`]).
    pub const ALL: [MnemonicLanguage; 12] = [
        MnemonicLanguage::ChineseSimplified,
        MnemonicLanguage::English,
        MnemonicLanguage::Dutch,
        MnemonicLanguage::French,
        MnemonicLanguage::Spanish,
        MnemonicLanguage::German,
        MnemonicLanguage::Italian,
        MnemonicLanguage::Portuguese,
        MnemonicLanguage::Japanese,
        MnemonicLanguage::Russian,
        MnemonicLanguage::Esperanto,
        MnemonicLanguage::Lojban,
    ];

    fn list(self) -> &'static WordList {
        match self {
            MnemonicLanguage::English => &ENGLISH,
            MnemonicLanguage::Spanish => &SPANISH,
            MnemonicLanguage::French => &FRENCH,
            MnemonicLanguage::German => &GERMAN,
            MnemonicLanguage::Italian => &ITALIAN,
            MnemonicLanguage::Portuguese => &PORTUGUESE,
            MnemonicLanguage::Russian => &RUSSIAN,
            MnemonicLanguage::Japanese => &JAPANESE,
            MnemonicLanguage::ChineseSimplified => &CHINESE_SIMPLIFIED,
            MnemonicLanguage::Dutch => &DUTCH,
            MnemonicLanguage::Esperanto => &ESPERANTO,
            MnemonicLanguage::Lojban => &LOJBAN,
        }
    }

    /// The name of the language in the language itself, as the reference
    /// wallet shows it.
    pub fn name(self) -> &'static str {
        match self {
            MnemonicLanguage::English => "English",
            MnemonicLanguage::Spanish => "Español",
            MnemonicLanguage::French => "Français",
            MnemonicLanguage::German => "Deutsch",
            MnemonicLanguage::Italian => "Italiano",
            MnemonicLanguage::Portuguese => "Português",
            MnemonicLanguage::Russian => "русский язык",
            MnemonicLanguage::Japanese => "日本語",
            MnemonicLanguage::ChineseSimplified => "简体中文 (中国)",
            MnemonicLanguage::Dutch => "Nederlands",
            MnemonicLanguage::Esperanto => "Esperanto",
            MnemonicLanguage::Lojban => "Lojban",
        }
    }

    /// The name of the language in English, as the reference wallet has it.
    pub fn english_name(self) -> &'static str {
        match self {
            MnemonicLanguage::English => "English",
            MnemonicLanguage::Spanish => "Spanish",
            MnemonicLanguage::French => "French",
            MnemonicLanguage::German => "German",
            MnemonicLanguage::Italian => "Italian",
            MnemonicLanguage::Portuguese => "Portuguese",
            MnemonicLanguage::Russian => "Russian",
            MnemonicLanguage::Japanese => "Japanese",
            MnemonicLanguage::ChineseSimplified => "Chinese (simplified)",
            MnemonicLanguage::Dutch => "Dutch",
            MnemonicLanguage::Esperanto => "Esperanto",
            MnemonicLanguage::Lojban => "Lojban",
        }
    }

    /// The number of letters (Unicode scalar values) that identify a word
    /// of this language's list: no two words start with the same ones. A
    /// few Spanish words are shorter, and identified by all their letters.
    pub fn prefix_len(self) -> usize {
        match self {
            MnemonicLanguage::ChineseSimplified => 1,
            MnemonicLanguage::English | MnemonicLanguage::Japanese => 3,
            _ => 4,
        }
    }

    /// The word number `index` of the list (there are 1626).
    pub fn word(self, index: usize) -> Option<&'static str> {
        self.list().word(index)
    }

    /// The words of the list, in order.
    pub fn words(self) -> impl Iterator<Item = &'static str> {
        self.list().words()
    }

    /// The index of the word of the list that starts with the same
    /// [`prefix_len`](Self::prefix_len) letters as `word`, whatever their
    /// case.
    ///
    /// As in the reference wallet, nothing else is normalized: accents
    /// count, and the letters must be in the Unicode form of the list
    /// (composed, NFC). The whole list is gone through whatever the word,
    /// but the comparison is not constant-time.
    pub fn word_index(self, word: &str) -> Option<u16> {
        let prefix_len = self.prefix_len();
        let wanted = prefix(word, prefix_len);
        let mut found = None;
        for (index, candidate) in self.words().enumerate() {
            if same_letters(prefix(candidate, prefix_len), wanted) {
                found = u16::try_from(index).ok();
            }
        }
        found
    }
}

/// The first `count` letters of `word` (`utf8prefix`): all of it if it has
/// no more.
fn prefix(word: &str, count: usize) -> &str {
    if word.is_ascii() {
        return word.get(..count).unwrap_or(word);
    }
    match word.char_indices().nth(count) {
        Some((end, _)) => word.get(..end).unwrap_or(word),
        None => word,
    }
}

/// Whether two words are the same, whatever the case of their letters.
fn same_letters(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

/// CRC-32 (IEEE 802.3), bit by bit: the input is a few dozen bytes.
struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Crc32(!0)
    }

    fn update(&mut self, data: &[u8]) {
        for byte in data {
            self.0 ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = (self.0 & 1).wrapping_neg();
                self.0 = (self.0 >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.0
    }
}

/// The position, among the 24 words with these indices, of the one the
/// checksum repeats.
fn checksum_position(language: MnemonicLanguage, indices: &[u16; 24]) -> usize {
    let mut crc = Crc32::new();
    for index in indices {
        let word = language.word(usize::from(*index)).unwrap_or("");
        crc.update(prefix(word, language.prefix_len()).as_bytes());
    }
    (crc.finish() % 24) as usize
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

/// The 25 words of the English mnemonic for `seed`
/// ([`seed_to_mnemonic_words_in`] with [`MnemonicLanguage::English`]).
///
/// The words are as secret as the seed: whoever reads them owns the wallet.
pub fn seed_to_mnemonic_words(seed: &[u8; 32]) -> [&'static str; MNEMONIC_WORDS] {
    seed_to_mnemonic_words_in(MnemonicLanguage::English, seed)
}

/// The 25 words of the mnemonic for `seed` in `language`.
///
/// The words are as secret as the seed: whoever reads them owns the wallet.
///
/// ```
/// use outscript::monero::{MnemonicLanguage, seed_from_mnemonic_in, seed_to_mnemonic_words_in};
///
/// let seed = [0x42u8; 32];
/// let words = seed_to_mnemonic_words_in(MnemonicLanguage::Japanese, &seed);
/// let text = words.join(" ");
/// assert_eq!(*seed_from_mnemonic_in(MnemonicLanguage::Japanese, &text)?, seed);
/// # Ok::<(), outscript::monero::Error>(())
/// ```
pub fn seed_to_mnemonic_words_in(
    language: MnemonicLanguage,
    seed: &[u8; 32],
) -> [&'static str; MNEMONIC_WORDS] {
    let indices = seed_indices(seed);
    let mut words = [""; MNEMONIC_WORDS];
    for (word, index) in words.iter_mut().zip(indices.iter()) {
        *word = language.word(usize::from(*index)).unwrap_or("");
    }
    let checksum = words
        .get(checksum_position(language, &indices))
        .copied()
        .unwrap_or("");
    if let Some(last) = words.last_mut() {
        *last = checksum;
    }
    words
}

/// The English mnemonic for `seed`: its 25 words separated by spaces
/// ([`seed_to_mnemonic_in`] with [`MnemonicLanguage::English`]).
///
/// The text is as secret as the seed, and wiped when dropped.
#[cfg(feature = "alloc")]
pub fn seed_to_mnemonic(seed: &[u8; 32]) -> Zeroizing<String> {
    seed_to_mnemonic_in(MnemonicLanguage::English, seed)
}

/// The mnemonic for `seed` in `language`: its 25 words separated by spaces.
///
/// The text is as secret as the seed, and wiped when dropped.
#[cfg(feature = "alloc")]
pub fn seed_to_mnemonic_in(language: MnemonicLanguage, seed: &[u8; 32]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(MNEMONIC_WORDS * 24));
    for (i, word) in seed_to_mnemonic_words_in(language, seed).iter().enumerate() {
        if i != 0 {
            text.push(' ');
        }
        text.push_str(word);
    }
    text
}

/// Decodes a 25-word English mnemonic into the wallet seed, to be given to
/// [`AccountKeys::from_seed`](super::AccountKeys::from_seed)
/// ([`seed_from_mnemonic_in`] with [`MnemonicLanguage::English`]).
///
/// The words are separated by whitespace and matched by their first three
/// letters, case ignored, as in the reference wallet.
///
/// Fails with [`Error::InvalidMnemonic`] unless there are exactly 25 words,
/// all of them in the list, the last one being the checksum of the others,
/// and each group of three encoding a 32-bit value.
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    seed_from_mnemonic_in(MnemonicLanguage::English, mnemonic)
}

/// Decodes a 25-word mnemonic in `language` into the wallet seed, to be
/// given to [`AccountKeys::from_seed`](super::AccountKeys::from_seed).
///
/// The words are separated by whitespace and matched by their first
/// letters ([`MnemonicLanguage::word_index`]), as in the reference wallet.
///
/// Fails with [`Error::InvalidMnemonic`] unless there are exactly 25 words,
/// all of them in the list, the last one being the checksum of the others,
/// and each group of three encoding a 32-bit value.
///
/// ```
/// use outscript::monero::{MnemonicLanguage, seed_from_mnemonic_in};
///
/// let seed = seed_from_mnemonic_in(
///     MnemonicLanguage::French,
///     "poids vaseux tarte bazar poivre effet entier nuance sensuel ennui pacte osselet \
///      poudre battre alibi mouton stade paquet pliage gibier type question position projet \
///      pliage",
/// )?;
/// assert_eq!(seed[..4], [0x2d, 0xd3, 0x9f, 0xf1]);
/// # Ok::<(), outscript::monero::Error>(())
/// ```
pub fn seed_from_mnemonic_in(
    language: MnemonicLanguage,
    mnemonic: &str,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut indices = Zeroizing::new([0u16; 24]);
    let mut checksum = None;
    let mut count = 0usize;
    for word in mnemonic.split_whitespace() {
        let index = language.word_index(word).ok_or(Error::InvalidMnemonic)?;
        match indices.get_mut(count) {
            Some(slot) => *slot = index,
            None if count == 24 => checksum = Some(index),
            None => return Err(Error::InvalidMnemonic),
        }
        count += 1;
    }
    let expected = indices.get(checksum_position(language, &indices)).copied();
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

/// Decodes a 25-word mnemonic whose language is not known: the languages
/// are tried in the order of [`MnemonicLanguage::ALL`], and the first in
/// which the mnemonic is valid — all its words in the list, and the
/// checksum right — is returned with the seed.
///
/// A few words are in more than one list: a mnemonic made of such words
/// only can be valid in two languages, and stand for different seeds. This
/// returns the first, as the reference wallet does; when the language is
/// known, [`seed_from_mnemonic_in`] leaves no doubt.
///
/// Fails with [`Error::InvalidMnemonic`] if the mnemonic is valid in none.
///
/// ```
/// use outscript::monero::{MnemonicLanguage, seed_from_mnemonic_any, seed_to_mnemonic_words_in};
///
/// let words = seed_to_mnemonic_words_in(MnemonicLanguage::Russian, &[7u8; 32]);
/// let (seed, language) = seed_from_mnemonic_any(&words.join(" "))?;
/// assert_eq!((*seed, language), ([7u8; 32], MnemonicLanguage::Russian));
/// # Ok::<(), outscript::monero::Error>(())
/// ```
pub fn seed_from_mnemonic_any(
    mnemonic: &str,
) -> Result<(Zeroizing<[u8; 32]>, MnemonicLanguage), Error> {
    for language in MnemonicLanguage::ALL {
        if let Ok(seed) = seed_from_mnemonic_in(language, mnemonic) {
            return Ok((seed, language));
        }
    }
    Err(Error::InvalidMnemonic)
}
