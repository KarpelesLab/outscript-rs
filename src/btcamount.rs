//! Bitcoin amount type (satoshis) with Go-compatible JSON.

#[cfg(feature = "alloc")]
use crate::prelude::*;
#[cfg(feature = "alloc")]
use core::fmt;
#[cfg(feature = "alloc")]
use serde::de::{self, Visitor};
#[cfg(feature = "alloc")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A Bitcoin amount in satoshis (1 BTC = 100,000,000 satoshis).
///
/// Serializes to JSON as an unquoted decimal number with 8 decimal places
/// (e.g. `1.00000000`). Deserializes from JSON numbers, decimal strings,
/// integer strings, and `0x`-prefixed hex strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BtcAmount(pub u64);

/// Errors from [`BtcAmount::from_text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmountError {
    /// The text is not a valid number.
    Invalid,
    /// The amount does not fit in 64 bits of satoshis.
    Overflow,
    /// The decimal amount has more than 8 fractional digits.
    TooManyDecimals,
}

impl core::fmt::Display for AmountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AmountError::Invalid => "invalid amount",
            AmountError::Overflow => "amount overflows u64",
            AmountError::TooManyDecimals => "cannot parse amount with more than 8 decimals",
        })
    }
}

impl core::error::Error for AmountError {}

/// Parses decimal digits (with an optional leading `+`, like `u64::from_str`),
/// skipping the byte at `skip`.
fn parse_digits(s: &[u8], skip: Option<usize>) -> Result<u64, AmountError> {
    let mut digits = s
        .iter()
        .enumerate()
        .filter(|&(i, _)| Some(i) != skip)
        .map(|(_, &c)| c)
        .peekable();
    if digits.peek() == Some(&b'+') {
        digits.next();
    }
    let mut v: u64 = 0;
    let mut any = false;
    for c in digits {
        let d = c
            .checked_sub(b'0')
            .filter(|d| *d < 10)
            .ok_or(AmountError::Invalid)?;
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(d as u64))
            .ok_or(AmountError::Overflow)?;
        any = true;
    }
    if any {
        Ok(v)
    } else {
        Err(AmountError::Invalid)
    }
}

impl BtcAmount {
    /// Formats the amount as a decimal string with exactly 8 decimal places
    /// (the same text as the [`Display`](core::fmt::Display) implementation).
    #[cfg(feature = "alloc")]
    pub fn to_decimal_string(self) -> String {
        self.to_string()
    }

    /// Parses a textual amount. Accepts decimal strings (e.g. "1.5"), integer
    /// strings (multiplied by 10^8), and `0x`-prefixed hex (treated as raw
    /// satoshis).
    pub fn from_text(s: &str) -> Result<BtcAmount, AmountError> {
        if let Some(hex_part) = s.strip_prefix("0x") {
            return u64::from_str_radix(hex_part, 16)
                .map(BtcAmount)
                .map_err(|e| match e.kind() {
                    core::num::IntErrorKind::PosOverflow => AmountError::Overflow,
                    _ => AmountError::Invalid,
                });
        }
        match s.find('.') {
            None => {
                let v = parse_digits(s.as_bytes(), None)?;
                Ok(BtcAmount(
                    v.checked_mul(100_000_000).ok_or(AmountError::Overflow)?,
                ))
            }
            Some(pos) => {
                let dec_count = s.len() - pos - 1;
                if dec_count > 8 {
                    return Err(AmountError::TooManyDecimals);
                }
                let mut v = parse_digits(s.as_bytes(), Some(pos))?;
                for _ in dec_count..8 {
                    v = v.checked_mul(10).ok_or(AmountError::Overflow)?;
                }
                Ok(BtcAmount(v))
            }
        }
    }
}

/// Formats as a decimal number with exactly 8 decimal places, e.g.
/// `1.50000000`.
impl core::fmt::Display for BtcAmount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{:08}", self.0 / 100_000_000, self.0 % 100_000_000)
    }
}

impl From<u64> for BtcAmount {
    fn from(v: u64) -> Self {
        BtcAmount(v)
    }
}

impl From<BtcAmount> for u64 {
    fn from(v: BtcAmount) -> Self {
        v.0
    }
}

#[cfg(feature = "alloc")]
impl Serialize for BtcAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Emit an unquoted JSON number with 8 decimal places, matching Go.
        let raw = serde_json::value::RawValue::from_string(self.to_decimal_string())
            .map_err(serde::ser::Error::custom)?;
        raw.serialize(serializer)
    }
}

#[cfg(feature = "alloc")]
struct BtcAmountVisitor;

#[cfg(feature = "alloc")]
impl Visitor<'_> for BtcAmountVisitor {
    type Value = BtcAmount;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a bitcoin amount as number or string")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<BtcAmount, E> {
        BtcAmount::from_text(&v.to_string()).map_err(de::Error::custom)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<BtcAmount, E> {
        BtcAmount::from_text(&v.to_string()).map_err(de::Error::custom)
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<BtcAmount, E> {
        // Format with shortest round-trip representation, then parse as decimal.
        BtcAmount::from_text(&format!("{v}")).map_err(de::Error::custom)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<BtcAmount, E> {
        BtcAmount::from_text(v).map_err(de::Error::custom)
    }

    fn visit_unit<E: de::Error>(self) -> Result<BtcAmount, E> {
        Ok(BtcAmount(0))
    }

    fn visit_none<E: de::Error>(self) -> Result<BtcAmount, E> {
        Ok(BtcAmount(0))
    }
}

#[cfg(feature = "alloc")]
impl<'de> Deserialize<'de> for BtcAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BtcAmountVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_matches_std_integer_rules() {
        assert_eq!(BtcAmount::from_text("+1.5"), Ok(BtcAmount(150_000_000)));
        assert_eq!(BtcAmount::from_text(".5"), Ok(BtcAmount(50_000_000)));
        assert_eq!(BtcAmount::from_text("5."), Ok(BtcAmount(500_000_000)));
        for bad in ["", ".", "+", "1.2.3", "-1", "1 ", "0x", "0xzz", "++1"] {
            assert!(BtcAmount::from_text(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            BtcAmount::from_text("18446744073709551616"),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn display() {
        use core::fmt::Write;
        struct Buf([u8; 32], usize);
        impl Write for Buf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                self.0[self.1..self.1 + s.len()].copy_from_slice(s.as_bytes());
                self.1 += s.len();
                Ok(())
            }
        }
        for (v, want) in [
            (0u64, "0.00000000"),
            (1, "0.00000001"),
            (150_000_000, "1.50000000"),
            (u64::MAX, "184467440737.09551615"),
        ] {
            let mut b = Buf([0; 32], 0);
            write!(b, "{}", BtcAmount(v)).unwrap();
            assert_eq!(&b.0[..b.1], want.as_bytes());
        }
    }

    #[test]
    fn unmarshal_text_decimal() {
        let cases = [
            ("1.5", 150_000_000u64),
            ("0.00000001", 1),
            ("21000000.00000000", 2_100_000_000_000_000),
            ("0.1", 10_000_000),
            ("100", 10_000_000_000),
        ];
        for (input, want) in cases {
            assert_eq!(
                BtcAmount::from_text(input).unwrap().0,
                want,
                "input {input}"
            );
        }
    }

    #[test]
    fn unmarshal_text_hex() {
        assert_eq!(BtcAmount::from_text("0x5f5e100").unwrap().0, 100_000_000);
    }

    #[test]
    fn unmarshal_text_integer() {
        assert_eq!(BtcAmount::from_text("50").unwrap().0, 5_000_000_000);
    }

    #[test]
    fn too_many_decimals() {
        assert!(BtcAmount::from_text("1.123456789").is_err());
    }

    #[test]
    fn overflow_is_rejected() {
        // integer path: v * 1e8 wraps u64
        assert!(BtcAmount::from_text("1000000000000").is_err());
        // decimal-scaling path: v *= 10 wraps u64
        assert!(BtcAmount::from_text("1844674407370955161.5").is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn json_roundtrip() {
        let a = BtcAmount(150_000_000);
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, "1.50000000");
        let b: BtcAmount = serde_json::from_str(&j).unwrap();
        assert_eq!(a, b);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn json_from_quoted_and_null() {
        let b: BtcAmount = serde_json::from_str("\"1.5\"").unwrap();
        assert_eq!(b.0, 150_000_000);
        let n: BtcAmount = serde_json::from_str("null").unwrap();
        assert_eq!(n.0, 0);
    }
}
