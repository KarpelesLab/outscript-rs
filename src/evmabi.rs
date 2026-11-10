//! EVM ABI encoding (port of `evmabi.go`).
//!
//! The fixed-size helpers ([`function_selector`], [`address_word`],
//! [`uint_word`], [`erc20_transfer_calldata`]) never allocate; the dynamic
//! `AbiBuffer` encoder needs `alloc`.

pub use crate::Error;

#[cfg(feature = "alloc")]
use crate::prelude::*;

#[cfg(feature = "alloc")]
use num_bigint::{BigInt, Sign};

use purecrypto::hash::{Digest, Keccak256};

#[cfg(feature = "alloc")]
use crate::out::Out;

/// Returns the 4-byte function selector for a signature such as
/// `"transfer(address,uint256)"`: the first 4 bytes of its keccak-256 hash.
///
/// The selector is defined over canonical type names, so the aliases `uint`
/// and `int` in the parameter list are hashed as `uint256` and `int256`:
/// `"f(uint)"` and `"f(uint256)"` give the same selector.
pub fn function_selector(signature: &str) -> [u8; 4] {
    let b = signature.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut hash = Keccak256::new();
    // the name, up to the parameter list, is hashed as written
    let mut i = b.iter().position(|&c| c == b'(').unwrap_or(b.len());
    hash.update(&b[..i]);
    while i < b.len() {
        let start = i;
        if is_word(b[i]) {
            while i < b.len() && is_word(b[i]) {
                i += 1;
            }
            hash.update(&b[start..i]);
            if matches!(&b[start..i], b"uint" | b"int") {
                hash.update(b"256");
            }
        } else {
            i += 1;
            hash.update(&b[start..i]);
        }
    }
    let h: [u8; 32] = hash.finalize();
    [h[0], h[1], h[2], h[3]]
}

/// Encodes a 20-byte address as a 32-byte ABI word (left-padded with zeros).
pub fn address_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr);
    w
}

/// Encodes an unsigned integer as a 32-byte big-endian ABI word.
pub fn uint_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Builds ERC-20 `transfer(address,uint256)` calldata for sending `amount` (a
/// 32-byte big-endian uint256, e.g. from [`uint_word`]) to `to`.
pub fn erc20_transfer_calldata(to: &[u8; 20], amount: &[u8; 32]) -> [u8; 68] {
    let mut out = [0u8; 68];
    out[..4].copy_from_slice(&function_selector("transfer(address,uint256)"));
    out[4..36].copy_from_slice(&address_word(to));
    out[36..].copy_from_slice(amount);
    out
}

#[cfg(feature = "alloc")]
fn two_pow_256() -> BigInt {
    BigInt::from(1) << 256
}

/// The width of an integer type: `prefix` (`uint` or `int`) alone means 256
/// bits, otherwise it is followed by a multiple of 8 from 8 to 256.
#[cfg(feature = "alloc")]
fn int_bits(t: &str, prefix: &str) -> Option<u32> {
    let n = t.strip_prefix(prefix)?;
    if n.is_empty() {
        return Some(256);
    }
    if n.starts_with('0') || !n.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let bits: u32 = n.parse().ok()?;
    (bits.is_multiple_of(8) && (8..=256).contains(&bits)).then_some(bits)
}

/// The size of a fixed-size byte array type, `bytes1` to `bytes32`.
#[cfg(feature = "alloc")]
fn fixed_bytes_len(t: &str) -> Option<usize> {
    let n = t.strip_prefix("bytes")?;
    if n.is_empty() || n.starts_with('0') || !n.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let len: usize = n.parse().ok()?;
    (1..=32).contains(&len).then_some(len)
}

#[cfg(feature = "alloc")]
/// A value that can be ABI-encoded.
///
/// Non-exhaustive: more ABI value kinds (fixed bytes, arrays, tuples, …) may be
/// added.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AbiValue {
    /// Unsigned/large integer.
    Uint(BigInt),
    /// Signed 64-bit integer.
    Int(i64),
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Boolean.
    Bool(bool),
    /// Dynamic byte string.
    Bytes(Vec<u8>),
    /// UTF-8 string.
    Str(String),
    /// An `Out` (used as an EVM address by `encode_auto`).
    Out(Out),
}

#[cfg(feature = "alloc")]
struct AbiString {
    offset: usize,
    data: Vec<u8>,
}

#[cfg(feature = "alloc")]
/// A builder for EVM ABI-encoded data.
#[derive(Default)]
pub struct AbiBuffer {
    buf: Vec<u8>,
    str: Vec<AbiString>,
    /// The length of the seed given to [`AbiBuffer::new`], which precedes
    /// the encoding and is not counted in its offsets.
    base: usize,
}

#[cfg(feature = "alloc")]
impl AbiBuffer {
    /// Creates a new buffer seeded with `buf`, typically a 4-byte function
    /// selector. The encoding starts after the seed: the offsets of dynamic
    /// values are relative to its end.
    pub fn new(buf: Vec<u8>) -> AbiBuffer {
        AbiBuffer {
            base: buf.len(),
            buf,
            str: Vec::new(),
        }
    }

    /// Encodes values by inferring their natural ABI representation.
    pub fn encode_auto(&mut self, params: &[AbiValue]) -> Result<(), Error> {
        for p in params {
            match p {
                AbiValue::Int(o) => self.append_big_int(&BigInt::from(*o))?,
                AbiValue::Uint64(o) => self.append_big_int(&BigInt::from(*o))?,
                AbiValue::Uint(o) => self.append_big_int(o)?,
                AbiValue::Bool(b) => self.append_big_int(&BigInt::from(*b as u8))?,
                AbiValue::Bytes(o) => self.append_bytes(o),
                AbiValue::Str(s) => self.append_bytes(s.as_bytes()),
                AbiValue::Out(o) => {
                    if o.name == "evm" || o.name == "eth" {
                        self.append_big_int(&BigInt::from_bytes_be(Sign::Plus, o.bytes()))?;
                    } else {
                        return Err(Error::AbiValueMismatch);
                    }
                }
            }
        }
        Ok(())
    }

    /// Encodes parameters according to an ABI signature like
    /// "transfer(address,uint256)".
    pub fn encode_abi(&mut self, abi: &str, params: &[AbiValue]) -> Result<(), Error> {
        let pos = abi.find('(').ok_or(Error::InvalidAbiSignature)?;
        if !abi.ends_with(')') {
            return Err(Error::InvalidAbiSignature);
        }
        let inner = &abi[pos + 1..abi.len() - 1];
        let types: Vec<&str> = if inner.is_empty() {
            Vec::new()
        } else {
            inner.split(',').collect()
        };
        self.encode_types(&types, params)
    }

    /// Encodes parameters according to explicit ABI type strings.
    ///
    /// Supported types: `uintN` and `intN` (`uint` and `int` meaning 256
    /// bits), which take an integer value within the type's range; `bytesN`,
    /// which takes [`AbiValue::Bytes`] of exactly `N` bytes; `address`;
    /// `bytes` and `string`.
    pub fn encode_types(&mut self, types: &[&str], params: &[AbiValue]) -> Result<(), Error> {
        if types.len() != params.len() {
            return Err(Error::AbiArgumentCount);
        }
        for (t, p) in types.iter().zip(params.iter()) {
            match *t {
                "address" => self.append_address_any(p)?,
                "bytes" | "string" => self.append_buffer_any(p)?,
                t => {
                    if let Some(bits) = int_bits(t, "uint") {
                        self.append_int_any(p, bits, false)?
                    } else if let Some(bits) = int_bits(t, "int") {
                        self.append_int_any(p, bits, true)?
                    } else if let Some(len) = fixed_bytes_len(t) {
                        self.append_fixed_bytes_any(p, len)?
                    } else {
                        return Err(Error::UnsupportedAbiType);
                    }
                }
            }
        }
        Ok(())
    }

    /// Appends an integer of a `bits`-wide type, checking its range: a
    /// negative value is not a `uintN` ([`Error::AbiValueMismatch`]), and a
    /// value outside the type's range is an [`Error::Overflow`].
    fn append_int_any(&mut self, v: &AbiValue, bits: u32, signed: bool) -> Result<(), Error> {
        let v = match v {
            AbiValue::Bool(b) => BigInt::from(*b as u8),
            AbiValue::Int(o) => BigInt::from(*o),
            AbiValue::Uint64(o) => BigInt::from(*o),
            AbiValue::Uint(o) => o.clone(),
            _ => return Err(Error::AbiValueMismatch),
        };
        let in_range = if signed {
            let bound = BigInt::from(1) << (bits - 1);
            v >= -&bound && v < bound
        } else {
            if v.sign() == Sign::Minus {
                return Err(Error::AbiValueMismatch);
            }
            v.bits() <= u64::from(bits)
        };
        if !in_range {
            return Err(Error::Overflow);
        }
        self.append_big_int(&v)
    }

    /// Appends a `bytesN` value: exactly `len` bytes, left-aligned in the
    /// word and zero-padded on the right. Integers are not accepted, as they
    /// would be right-aligned.
    fn append_fixed_bytes_any(&mut self, v: &AbiValue, len: usize) -> Result<(), Error> {
        let AbiValue::Bytes(b) = v else {
            return Err(Error::AbiValueMismatch);
        };
        if b.len() != len {
            return Err(Error::InvalidLength);
        }
        let mut word = [0u8; 32];
        word[..len].copy_from_slice(b);
        self.buf.extend_from_slice(&word);
        Ok(())
    }

    /// Validates that `addr` is exactly 20 bytes and appends it as a uint256-style
    /// ABI word (left-padded to 32 bytes).
    fn append_address_bytes(&mut self, addr: &[u8]) -> Result<(), Error> {
        if addr.len() != 20 {
            return Err(Error::InvalidAddress);
        }
        self.append_big_int(&BigInt::from_bytes_be(Sign::Plus, addr))
    }

    fn append_address_any(&mut self, v: &AbiValue) -> Result<(), Error> {
        match v {
            AbiValue::Out(o) => {
                if o.name != "evm" && o.name != "eth" {
                    return Err(Error::AbiValueMismatch);
                }
                self.append_address_bytes(o.bytes())
            }
            AbiValue::Bytes(b) => self.append_address_bytes(b),
            AbiValue::Str(s) => {
                let s = s.strip_prefix("0x").unwrap_or(s);
                let addr = hex::decode(s).map_err(|_| Error::InvalidAddress)?;
                self.append_address_bytes(&addr)
            }
            _ => Err(Error::AbiValueMismatch),
        }
    }

    fn append_buffer_any(&mut self, v: &AbiValue) -> Result<(), Error> {
        match v {
            AbiValue::Bytes(o) => {
                self.append_bytes(o);
                Ok(())
            }
            AbiValue::Str(s) => {
                self.append_bytes(s.as_bytes());
                Ok(())
            }
            _ => Err(Error::AbiValueMismatch),
        }
    }

    /// Appends a 256-bit integer (big-endian, 32 bytes): a non-negative value
    /// below 2^256, or a negative one down to -2^255 in two's complement.
    /// Anything else is an [`Error::Overflow`].
    pub fn append_big_int(&mut self, v: &BigInt) -> Result<(), Error> {
        let bound = two_pow_256();
        // Only the (rare) negative case allocates; the common path borrows `v`.
        let owned;
        let val: &BigInt = if v.sign() == Sign::Minus {
            // two's complement: 2^256 + v (v is negative). For v == -1 this yields
            // an all-ones 32-byte word. Below -2^255 the result would wrap
            // into the positive int256 range.
            let min: BigInt = -(BigInt::from(1) << 255u32);
            if *v < min {
                return Err(Error::Overflow);
            }
            owned = &bound + v;
            &owned
        } else {
            v
        };
        if *val >= bound {
            return Err(Error::Overflow);
        }
        let mut inbuf = [0u8; 32];
        let (_, bytes) = val.to_bytes_be();
        inbuf[32 - bytes.len()..].copy_from_slice(&bytes);
        self.buf.extend_from_slice(&inbuf);
        Ok(())
    }

    /// Appends a dynamic byte buffer (stored as an offset pointer + tail data).
    pub fn append_bytes(&mut self, v: &[u8]) {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 32]);
        let mut len_buf = [0u8; 32];
        let len_bytes = (v.len() as u64).to_be_bytes();
        len_buf[24..].copy_from_slice(&len_bytes);
        let mut data = len_buf.to_vec();
        data.extend_from_slice(v);
        self.str.push(AbiString { offset: pos, data });
    }

    /// Returns the encoded ABI buffer.
    pub fn bytes(&self) -> Vec<u8> {
        let mut res = self.buf.clone();
        for s in &self.str {
            let mut in_ = s.data.clone();
            let x = in_.len() % 32;
            if x != 0 {
                in_.extend(core::iter::repeat_n(0u8, 32 - x));
            }
            let pos = (res.len() - self.base) as u64;
            let mut pos_buf = [0u8; 32];
            pos_buf[24..].copy_from_slice(&pos.to_be_bytes());
            res[s.offset..s.offset + 32].copy_from_slice(&pos_buf);
            res.extend_from_slice(&in_);
        }
        res
    }

    /// Returns the ABI-encoded method call (4-byte selector + encoded args).
    /// The selector is that of the canonical signature (see
    /// [`function_selector`]).
    pub fn call(&self, method: &str) -> Vec<u8> {
        let mut out = function_selector(method).to_vec();
        out.extend_from_slice(&self.bytes());
        out
    }
}

#[cfg(feature = "alloc")]
/// Generates calldata for an EVM call, performing no validation that the
/// parameters match the ABI signature.
pub fn evm_call(method: &str, params: &[AbiValue]) -> Result<Vec<u8>, Error> {
    let mut buf = AbiBuffer::default();
    buf.encode_abi(method, params)?;
    Ok(buf.call(method))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::address::parse_evm_address;

    #[test]
    fn erc20_transfer_fixed() {
        let mut to = [0u8; 20];
        hex::decode_to_slice("5fb84129ad9e7818f099966de975ff41213f028d", &mut to).unwrap();
        let data = erc20_transfer_calldata(&to, &uint_word(123456789123456789));
        let mut want = [0u8; 68];
        hex::decode_to_slice(
            "a9059cbb0000000000000000000000005fb84129ad9e7818f099966de975ff41213f028d00000000000000000000000000000000000000000000000001b69b4bacd05f15",
            &mut want,
        )
        .unwrap();
        assert_eq!(data, want);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn transfer_encode_auto() {
        let mut buf = AbiBuffer::default();
        let addr = parse_evm_address("0x5Fb84129AD9E7818F099966de975ff41213F028d").unwrap();
        buf.encode_auto(&[
            AbiValue::Out(addr),
            AbiValue::Uint(BigInt::from(123456789123456789u64)),
        ])
        .unwrap();
        let call = buf.call("transfer(address,uint256)");
        assert_eq!(
            hex::encode(call),
            "a9059cbb0000000000000000000000005fb84129ad9e7818f099966de975ff41213f028d00000000000000000000000000000000000000000000000001b69b4bacd05f15"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn address_abi_type_encodes() {
        // The "address" ABI type must be usable via encode_abi (the evm_call path),
        // not only encode_auto.
        let addr = parse_evm_address("0x5Fb84129AD9E7818F099966de975ff41213F028d").unwrap();
        let mut buf = AbiBuffer::default();
        buf.encode_abi(
            "transfer(address,uint256)",
            &[
                AbiValue::Out(addr),
                AbiValue::Uint(BigInt::from(123456789123456789u64)),
            ],
        )
        .unwrap();
        let call = buf.call("transfer(address,uint256)");
        assert_eq!(
            hex::encode(call),
            "a9059cbb0000000000000000000000005fb84129ad9e7818f099966de975ff41213f028d00000000000000000000000000000000000000000000000001b69b4bacd05f15"
        );

        // a "0x..." string address also works
        let mut buf2 = AbiBuffer::default();
        buf2.encode_types(
            &["address"],
            &[AbiValue::Str(
                "0x5Fb84129AD9E7818F099966de975ff41213F028d".into(),
            )],
        )
        .unwrap();

        // an address that is not 20 bytes is rejected
        let mut buf3 = AbiBuffer::default();
        assert!(
            buf3.encode_types(&["address"], &[AbiValue::Bytes(vec![0u8; 19])])
                .is_err()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn negative_two_complement() {
        // -1 must encode as the all-ones 32-byte word, not be rejected.
        let mut buf = AbiBuffer::default();
        buf.append_big_int(&BigInt::from(-1)).unwrap();
        assert_eq!(hex::encode(buf.bytes()), "f".repeat(64));
    }

    #[test]
    fn selector_canonicalizes_aliases() {
        assert_eq!(
            function_selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert_eq!(
            function_selector("transfer(address,uint)"),
            function_selector("transfer(address,uint256)")
        );
        assert_eq!(
            function_selector("f(int,uint[],(uint,int)[2])"),
            function_selector("f(int256,uint256[],(uint256,int256)[2])")
        );
        // only whole type names, and only in the parameter list
        assert_ne!(
            function_selector("f(uint8)"),
            function_selector("f(uint2568)")
        );
        assert_ne!(
            function_selector("uint(bool)"),
            function_selector("uint256(bool)")
        );
        assert_ne!(
            function_selector("f(my_uint)"),
            function_selector("f(my_uint256)")
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn call_selector_for_aliases() {
        let args = [AbiValue::Uint64(5)];
        assert_eq!(
            evm_call("f(uint)", &args).unwrap(),
            evm_call("f(uint256)", &args).unwrap()
        );
        assert_eq!(
            evm_call("f(int)", &args).unwrap(),
            evm_call("f(int256)", &args).unwrap()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn fixed_bytes_are_left_aligned() {
        let enc = |t: &str, v: AbiValue| {
            let mut buf = AbiBuffer::default();
            buf.encode_types(&[t], &[v])
                .map(|()| hex::encode(buf.bytes()))
        };
        assert_eq!(
            enc("bytes4", AbiValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef])).unwrap(),
            format!("deadbeef{}", "0".repeat(56))
        );
        assert_eq!(
            enc("bytes32", AbiValue::Bytes(vec![0xab; 32])).unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(
            enc("bytes1", AbiValue::Bytes(vec![0x01])).unwrap(),
            format!("01{}", "0".repeat(62))
        );
        // the wrong length, and integers (which would be right-aligned)
        assert_eq!(
            enc("bytes4", AbiValue::Bytes(vec![1, 2, 3])),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            enc("bytes4", AbiValue::Bytes(vec![1, 2, 3, 4, 5])),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            enc("bytes4", AbiValue::Uint64(0xdeadbeef)),
            Err(Error::AbiValueMismatch)
        );
        assert_eq!(
            enc("bytes32", AbiValue::Int(1)),
            Err(Error::AbiValueMismatch)
        );
        // not types
        for t in [
            "bytes0", "bytes33", "bytes04", "uint7", "uint264", "uint08", "int0", "uintx",
        ] {
            assert_eq!(
                enc(t, AbiValue::Bytes(vec![1])),
                Err(Error::UnsupportedAbiType),
                "{t}"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn integers_are_range_checked() {
        let enc = |t: &str, v: AbiValue| {
            let mut buf = AbiBuffer::default();
            buf.encode_types(&[t], &[v])
                .map(|()| hex::encode(buf.bytes()))
        };
        let pow = |n: u32| BigInt::from(1) << n;
        let word = |v: u64| format!("{v:064x}");

        // uintN: no negatives, nothing at or above 2^N
        assert_eq!(
            enc("uint256", AbiValue::Int(-1)),
            Err(Error::AbiValueMismatch)
        );
        assert_eq!(enc("uint", AbiValue::Int(-1)), Err(Error::AbiValueMismatch));
        assert_eq!(
            enc("uint8", AbiValue::Uint(BigInt::from(-1))),
            Err(Error::AbiValueMismatch)
        );
        assert_eq!(enc("uint8", AbiValue::Uint64(255)).unwrap(), word(255));
        assert_eq!(enc("uint8", AbiValue::Uint64(256)), Err(Error::Overflow));
        assert_eq!(enc("uint8", AbiValue::Int(256)), Err(Error::Overflow));
        assert_eq!(
            enc("uint64", AbiValue::Uint64(u64::MAX)).unwrap(),
            word(u64::MAX)
        );
        assert_eq!(enc("uint64", AbiValue::Uint(pow(64))), Err(Error::Overflow));
        assert_eq!(
            enc("uint256", AbiValue::Uint(pow(256) - 1)).unwrap(),
            "f".repeat(64)
        );
        assert_eq!(
            enc("uint256", AbiValue::Uint(pow(256))),
            Err(Error::Overflow)
        );
        assert_eq!(
            enc("uint24", AbiValue::Uint64(0xff_ffff)).unwrap(),
            word(0xff_ffff)
        );
        assert_eq!(
            enc("uint24", AbiValue::Uint64(0x100_0000)),
            Err(Error::Overflow)
        );
        assert_eq!(enc("uint8", AbiValue::Bool(true)).unwrap(), word(1));

        // intN: two's complement within N bits
        assert_eq!(enc("int8", AbiValue::Int(-1)).unwrap(), "f".repeat(64));
        assert_eq!(enc("int8", AbiValue::Int(127)).unwrap(), word(127));
        assert_eq!(
            enc("int8", AbiValue::Int(-128)).unwrap(),
            format!("{}80", "f".repeat(62))
        );
        assert_eq!(enc("int8", AbiValue::Int(128)), Err(Error::Overflow));
        assert_eq!(enc("int8", AbiValue::Int(-129)), Err(Error::Overflow));
        assert_eq!(enc("int8", AbiValue::Uint64(128)), Err(Error::Overflow));
        assert_eq!(
            enc("int256", AbiValue::Uint(-pow(255))).unwrap(),
            format!("8{}", "0".repeat(63))
        );
        assert_eq!(
            enc("int", AbiValue::Uint(pow(255) - 1)).unwrap(),
            format!("7{}", "f".repeat(63))
        );
        assert_eq!(
            enc("int256", AbiValue::Uint(pow(255))),
            Err(Error::Overflow)
        );
        assert_eq!(
            enc("int256", AbiValue::Uint(-pow(255) - 1)),
            Err(Error::Overflow)
        );
        assert_eq!(
            enc("int256", AbiValue::Str("1".into())),
            Err(Error::AbiValueMismatch)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn append_big_int_bounds() {
        let pow = |n: u32| BigInt::from(1) << n;
        let app = |v: BigInt| {
            let mut buf = AbiBuffer::default();
            buf.append_big_int(&v).map(|()| hex::encode(buf.bytes()))
        };
        assert_eq!(app(-pow(255)).unwrap(), format!("8{}", "0".repeat(63)));
        // below -2^255 used to wrap into the positive range
        assert_eq!(app(-pow(255) - 1), Err(Error::Overflow));
        assert_eq!(app(-pow(256) + 1), Err(Error::Overflow));
        assert_eq!(app(-pow(256)), Err(Error::Overflow));
        assert_eq!(app(-pow(300)), Err(Error::Overflow));
        assert_eq!(app(pow(256) - 1).unwrap(), "f".repeat(64));
        assert_eq!(app(pow(256)), Err(Error::Overflow));
    }

    /// Offsets of dynamic values are relative to the start of the encoding,
    /// not of a selector the buffer was seeded with.
    #[cfg(feature = "alloc")]
    #[test]
    fn seeded_buffer_offsets() {
        let sig = "castVoteWithReason(uint256,uint8,string)";
        let args = [
            AbiValue::Int(123456789123456789),
            AbiValue::Int(1),
            AbiValue::Str("this is a test".into()),
        ];
        let mut seeded = AbiBuffer::new(function_selector(sig).to_vec());
        seeded.encode_abi(sig, &args).unwrap();
        assert_eq!(seeded.bytes(), evm_call(sig, &args).unwrap());

        // two dynamic values
        let mut seeded = AbiBuffer::new(vec![1, 2, 3, 4]);
        let mut plain = AbiBuffer::default();
        for buf in [&mut seeded, &mut plain] {
            buf.encode_types(
                &["bytes", "uint8", "string"],
                &[
                    AbiValue::Bytes(vec![0xaa; 33]),
                    AbiValue::Uint64(7),
                    AbiValue::Str("x".into()),
                ],
            )
            .unwrap();
        }
        assert_eq!(&seeded.bytes()[4..], &plain.bytes()[..]);
        assert_eq!(&plain.bytes()[..32], &uint_word(0x60)[..]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn cast_vote_with_reason() {
        let call = evm_call(
            "castVoteWithReason(uint256,uint8,string)",
            &[
                AbiValue::Int(123456789123456789),
                AbiValue::Int(1),
                AbiValue::Str("this is a test".into()),
            ],
        )
        .unwrap();
        assert_eq!(
            hex::encode(call),
            "7b3c71d300000000000000000000000000000000000000000000000001b69b4bacd05f1500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000e7468697320697320612074657374000000000000000000000000000000000000"
        );
    }
}
