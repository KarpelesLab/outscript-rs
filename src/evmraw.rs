//! Heap-free EVM transaction signing: [`RawEvmTx`] holds fixed-size fields and
//! streams its RLP encoding straight into keccak-256 or a caller buffer.
//!
//! Supports legacy (with or without EIP-155 replay protection), EIP-2930 and
//! EIP-1559 transactions with an empty access list — the same subset as
//! `EvmTx`.

use purecrypto::hash::{Digest, Keccak256};

use crate::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
use crate::hash::ether_hash;
use crate::sink::{Counter, HashSink, Sink, SliceSink};

/// EVM transaction type.
///
/// Non-exhaustive: Ethereum continues to define new EIP-2718 transaction types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvmTxType {
    /// Legacy (pre-EIP-2718).
    Legacy,
    /// EIP-2930 access-list transaction.
    Eip2930,
    /// EIP-1559 dynamic-fee transaction.
    Eip1559,
    /// EIP-4844 blob transaction.
    Eip4844,
}

impl EvmTxType {
    pub(crate) fn type_value(self) -> u8 {
        match self {
            EvmTxType::Legacy => 0,
            EvmTxType::Eip2930 => 1,
            EvmTxType::Eip1559 => 2,
            EvmTxType::Eip4844 => 3,
        }
    }
}

/// Errors from [`RawEvmTx`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The transaction type cannot be encoded (EIP-4844).
    UnsupportedType,
    /// The signature's `v` does not match the transaction type.
    InvalidV,
    /// Public-key recovery failed.
    Recovery,
    /// The output buffer is too small.
    BufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::UnsupportedType => "transaction type not supported",
            Error::InvalidV => "invalid signature v value",
            Error::Recovery => "sender recovery failed",
            Error::BufferTooSmall => "transaction output buffer too small",
        })
    }
}

impl core::error::Error for Error {}

/// A transaction signature as carried in the encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmSignature {
    /// `v`: the y-parity for typed transactions, `27 + recid` for pre-EIP-155
    /// legacy, or `chain_id * 2 + 35 + recid` for EIP-155 legacy.
    pub v: u64,
    /// `r`, big-endian.
    pub r: [u8; 32],
    /// `s`, big-endian.
    pub s: [u8; 32],
}

/// An EVM transaction with fixed-size fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEvmTx<'a> {
    /// Transaction type.
    pub tx_type: EvmTxType,
    /// Chain id (0 for a pre-EIP-155 legacy transaction).
    pub chain_id: u64,
    /// Account nonce.
    pub nonce: u64,
    /// Max priority fee per gas (EIP-1559 only).
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas (EIP-1559), or the gas price (legacy/EIP-2930).
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas: u64,
    /// Destination, or `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei, as a big-endian uint256.
    pub value: [u8; 32],
    /// Calldata.
    pub data: &'a [u8],
}

// --- RLP ---

fn trim(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

/// The RLP header for a string (`base` 0x80) or list (`base` 0xc0) of `len`
/// bytes, as a buffer and its used length.
fn rlp_header(base: u8, len: usize) -> ([u8; 9], usize) {
    let mut h = [0u8; 9];
    if len <= 55 {
        h[0] = base + len as u8;
        (h, 1)
    } else {
        let be = (len as u64).to_be_bytes();
        let len_bytes = trim(&be);
        h[0] = base + 55 + len_bytes.len() as u8;
        h[1..=len_bytes.len()].copy_from_slice(len_bytes);
        (h, 1 + len_bytes.len())
    }
}

fn rlp_bytes<S: Sink>(s: &mut S, b: &[u8]) {
    if b.len() == 1 && b[0] <= 0x7f {
        s.put(b);
    } else {
        let (h, n) = rlp_header(0x80, b.len());
        s.put(&h[..n]);
        s.put(b);
    }
}

fn rlp_uint<S: Sink>(s: &mut S, be: &[u8]) {
    rlp_bytes(s, trim(be));
}

impl RawEvmTx<'_> {
    /// Writes the RLP list items; `sig` adds v, r, s, and `eip155_suffix` adds
    /// the legacy `[chain_id, 0, 0]` signing suffix.
    fn write_fields<S: Sink>(&self, s: &mut S, sig: Option<&EvmSignature>, eip155_suffix: bool) {
        let to: &[u8] = match &self.to {
            Some(a) => a,
            None => &[],
        };
        match self.tx_type {
            EvmTxType::Legacy => {
                rlp_uint(s, &self.nonce.to_be_bytes());
                rlp_uint(s, &self.max_fee_per_gas.to_be_bytes());
                rlp_uint(s, &self.gas.to_be_bytes());
                rlp_bytes(s, to);
                rlp_uint(s, &self.value);
                rlp_bytes(s, self.data);
                if eip155_suffix {
                    rlp_uint(s, &self.chain_id.to_be_bytes());
                    rlp_uint(s, &[]);
                    rlp_uint(s, &[]);
                }
            }
            EvmTxType::Eip2930 | EvmTxType::Eip1559 => {
                rlp_uint(s, &self.chain_id.to_be_bytes());
                rlp_uint(s, &self.nonce.to_be_bytes());
                if self.tx_type == EvmTxType::Eip1559 {
                    rlp_uint(s, &self.max_priority_fee_per_gas.to_be_bytes());
                }
                rlp_uint(s, &self.max_fee_per_gas.to_be_bytes());
                rlp_uint(s, &self.gas.to_be_bytes());
                rlp_bytes(s, to);
                rlp_uint(s, &self.value);
                rlp_bytes(s, self.data);
                s.put(&[0xc0]); // empty access list
            }
            EvmTxType::Eip4844 => unreachable!("rejected by encode"),
        }
        if let Some(sig) = sig {
            rlp_uint(s, &sig.v.to_be_bytes());
            rlp_uint(s, &sig.r);
            rlp_uint(s, &sig.s);
        }
    }

    /// Writes the full encoding: optional type byte, then the RLP list.
    fn encode<S: Sink>(&self, s: &mut S, sig: Option<&EvmSignature>) -> Result<(), Error> {
        if self.tx_type == EvmTxType::Eip4844 {
            return Err(Error::UnsupportedType);
        }
        let eip155_suffix =
            sig.is_none() && self.tx_type == EvmTxType::Legacy && self.chain_id != 0;
        let mut body = Counter::default();
        self.write_fields(&mut body, sig, eip155_suffix);
        if self.tx_type != EvmTxType::Legacy {
            s.put(&[self.tx_type.type_value()]);
        }
        let (h, n) = rlp_header(0xc0, body.0);
        s.put(&h[..n]);
        self.write_fields(s, sig, eip155_suffix);
        Ok(())
    }

    /// The keccak-256 digest that is signed.
    pub fn signing_hash(&self) -> Result<[u8; 32], Error> {
        let mut h = HashSink(Keccak256::new());
        self.encode(&mut h, None)?;
        Ok(h.0.finalize())
    }

    /// Signs the transaction, returning the signature with `v` in the form the
    /// transaction type requires.
    pub fn sign(&self, key: &SecpPrivateKey) -> Result<EvmSignature, Error> {
        let (r, s, recid) = key.sign_recoverable(&self.signing_hash()?);
        let recid = recid as u64;
        let v = match self.tx_type {
            EvmTxType::Legacy if self.chain_id == 0 => 27 + recid,
            EvmTxType::Legacy => self.chain_id * 2 + 35 + recid,
            _ => recid,
        };
        Ok(EvmSignature { v, r, s })
    }

    /// Recovers the 20-byte sender address from a signature.
    pub fn recover_sender(&self, sig: &EvmSignature) -> Result<[u8; 20], Error> {
        let recid = match (self.tx_type, sig.v) {
            (EvmTxType::Legacy, v) if v >= 35 => {
                if (v - 35) / 2 != self.chain_id {
                    return Err(Error::InvalidV);
                }
                (v - 35) % 2
            }
            (EvmTxType::Legacy, 27 | 28) if self.chain_id == 0 => sig.v - 27,
            (EvmTxType::Legacy, _) => return Err(Error::InvalidV),
            (_, v @ (0 | 1)) => v,
            _ => return Err(Error::InvalidV),
        };
        let pubkey = recover_public_key(&sig.r, &sig.s, recid as u8, &self.signing_hash()?)
            .map_err(|_| Error::Recovery)?;
        Ok(ether_hash(&pubkey.serialize_uncompressed()))
    }

    /// The length of the signed encoding.
    pub fn signed_len(&self, sig: &EvmSignature) -> Result<usize, Error> {
        let mut c = Counter::default();
        self.encode(&mut c, Some(sig))?;
        Ok(c.0)
    }

    /// Writes the signed encoding into `out`, returning the number of bytes
    /// written.
    pub fn encode_signed_to_slice(
        &self,
        sig: &EvmSignature,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut s = SliceSink::new(out);
        self.encode(&mut s, Some(sig))?;
        s.finish().ok_or(Error::BufferTooSmall)
    }

    /// The transaction hash: keccak-256 of the signed encoding.
    pub fn tx_hash(&self, sig: &EvmSignature) -> Result<[u8; 32], Error> {
        let mut h = HashSink(Keccak256::new());
        self.encode(&mut h, Some(sig))?;
        Ok(h.0.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let mut a = [0u8; N];
        hex::decode_to_slice(s, &mut a).unwrap();
        a
    }

    fn u256(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    /// Mainnet legacy EIP-155 transaction (also used by `evmtx`'s tests).
    #[test]
    fn legacy_known_vector() {
        let tx = RawEvmTx {
            tx_type: EvmTxType::Legacy,
            chain_id: 1,
            nonce: 0x1e,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0x07ea8ed400,
            gas: 0x5208,
            to: Some(h("43badf0e63ac147ace611dc1113afe0ea3f86917")),
            value: u256(0xd529ae9e860000),
            data: &[],
        };
        let sig = EvmSignature {
            v: 0x26,
            r: h("cacce90eb140f837a139e5d8acbe73527663aea163d4e4c6e8218681d1d37b0f"),
            s: h("7fdb860517234804b71bbc518ecb4dc4bb96c1944ab28d502fc429baac939b3c"),
        };
        let want: [u8; 109] = h(
            "f86b1e8507ea8ed4008252089443badf0e63ac147ace611dc1113afe0ea3f8691787d529ae9e8600008026a0cacce90eb140f837a139e5d8acbe73527663aea163d4e4c6e8218681d1d37b0fa07fdb860517234804b71bbc518ecb4dc4bb96c1944ab28d502fc429baac939b3c",
        );
        let mut out = [0u8; 109];
        assert_eq!(tx.signed_len(&sig), Ok(109));
        assert_eq!(tx.encode_signed_to_slice(&sig, &mut out), Ok(109));
        assert_eq!(out, want);
        assert_eq!(
            tx.tx_hash(&sig),
            Ok(h(
                "bac4cb10f95b37dab2c8a78e880d39661cc53f87386ded2fb721ac2304113ea3"
            ))
        );
        assert_eq!(
            tx.recover_sender(&sig),
            Ok(h("ebe790e554f30924801b48197dcb6f71de2760bc"))
        );
        assert_eq!(
            tx.encode_signed_to_slice(&sig, &mut out[..108]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn sign_recover_roundtrip_all_types() {
        let key = SecpPrivateKey::from_bytes(&h(
            "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        ))
        .unwrap();
        let want = h("2aeb8add8337360e088b7d9ce4e857b9be60f3a7");
        let data = [0xabu8; 100]; // long enough for a two-byte RLP header
        for (tx_type, chain_id) in [
            (EvmTxType::Legacy, 0),
            (EvmTxType::Legacy, 137),
            (EvmTxType::Eip2930, 1),
            (EvmTxType::Eip1559, 1),
        ] {
            let tx = RawEvmTx {
                tx_type,
                chain_id,
                nonce: 42,
                max_priority_fee_per_gas: 2_000_000_000,
                max_fee_per_gas: 30_000_000_000,
                gas: 60_000,
                to: None,
                value: u256(10u128.pow(18)),
                data: &data,
            };
            let sig = tx.sign(&key).unwrap();
            assert_eq!(tx.recover_sender(&sig), Ok(want), "{tx_type:?}/{chain_id}");
            let wrong_chain = RawEvmTx {
                chain_id: chain_id + 1,
                ..tx
            };
            assert_ne!(wrong_chain.recover_sender(&sig), Ok(want));
        }
        let blob = RawEvmTx {
            tx_type: EvmTxType::Eip4844,
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas: 0,
            to: None,
            value: [0; 32],
            data: &[],
        };
        assert_eq!(blob.signing_hash(), Err(Error::UnsupportedType));
    }
}
