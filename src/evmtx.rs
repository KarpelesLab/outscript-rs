//! EVM transactions: legacy, EIP-2930, EIP-1559, EIP-4844. Build, sign,
//! serialize, parse and recover sender. Port of `evmtx.go`.

pub use crate::Error;

use crate::prelude::*;

use num_bigint::{BigInt, Sign};
use num_traits::{Num, ToPrimitive};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::address::eip55;
use crate::crypto::secp256k1::{SecpPrivateKey, recover_public_key};
use crate::evmabi::{AbiValue, evm_call};
pub use crate::evmraw::EvmTxType;
use crate::hash::keccak256_once;
use crate::rlp::{self, RlpItem};

/// An EVM transaction.
#[derive(Debug, Clone)]
pub struct EvmTx {
    /// Account nonce.
    pub nonce: u64,
    /// Max priority fee per gas (EIP-1559).
    pub gas_tip_cap: BigInt,
    /// Max fee per gas / gas price (legacy/2930).
    pub gas_fee_cap: BigInt,
    /// Gas limit.
    pub gas: u64,
    /// Destination address, "0x..." (empty "0x" for contract creation).
    pub to: String,
    /// Value in wei.
    pub value: BigInt,
    /// Calldata.
    pub data: Vec<u8>,
    /// Chain id (encoded in v for legacy EIP-155).
    pub chain_id: u64,
    /// Transaction type.
    pub tx_type: EvmTxType,
    /// Whether the transaction has been signed.
    pub signed: bool,
    /// Signature y-parity / v.
    pub y: BigInt,
    /// Signature r.
    pub r: BigInt,
    /// Signature s.
    pub s: BigInt,
    /// The access list of an EIP-2930 or EIP-1559 transaction, as its RLP
    /// entries: each a list of a 20-byte address and a list of 32-byte
    /// storage keys. Empty for none; must be empty for a legacy transaction.
    pub access_list: Vec<RlpItem>,
}

impl Default for EvmTx {
    fn default() -> Self {
        EvmTx {
            nonce: 0,
            gas_tip_cap: BigInt::from(0),
            gas_fee_cap: BigInt::from(0),
            gas: 0,
            to: String::new(),
            value: BigInt::from(0),
            data: Vec::new(),
            chain_id: 0,
            tx_type: EvmTxType::Legacy,
            signed: false,
            y: BigInt::from(0),
            r: BigInt::from(0),
            s: BigInt::from(0),
            access_list: Vec::new(),
        }
    }
}

/// The `to` field: empty for `"0x"` (contract creation), otherwise exactly 20
/// bytes from 40 hex digits. Anything else is an error: a truncated address
/// must never be padded into a different one.
fn to_item(to: &str) -> Result<RlpItem, Error> {
    let body = to.strip_prefix("0x").ok_or(Error::InvalidAddress)?;
    if body.is_empty() {
        return Ok(RlpItem::Bytes(Vec::new()));
    }
    let mut addr = [0u8; 20];
    hex::decode_to_slice(body, &mut addr).map_err(|_| Error::InvalidAddress)?;
    Ok(RlpItem::Bytes(addr.to_vec()))
}

/// Checks that every access-list entry is `[address, [storage key, ...]]`
/// with a 20-byte address and 32-byte keys.
fn check_access_list(entries: &[RlpItem]) -> Result<(), Error> {
    for entry in entries {
        let Some([RlpItem::Bytes(address), RlpItem::List(keys)]) = entry.as_list() else {
            return Err(Error::InvalidData);
        };
        if address.len() != 20 {
            return Err(Error::InvalidData);
        }
        for key in keys {
            match key {
                RlpItem::Bytes(k) if k.len() == 32 => {}
                _ => return Err(Error::InvalidData),
            }
        }
    }
    Ok(())
}

// --- parsed fields ---

/// A byte-string field; a list is malformed.
fn field_bytes(item: &RlpItem) -> Result<&[u8], Error> {
    item.as_bytes().ok_or(Error::InvalidData)
}

/// An integer field: a byte string without a leading zero byte.
fn field_int(item: &RlpItem) -> Result<&[u8], Error> {
    let b = field_bytes(item)?;
    if b.first() == Some(&0) {
        return Err(Error::NonCanonical);
    }
    Ok(b)
}

fn field_u64(item: &RlpItem) -> Result<u64, Error> {
    rlp::decode_uint64_checked(field_int(item)?).map_err(Error::from)
}

/// An integer field of at most 256 bits.
fn field_u256(item: &RlpItem) -> Result<BigInt, Error> {
    let b = field_int(item)?;
    if b.len() > 32 {
        return Err(Error::TooLarge);
    }
    Ok(BigInt::from_bytes_be(Sign::Plus, b))
}

/// The `to` field: empty (contract creation) or a 20-byte address.
fn field_to(item: &RlpItem) -> Result<String, Error> {
    let b = field_bytes(item)?;
    if !b.is_empty() && b.len() != 20 {
        return Err(Error::InvalidAddress);
    }
    Ok(format!("0x{}", hex::encode(b)))
}

/// A signature's `r` or `s`: an integer of at most 32 bytes.
fn field_sig(item: &RlpItem) -> Result<BigInt, Error> {
    let b = field_int(item)?;
    if b.len() > 32 {
        return Err(Error::InvalidSignature);
    }
    Ok(BigInt::from_bytes_be(Sign::Plus, b))
}

impl EvmTx {
    /// Returns the RLP fields for the transaction (excluding signature fields).
    pub fn rlp_fields(&self) -> Result<Vec<RlpItem>, Error> {
        let bi = |v: &BigInt| RlpItem::bigint(v).map_err(Error::from);
        if self.tx_type == EvmTxType::Legacy && !self.access_list.is_empty() {
            return Err(Error::InvalidData);
        }
        check_access_list(&self.access_list)?;
        Ok(match self.tx_type {
            EvmTxType::Legacy => vec![
                RlpItem::uint(self.nonce),
                bi(&self.gas_fee_cap)?,
                RlpItem::uint(self.gas),
                to_item(&self.to)?,
                bi(&self.value)?,
                RlpItem::Bytes(self.data.clone()),
            ],
            EvmTxType::Eip2930 => vec![
                RlpItem::uint(self.chain_id),
                RlpItem::uint(self.nonce),
                bi(&self.gas_fee_cap)?,
                RlpItem::uint(self.gas),
                to_item(&self.to)?,
                bi(&self.value)?,
                RlpItem::Bytes(self.data.clone()),
                RlpItem::List(self.access_list.clone()),
            ],
            EvmTxType::Eip1559 => vec![
                RlpItem::uint(self.chain_id),
                RlpItem::uint(self.nonce),
                bi(&self.gas_tip_cap)?,
                bi(&self.gas_fee_cap)?,
                RlpItem::uint(self.gas),
                to_item(&self.to)?,
                bi(&self.value)?,
                RlpItem::Bytes(self.data.clone()),
                RlpItem::List(self.access_list.clone()),
            ],
            EvmTxType::Eip4844 => return Err(Error::UnsupportedTxType),
        })
    }

    /// Returns the bytes signed to produce the signature.
    pub fn sign_bytes(&self) -> Result<Vec<u8>, Error> {
        match self.tx_type {
            EvmTxType::Legacy => {
                let mut f = self.rlp_fields()?;
                if self.chain_id != 0 {
                    f.push(RlpItem::uint(self.chain_id));
                    f.push(RlpItem::uint(0));
                    f.push(RlpItem::uint(0));
                }
                Ok(rlp::encode_list(&f))
            }
            _ => {
                let f = self.rlp_fields()?;
                let mut out = vec![self.tx_type.type_value()];
                out.extend_from_slice(&rlp::encode_list(&f));
                Ok(out)
            }
        }
    }

    /// Serializes the transaction.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if !self.signed {
            return self.sign_bytes();
        }
        let bi = |v: &BigInt| RlpItem::bigint(v).map_err(Error::from);
        let mut f = self.rlp_fields()?;
        f.push(bi(&self.y)?);
        f.push(bi(&self.r)?);
        f.push(bi(&self.s)?);
        match self.tx_type {
            EvmTxType::Legacy => Ok(rlp::encode_list(&f)),
            _ => {
                let mut out = vec![self.tx_type.type_value()];
                out.extend_from_slice(&rlp::encode_list(&f));
                Ok(out)
            }
        }
    }

    /// Parses a transaction from its binary encoding.
    ///
    /// The encoding must be well formed, so that the parsed transaction
    /// serializes back to the same bytes: integer fields have no leading zero
    /// byte, `to` is empty or 20 bytes, `r` and `s` are at most 32 bytes, and
    /// the access list of a typed transaction (kept in
    /// [`access_list`](Self::access_list)) is a list of
    /// `[address, [storage key, ...]]` entries.
    pub fn parse_transaction(buf: &[u8]) -> Result<EvmTx, Error> {
        let (tx_type, payload) = match buf.first() {
            None => return Err(Error::UnexpectedEof),
            Some(&b) if b >= 0x80 => (EvmTxType::Legacy, buf),
            Some(1) => (EvmTxType::Eip2930, &buf[1..]),
            Some(2) => (EvmTxType::Eip1559, &buf[1..]),
            Some(_) => return Err(Error::UnsupportedTxType),
        };
        let dec = rlp::decode(payload).map_err(Error::from)?;
        let [RlpItem::List(list)] = dec.as_slice() else {
            return Err(Error::InvalidData);
        };
        let unsigned_len = match tx_type {
            EvmTxType::Legacy => 6,
            EvmTxType::Eip2930 => 8,
            _ => 9,
        };
        let signed = match list.len() {
            n if n == unsigned_len => false,
            n if n == unsigned_len + 3 => true,
            _ => return Err(Error::InvalidFieldCount),
        };
        let mut fields = list.iter();
        let mut next = || fields.next().ok_or(Error::InvalidFieldCount);
        let mut tx = EvmTx {
            tx_type,
            signed,
            ..Default::default()
        };
        if tx_type != EvmTxType::Legacy {
            tx.chain_id = field_u64(next()?)?;
        }
        tx.nonce = field_u64(next()?)?;
        if tx_type == EvmTxType::Eip1559 {
            tx.gas_tip_cap = field_u256(next()?)?;
        }
        tx.gas_fee_cap = field_u256(next()?)?;
        tx.gas = field_u64(next()?)?;
        tx.to = field_to(next()?)?;
        tx.value = field_u256(next()?)?;
        tx.data = field_bytes(next()?)?.to_vec();
        if tx_type != EvmTxType::Legacy {
            let access_list = next()?.as_list().ok_or(Error::InvalidData)?;
            check_access_list(access_list)?;
            tx.access_list = access_list.to_vec();
        }
        if signed {
            tx.y = BigInt::from_bytes_be(Sign::Plus, field_int(next()?)?);
            tx.r = field_sig(next()?)?;
            tx.s = field_sig(next()?)?;
            // Derive chain id from v (EIP-155) so SignBytes reconstructs
            // the same preimage during sender recovery.
            if tx_type == EvmTxType::Legacy
                && let Some(v) = tx.y.to_u64()
                && v >= 35
            {
                tx.chain_id = (v - 35) / 2;
            }
        }
        Ok(tx)
    }

    /// Parses from bytes (alias for `parse_transaction`).
    pub fn from_bytes(buf: &[u8]) -> Result<EvmTx, Error> {
        Self::parse_transaction(buf)
    }

    /// Returns `(r, s, recovery_id)` for the signed transaction, normalizing the
    /// legacy `v` and checking it against `chain_id`: an EIP-155 `v` must be
    /// for this chain id, and a pre-EIP-155 `v` (27/28) needs chain id 0.
    /// Otherwise the signed bytes would be those of another transaction.
    fn signature_parts(&self) -> Result<([u8; 32], [u8; 32], u8), Error> {
        if !self.signed {
            return Err(Error::NotSigned);
        }
        let r = bigint_to_32(&self.r)?;
        let s = bigint_to_32(&self.s)?;
        let mut v = self.y.to_u64().ok_or(Error::InvalidV)?;
        if self.tx_type == EvmTxType::Legacy {
            if v >= 35 {
                // EIP-155: v = chainId*2 + 35 + recid.
                if (v - 35) / 2 != self.chain_id {
                    return Err(Error::InvalidV);
                }
                v = (v - 35) % 2;
            } else {
                // Pre-EIP-155 legacy: v is the standard 27/28 (map to recovery
                // 0/1), or already a raw 0/1 recovery id. Anything else is invalid
                // and would otherwise be rejected below or panic in recovery.
                v = match v {
                    27 | 28 if self.chain_id == 0 => v - 27,
                    0 | 1 => v,
                    _ => return Err(Error::InvalidV),
                };
            }
        }
        if v > 3 {
            return Err(Error::InvalidV);
        }
        Ok((r, s, v as u8))
    }

    /// Recovers the sender's public key.
    pub fn sender_pubkey(&self) -> Result<crate::crypto::secp256k1::SecpPublicKey, Error> {
        let (r, s, recid) = self.signature_parts()?;
        let buf = self.sign_bytes()?;
        let digest = keccak256_once(&buf);
        recover_public_key(&r, &s, recid, &digest).map_err(|_| Error::Recovery)
    }

    /// Recovers the EIP-55 checksummed sender address.
    pub fn sender_address(&self) -> Result<String, Error> {
        let pubkey = self.sender_pubkey()?;
        let addr = crate::hash::ether_hash(&pubkey.serialize_uncompressed());
        Ok(eip55(&addr))
    }

    /// Signs the transaction with the given key.
    ///
    /// Fails with [`Error::Overflow`] for a legacy transaction whose chain id
    /// is so large that the EIP-155 `v` (`chain_id * 2 + 35 + recid`) does not
    /// fit a `u64`.
    pub fn sign(&mut self, key: &SecpPrivateKey) -> Result<(), Error> {
        let eip155_base = if self.tx_type == EvmTxType::Legacy && self.chain_id != 0 {
            let max_v = self
                .chain_id
                .checked_mul(2)
                .and_then(|v| v.checked_add(36))
                .ok_or(Error::Overflow)?;
            Some(max_v - 1)
        } else {
            None
        };
        let buf = self.sign_bytes()?;
        let digest = keccak256_once(&buf);
        let (r, s, recid) = key.sign_recoverable(&digest);
        self.signed = true;
        self.r = BigInt::from_bytes_be(Sign::Plus, &r);
        self.s = BigInt::from_bytes_be(Sign::Plus, &s);
        let v = recid as u64;
        self.y = match (self.tx_type, eip155_base) {
            (EvmTxType::Legacy, Some(base)) => BigInt::from(base + v),
            (EvmTxType::Legacy, None) => BigInt::from(27 + v),
            _ => BigInt::from(v),
        };
        Ok(())
    }

    /// Returns the keccak-256 hash of the signed transaction's encoding.
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        let data = self.to_bytes()?;
        Ok(keccak256_once(&data))
    }

    /// Sets the transaction's calldata to the ABI-encoded method call.
    pub fn call(&mut self, method: &str, params: &[AbiValue]) -> Result<(), Error> {
        self.data = evm_call(method, params)?;
        Ok(())
    }
}

fn bigint_to_32(v: &BigInt) -> Result<[u8; 32], Error> {
    let (sign, bytes) = v.to_bytes_be();
    if sign == Sign::Minus {
        return Err(Error::InvalidSignature);
    }
    if bytes.len() > 32 {
        return Err(Error::InvalidSignature);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecpPrivateKey {
        let mut s = [0u8; 32];
        s.copy_from_slice(
            &hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap(),
        );
        SecpPrivateKey::from_bytes(&s).unwrap()
    }

    #[test]
    fn legacy_parse_sender_hash() {
        let bin = hex::decode("f86b1e8507ea8ed4008252089443badf0e63ac147ace611dc1113afe0ea3f8691787d529ae9e8600008026a0cacce90eb140f837a139e5d8acbe73527663aea163d4e4c6e8218681d1d37b0fa07fdb860517234804b71bbc518ecb4dc4bb96c1944ab28d502fc429baac939b3c").unwrap();
        let tx = EvmTx::parse_transaction(&bin).unwrap();
        assert_eq!(
            tx.sender_address().unwrap(),
            "0xebE790E554f30924801B48197DCb6f71de2760BC"
        );
        assert_eq!(
            hex::encode(tx.hash().unwrap()),
            "bac4cb10f95b37dab2c8a78e880d39661cc53f87386ded2fb721ac2304113ea3"
        );
    }

    #[test]
    fn eip1559_parse_sender_hash() {
        let bin = hex::decode("02f87101830bdfbb80850243e1963982798e94e866fecdb429c72c30868d3582192a878298698487d3c0ba13571e2080c080a08032999a5ae9477f5f52134c9dc1690d1e25d0bb78ef0f22b949afd0df73a9e4a07106563a788499eb370a48e7c86c08e357866fcc12867a8c530b5ca22175e784").unwrap();
        let tx = EvmTx::parse_transaction(&bin).unwrap();
        assert_eq!(
            tx.sender_address().unwrap(),
            "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"
        );
        assert_eq!(
            hex::encode(tx.hash().unwrap()),
            "c0c7f78587ebe1f3b377f9c572fe59f4007c88677a1bbd78349f7356304e06b4"
        );
    }

    #[test]
    fn json_roundtrip() {
        let mut tx = EvmTx {
            chain_id: 1,
            nonce: 42,
            gas_fee_cap: BigInt::from(30_000_000_000u64),
            gas: 21000,
            to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
            value: BigInt::from(10u64).pow(18),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        let j = serde_json::to_string(&tx).unwrap();
        assert!(j.contains("\"from\":\"0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7\""));
        let parsed: EvmTx = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed.nonce, 42);
        assert_eq!(parsed.value, BigInt::from(10u64).pow(18));
    }

    #[test]
    fn sign_and_recover_sender() {
        let mut tx = EvmTx {
            chain_id: 1,
            nonce: 42,
            gas_fee_cap: BigInt::from(30_000_000_000u64),
            gas: 21000,
            to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
            value: BigInt::from(10u64).pow(18),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        assert_eq!(
            tx.sender_address().unwrap(),
            "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7"
        );
    }

    #[test]
    fn pre_eip155_sign_and_recover() {
        // chain_id == 0 produces a pre-EIP-155 legacy signature (v = 27/28).
        // Recovery must not panic and must return the signer.
        let mut tx = EvmTx {
            chain_id: 0,
            nonce: 7,
            gas_fee_cap: BigInt::from(20_000_000_000u64),
            gas: 21000,
            to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
            value: BigInt::from(1u64),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        // v must be the legacy 27/28 form
        let v = tx.y.to_u64().unwrap();
        assert!(v == 27 || v == 28, "expected legacy v 27/28, got {v}");
        assert_eq!(
            tx.sender_address().unwrap(),
            "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7"
        );
    }

    fn to_raw(tx: &EvmTx) -> (crate::evmraw::RawEvmTx<'_>, crate::evmraw::EvmSignature) {
        let u128_of = |v: &BigInt| u128::try_from(v).unwrap();
        let to = tx.to.strip_prefix("0x").unwrap();
        let raw = crate::evmraw::RawEvmTx {
            tx_type: tx.tx_type,
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            max_priority_fee_per_gas: u128_of(&tx.gas_tip_cap),
            max_fee_per_gas: u128_of(&tx.gas_fee_cap),
            gas: tx.gas,
            to: (!to.is_empty()).then(|| hex::decode(to).unwrap().try_into().unwrap()),
            value: bigint_to_32(&tx.value).unwrap(),
            data: &tx.data,
        };
        let sig = crate::evmraw::EvmSignature {
            v: tx.y.to_u64().unwrap(),
            r: bigint_to_32(&tx.r).unwrap(),
            s: bigint_to_32(&tx.s).unwrap(),
        };
        (raw, sig)
    }

    /// `RawEvmTx` must encode, hash and sign identically to `EvmTx`.
    #[test]
    fn raw_evm_tx_matches_evmtx() {
        let bin = hex::decode("02f87101830bdfbb80850243e1963982798e94e866fecdb429c72c30868d3582192a878298698487d3c0ba13571e2080c080a08032999a5ae9477f5f52134c9dc1690d1e25d0bb78ef0f22b949afd0df73a9e4a07106563a788499eb370a48e7c86c08e357866fcc12867a8c530b5ca22175e784").unwrap();
        let tx = EvmTx::parse_transaction(&bin).unwrap();
        let (raw, sig) = to_raw(&tx);
        let mut out = vec![0u8; raw.signed_len(&sig).unwrap()];
        raw.encode_signed_to_slice(&sig, &mut out).unwrap();
        assert_eq!(out, bin);
        assert_eq!(raw.tx_hash(&sig).unwrap(), tx.hash().unwrap());
        assert_eq!(
            eip55(&raw.recover_sender(&sig).unwrap()),
            "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"
        );

        for (tx_type, chain_id) in [
            (EvmTxType::Legacy, 0),
            (EvmTxType::Legacy, 1),
            (EvmTxType::Eip2930, 5),
            (EvmTxType::Eip1559, 1),
        ] {
            let mut tx = EvmTx {
                tx_type,
                chain_id,
                nonce: 7,
                gas_tip_cap: BigInt::from(1_000_000_000u64),
                gas_fee_cap: BigInt::from(20_000_000_000u64),
                gas: 21000,
                to: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7".into(),
                value: BigInt::from(10u64).pow(18),
                data: vec![1, 2, 3],
                ..Default::default()
            };
            let unsigned = tx.clone();
            tx.sign(&key()).unwrap();
            let (raw, _) = to_raw(&unsigned);
            assert_eq!(
                raw.signing_hash().unwrap(),
                keccak256_once(&unsigned.sign_bytes().unwrap())
            );
            let sig = raw.sign(&key()).unwrap();
            let mut out = vec![0u8; raw.signed_len(&sig).unwrap()];
            raw.encode_signed_to_slice(&sig, &mut out).unwrap();
            assert_eq!(out, tx.to_bytes().unwrap(), "{tx_type:?}/{chain_id}");
        }
    }

    #[test]
    fn parse_rejects_oversized_uint_field() {
        // A legacy tx whose nonce field is 9 bytes is valid RLP but must error
        // (not panic) when decoded as a u64.
        let nine = vec![0x88u8; 9]; // RLP byte string of 9 bytes -> 0x88 prefix
        let fields: Vec<crate::rlp::RlpItem> = vec![
            crate::rlp::RlpItem::Bytes(nine),             // nonce (9 bytes)
            crate::rlp::RlpItem::Bytes(vec![0x01]),       // gas price
            crate::rlp::RlpItem::Bytes(vec![0x52, 0x08]), // gas
            crate::rlp::RlpItem::Bytes(vec![0u8; 20]),    // to
            crate::rlp::RlpItem::Bytes(vec![]),           // value
            crate::rlp::RlpItem::Bytes(vec![]),           // data
        ];
        let encoded = crate::rlp::RlpItem::List(fields).encode();
        assert!(EvmTx::parse_transaction(&encoded).is_err());
    }

    const TO: &str = "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7";
    const SENDER: &str = "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7";

    fn bytes(b: &[u8]) -> RlpItem {
        RlpItem::Bytes(b.to_vec())
    }

    /// The unsigned fields of a well-formed legacy transaction.
    fn legacy_fields() -> Vec<RlpItem> {
        vec![
            bytes(&[0x01]),       // nonce
            bytes(&[0x02]),       // gas price
            bytes(&[0x52, 0x08]), // gas
            bytes(&[0x11; 20]),   // to
            bytes(&[0x03]),       // value
            bytes(&[]),           // data
        ]
    }

    fn parse_list(prefix: &[u8], fields: Vec<RlpItem>) -> Result<EvmTx, Error> {
        let mut buf = prefix.to_vec();
        buf.extend_from_slice(&RlpItem::List(fields).encode());
        EvmTx::parse_transaction(&buf)
    }

    /// Deeply nested lists must fail cleanly instead of overflowing the stack.
    #[test]
    fn parse_rejects_deep_nesting() {
        // 20,000 nested lists: each wraps the previous one's encoding
        let mut nested = vec![0xc0u8];
        for _ in 0..20_000 {
            let len = nested.len();
            let mut outer = if len <= 55 {
                vec![0xc0 + len as u8]
            } else {
                let be = (len as u64).to_be_bytes();
                let be = &be[be.iter().position(|&b| b != 0).unwrap()..];
                let mut h = vec![0xf7 + be.len() as u8];
                h.extend_from_slice(be);
                h
            };
            outer.extend_from_slice(&nested);
            nested = outer;
        }
        for prefix in [&[][..], &[0x01], &[0x02]] {
            let mut buf = prefix.to_vec();
            buf.extend_from_slice(&nested);
            assert_eq!(
                EvmTx::parse_transaction(&buf).map(drop),
                Err(Error::Rlp(rlp::Error::TooDeep))
            );
        }
    }

    /// A typed transaction with an access list, built field by field here
    /// (not through `rlp_fields`), must survive parse -> to_bytes unchanged.
    #[test]
    fn access_list_roundtrip() {
        let access_list = RlpItem::List(vec![
            RlpItem::List(vec![
                bytes(&[0xaa; 20]),
                RlpItem::List(vec![bytes(&[0x01; 32]), bytes(&[0x02; 32])]),
            ]),
            RlpItem::List(vec![bytes(&[0xbb; 20]), RlpItem::List(vec![])]),
        ]);
        for tx_type in [1u8, 2] {
            let mut fields = vec![
                RlpItem::uint(1),  // chain id
                RlpItem::uint(42), // nonce
            ];
            if tx_type == 2 {
                fields.push(RlpItem::uint(1_000_000_000)); // tip
            }
            fields.extend([
                RlpItem::uint(30_000_000_000),
                RlpItem::uint(60_000),
                bytes(&hex::decode(&TO[2..]).unwrap()),
                RlpItem::uint(1_000_000),
                bytes(&[1, 2, 3]),
                access_list.clone(),
            ]);
            let mut unsigned = vec![tx_type];
            unsigned.extend_from_slice(&rlp::encode_list(&fields));
            let (r, s, recid) = key().sign_recoverable(&keccak256_once(&unsigned));
            fields.push(RlpItem::uint(recid as u64));
            fields.push(RlpItem::bigint(&BigInt::from_bytes_be(Sign::Plus, &r)).unwrap());
            fields.push(RlpItem::bigint(&BigInt::from_bytes_be(Sign::Plus, &s)).unwrap());
            let mut signed = vec![tx_type];
            signed.extend_from_slice(&rlp::encode_list(&fields));

            let tx = EvmTx::parse_transaction(&signed).unwrap();
            assert_eq!(tx.access_list.len(), 2);
            assert_eq!(tx.to_bytes().unwrap(), signed);
            assert_eq!(tx.hash().unwrap(), keccak256_once(&signed));
            assert_eq!(tx.sign_bytes().unwrap(), unsigned);
            assert_eq!(tx.sender_address().unwrap(), SENDER);

            // the unsigned form round-trips too
            let tx = EvmTx::parse_transaction(&unsigned).unwrap();
            assert!(!tx.signed);
            assert_eq!(tx.to_bytes().unwrap(), unsigned);

            // and so does the JSON form, type and access list included
            let tx = EvmTx::parse_transaction(&signed).unwrap();
            let j = serde_json::to_string(&tx).unwrap();
            assert!(j.contains("\"accessList\""), "{j}");
            let back: EvmTx = serde_json::from_str(&j).unwrap();
            assert_eq!(back.tx_type, tx.tx_type);
            assert_eq!(back.to_bytes().unwrap(), signed);
        }
    }

    #[test]
    fn access_list_shape_is_checked() {
        let base = |access_list: RlpItem| {
            let mut f = vec![RlpItem::uint(1)];
            f.extend(legacy_fields());
            f.push(access_list);
            parse_list(&[0x01], f).map(drop)
        };
        assert_eq!(base(RlpItem::List(vec![])), Ok(()));
        // not a list
        assert_eq!(base(bytes(&[])), Err(Error::InvalidData));
        // an entry that is not [address, keys]
        assert_eq!(
            base(RlpItem::List(vec![bytes(&[0xaa; 20])])),
            Err(Error::InvalidData)
        );
        let entry = |addr: &[u8], key: &[u8]| {
            RlpItem::List(vec![RlpItem::List(vec![
                bytes(addr),
                RlpItem::List(vec![bytes(key)]),
            ])])
        };
        assert_eq!(base(entry(&[0xaa; 20], &[1; 32])), Ok(()));
        assert_eq!(base(entry(&[0xaa; 19], &[1; 32])), Err(Error::InvalidData));
        assert_eq!(base(entry(&[0xaa; 20], &[1; 31])), Err(Error::InvalidData));

        // when building: a malformed list, or any list on a legacy transaction
        let mut tx = EvmTx {
            tx_type: EvmTxType::Eip1559,
            to: TO.into(),
            access_list: vec![bytes(&[1])],
            ..Default::default()
        };
        assert_eq!(tx.sign_bytes(), Err(Error::InvalidData));
        assert_eq!(tx.sign(&key()), Err(Error::InvalidData));
        tx.access_list = vec![RlpItem::List(vec![
            bytes(&[0xaa; 20]),
            RlpItem::List(vec![]),
        ])];
        tx.sign(&key()).unwrap();
        assert_eq!(tx.sender_address().unwrap(), SENDER);
        tx.tx_type = EvmTxType::Legacy;
        assert_eq!(tx.sign_bytes(), Err(Error::InvalidData));
    }

    #[test]
    fn parse_rejects_malformed_fields() {
        assert!(parse_list(&[], legacy_fields()).is_ok());
        let with = |i: usize, item: RlpItem| {
            let mut f = legacy_fields();
            f[i] = item;
            parse_list(&[], f).map(drop)
        };
        // a list where a scalar is expected
        for i in 0..6 {
            assert_eq!(with(i, RlpItem::List(vec![])), Err(Error::InvalidData));
        }
        // integers with a leading zero byte
        for i in [0, 1, 2, 4] {
            assert_eq!(with(i, bytes(&[0x00, 0x01])), Err(Error::NonCanonical));
            assert_eq!(with(i, bytes(&[0x00])), Err(Error::NonCanonical));
        }
        // integers wider than 256 bits
        assert_eq!(with(1, bytes(&[1; 33])), Err(Error::TooLarge));
        assert_eq!(with(4, bytes(&[1; 33])), Err(Error::TooLarge));
        // `to` is empty or 20 bytes
        assert_eq!(with(3, bytes(&[])), Ok(()));
        assert_eq!(with(3, bytes(&[0x11; 19])), Err(Error::InvalidAddress));
        assert_eq!(with(3, bytes(&[0x11; 21])), Err(Error::InvalidAddress));

        // signature fields
        let signed = |v: RlpItem, r: RlpItem, s: RlpItem| {
            let mut f = legacy_fields();
            f.extend([v, r, s]);
            parse_list(&[], f).map(drop)
        };
        let ok = || bytes(&[0x22; 32]);
        assert_eq!(signed(bytes(&[27]), ok(), ok()), Ok(()));
        assert_eq!(
            signed(bytes(&[27]), bytes(&[0x22; 33]), ok()),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            signed(bytes(&[27]), ok(), bytes(&[0x22; 33])),
            Err(Error::InvalidSignature)
        );
        let mut zero_led = [0x22u8; 32];
        zero_led[0] = 0;
        assert_eq!(
            signed(bytes(&[27]), bytes(&zero_led), ok()),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            signed(bytes(&[0, 27]), ok(), ok()),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            signed(RlpItem::List(vec![]), ok(), ok()),
            Err(Error::InvalidData)
        );
        // wrong field counts, and trailing data
        let mut f = legacy_fields();
        f.push(bytes(&[27]));
        assert_eq!(parse_list(&[], f).map(drop), Err(Error::InvalidFieldCount));
        let mut buf = RlpItem::List(legacy_fields()).encode();
        buf.push(0x80);
        assert_eq!(
            EvmTx::parse_transaction(&buf).map(drop),
            Err(Error::InvalidData)
        );
    }

    /// A recipient that is not exactly 20 bytes must never be padded into
    /// another address and signed.
    #[test]
    fn to_must_be_a_full_address() {
        let tx = |to: &str| EvmTx {
            chain_id: 1,
            gas: 21000,
            to: to.into(),
            ..Default::default()
        };
        for bad in [
            "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a", // 39 digits
            "0x2aeb8add8337360e088b7d9ce4e857b9be60f3",  // 19 bytes
            "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a700", // 21 bytes
            "0x2aeb8add8337360e088b7d9ce4e857b9be60f3ag", // not hex
            "2aeb8add8337360e088b7d9ce4e857b9be60f3a7",  // no prefix
            "0x0",
            "",
        ] {
            let mut t = tx(bad);
            assert_eq!(t.sign_bytes(), Err(Error::InvalidAddress), "{bad:?}");
            assert_eq!(t.sign(&key()), Err(Error::InvalidAddress), "{bad:?}");
            assert!(!t.signed);
            assert_eq!(t.to_bytes(), Err(Error::InvalidAddress), "{bad:?}");
            if !bad.is_empty() {
                let j = format!("{{\"to\":\"{bad}\"}}");
                assert!(serde_json::from_str::<EvmTx>(&j).is_err(), "{bad:?}");
            }
        }
        // a full address and contract creation are accepted
        let mut t = tx(TO);
        t.sign(&key()).unwrap();
        let parsed = EvmTx::parse_transaction(&t.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed.to, TO);
        let mut t = tx("0x");
        t.sign(&key()).unwrap();
        let parsed = EvmTx::parse_transaction(&t.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed.to, "0x");
        assert!(serde_json::from_str::<EvmTx>(&format!("{{\"to\":\"{TO}\"}}")).is_ok());
    }

    #[test]
    fn sign_rejects_chain_id_overflowing_v() {
        for chain_id in [u64::MAX, u64::MAX / 2, (u64::MAX - 36) / 2 + 1] {
            let mut tx = EvmTx {
                chain_id,
                to: TO.into(),
                ..Default::default()
            };
            assert_eq!(tx.sign(&key()), Err(Error::Overflow), "{chain_id}");
            assert!(!tx.signed);
            // a typed transaction carries the chain id itself
            tx.tx_type = EvmTxType::Eip1559;
            tx.sign(&key()).unwrap();
            assert_eq!(tx.sender_address().unwrap(), SENDER);
        }
        // the largest chain id whose v fits
        let mut tx = EvmTx {
            chain_id: (u64::MAX - 36) / 2,
            to: TO.into(),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        assert_eq!(tx.sender_address().unwrap(), SENDER);
        let parsed = EvmTx::parse_transaction(&tx.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed.chain_id, tx.chain_id);
        assert_eq!(parsed.sender_address().unwrap(), SENDER);
    }

    /// JSON with a signature is a signed transaction, of the type it names.
    #[test]
    fn json_keeps_signature_and_type() {
        for (tx_type, chain_id) in [
            (EvmTxType::Legacy, 0),
            (EvmTxType::Legacy, 1),
            (EvmTxType::Eip2930, 5),
            (EvmTxType::Eip1559, 1),
        ] {
            let mut tx = EvmTx {
                tx_type,
                chain_id,
                nonce: 7,
                gas_tip_cap: BigInt::from(1_000_000_000u64),
                gas_fee_cap: BigInt::from(20_000_000_000u64),
                gas: 21000,
                to: TO.into(),
                value: BigInt::from(10u64).pow(18),
                data: vec![1, 2, 3],
                ..Default::default()
            };
            // unsigned stays unsigned
            let j = serde_json::to_string(&tx).unwrap();
            let back: EvmTx = serde_json::from_str(&j).unwrap();
            assert!(!back.signed);
            assert_eq!(back.to_bytes().unwrap(), tx.to_bytes().unwrap());

            tx.sign(&key()).unwrap();
            let j = serde_json::to_string(&tx).unwrap();
            let back: EvmTx = serde_json::from_str(&j).unwrap();
            assert!(back.signed, "{tx_type:?}");
            assert_eq!(back.tx_type, tx_type);
            assert_eq!(back.to_bytes().unwrap(), tx.to_bytes().unwrap());
            assert_eq!(back.hash().unwrap(), tx.hash().unwrap());
            assert_eq!(back.sender_address().unwrap(), SENDER);
        }

        // without "type" the fee fields decide, as before
        let j = r#"{"gas":"0x5208","maxFeePerGas":"0x2","maxPriorityFeePerGas":"0x1","to":"0x"}"#;
        let tx: EvmTx = serde_json::from_str(j).unwrap();
        assert_eq!(tx.tx_type, EvmTxType::Eip1559);
        assert!(!tx.signed);
        let tx: EvmTx = serde_json::from_str(r#"{"gasPrice":"0x2"}"#).unwrap();
        assert_eq!(tx.tx_type, EvmTxType::Legacy);
        assert!(serde_json::from_str::<EvmTx>(r#"{"type":"0x3"}"#).is_err());

        // a legacy transaction's chain id comes from v when not given
        let mut tx = EvmTx {
            chain_id: 137,
            to: TO.into(),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        let j = serde_json::to_string(&tx).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("chainId");
        obj.remove("type");
        let back: EvmTx = serde_json::from_value(v).unwrap();
        assert_eq!(back.chain_id, 137);
        assert_eq!(back.sender_address().unwrap(), SENDER);
    }

    /// A legacy `v` must agree with the chain id the signed bytes are built
    /// from.
    #[test]
    fn legacy_v_must_match_chain_id() {
        let mut tx = EvmTx {
            chain_id: 1,
            to: TO.into(),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        assert_eq!(tx.sender_address().unwrap(), SENDER);
        tx.chain_id = 2;
        assert_eq!(tx.sender_address(), Err(Error::InvalidV));
        tx.chain_id = 0;
        assert_eq!(tx.sender_address(), Err(Error::InvalidV));

        // a pre-EIP-155 v needs chain id 0
        let mut tx = EvmTx {
            to: TO.into(),
            ..Default::default()
        };
        tx.sign(&key()).unwrap();
        assert_eq!(tx.sender_address().unwrap(), SENDER);
        tx.chain_id = 1;
        assert_eq!(tx.sender_address(), Err(Error::InvalidV));
    }
}

// --- JSON (serde) ---

fn hex0x_u64(v: u64) -> String {
    format!("0x{v:x}")
}
fn hex0x_big(v: &BigInt) -> String {
    format!("0x{v:x}")
}

fn parse_u64_auto(s: &str) -> Result<u64, core::num::ParseIntError> {
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16)
    } else {
        s.parse::<u64>()
    }
}
fn parse_big_auto(s: &str) -> Result<BigInt, num_bigint::ParseBigIntError> {
    if let Some(h) = s.strip_prefix("0x") {
        BigInt::from_str_radix(h, 16)
    } else {
        BigInt::from_str_radix(s, 10)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct EvmTxJson {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    from: String,
    #[serde(default)]
    gas: String,
    #[serde(rename = "gasPrice", default, skip_serializing_if = "String::is_empty")]
    gas_price: String,
    #[serde(
        rename = "maxPriorityFeePerGas",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    gas_tip_cap: String,
    #[serde(
        rename = "maxFeePerGas",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    gas_fee_cap: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    hash: String,
    #[serde(default)]
    input: String,
    #[serde(default)]
    nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    to: String,
    #[serde(default)]
    value: String,
    #[serde(rename = "chainId", default)]
    chain_id: String,
    #[serde(default)]
    v: String,
    #[serde(default)]
    r: String,
    #[serde(default)]
    s: String,
    /// The EIP-2718 type, e.g. `"0x2"`. Optional on input: without it the
    /// type is inferred from the fee fields.
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    tx_type: String,
    #[serde(
        rename = "accessList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    access_list: Option<Vec<AccessListEntryJson>>,
}

#[derive(Serialize, Deserialize)]
struct AccessListEntryJson {
    address: String,
    #[serde(rename = "storageKeys", default)]
    storage_keys: Vec<String>,
}

/// The JSON form of an access list; `None` when empty.
fn access_list_to_json(entries: &[RlpItem]) -> Result<Option<Vec<AccessListEntryJson>>, Error> {
    check_access_list(entries)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let hex0x = |item: &RlpItem| format!("0x{}", hex::encode(item.as_bytes().unwrap_or(&[])));
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some([address, RlpItem::List(keys)]) = entry.as_list() else {
            return Err(Error::InvalidData);
        };
        out.push(AccessListEntryJson {
            address: hex0x(address),
            storage_keys: keys.iter().map(hex0x).collect(),
        });
    }
    Ok(Some(out))
}

/// `"0x"` followed by exactly `2 * N` hex digits.
fn fixed_hex<const N: usize>(s: &str) -> Result<RlpItem, Error> {
    let mut out = [0u8; N];
    let body = s.strip_prefix("0x").ok_or(Error::InvalidData)?;
    hex::decode_to_slice(body, &mut out).map_err(|_| Error::InvalidData)?;
    Ok(RlpItem::Bytes(out.to_vec()))
}

fn access_list_from_json(entries: &[AccessListEntryJson]) -> Result<Vec<RlpItem>, Error> {
    entries
        .iter()
        .map(|e| {
            let keys = e
                .storage_keys
                .iter()
                .map(|k| fixed_hex::<32>(k))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RlpItem::List(vec![
                fixed_hex::<20>(&e.address)?,
                RlpItem::List(keys),
            ]))
        })
        .collect()
}

impl Serialize for EvmTx {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut obj = EvmTxJson {
            tx_type: hex0x_u64(u64::from(self.tx_type.type_value())),
            access_list: access_list_to_json(&self.access_list).map_err(S::Error::custom)?,
            gas: hex0x_u64(self.gas),
            input: format!("0x{}", hex::encode(&self.data)),
            nonce: hex0x_u64(self.nonce),
            to: self.to.clone(),
            value: hex0x_big(&self.value),
            chain_id: hex0x_u64(self.chain_id),
            ..Default::default()
        };
        if matches!(self.tx_type, EvmTxType::Legacy | EvmTxType::Eip2930) {
            obj.gas_price = hex0x_big(&self.gas_fee_cap);
        } else {
            obj.gas_fee_cap = hex0x_big(&self.gas_fee_cap);
            obj.gas_tip_cap = hex0x_big(&self.gas_tip_cap);
        }
        if self.signed {
            obj.from = self.sender_address().unwrap_or_default();
            obj.v = hex0x_big(&self.y);
            obj.r = hex0x_big(&self.r);
            obj.s = hex0x_big(&self.s);
        }
        obj.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EvmTx {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let o = EvmTxJson::deserialize(deserializer)?;
        let mut tx = EvmTx::default();
        if !o.gas.is_empty() {
            tx.gas = parse_u64_auto(&o.gas).map_err(D::Error::custom)?;
        }
        let typed = !o.tx_type.is_empty();
        tx.tx_type = if typed {
            match parse_u64_auto(&o.tx_type).map_err(D::Error::custom)? {
                0 => EvmTxType::Legacy,
                1 => EvmTxType::Eip2930,
                2 => EvmTxType::Eip1559,
                _ => return Err(D::Error::custom(crate::Error::UnsupportedTxType)),
            }
        } else if !o.gas_fee_cap.is_empty() && !o.gas_tip_cap.is_empty() {
            // no type given: fee cap and tip mean EIP-1559
            EvmTxType::Eip1559
        } else {
            EvmTxType::Legacy
        };
        if tx.tx_type == EvmTxType::Eip1559 {
            if !o.gas_fee_cap.is_empty() {
                tx.gas_fee_cap = parse_big_auto(&o.gas_fee_cap).map_err(D::Error::custom)?;
            }
            if !o.gas_tip_cap.is_empty() {
                tx.gas_tip_cap = parse_big_auto(&o.gas_tip_cap).map_err(D::Error::custom)?;
            }
        } else if !o.gas_price.is_empty() {
            tx.gas_fee_cap = parse_big_auto(&o.gas_price).map_err(D::Error::custom)?;
        } else if typed && !o.gas_fee_cap.is_empty() {
            tx.gas_fee_cap = parse_big_auto(&o.gas_fee_cap).map_err(D::Error::custom)?;
        }
        if let Some(access_list) = &o.access_list {
            tx.access_list = access_list_from_json(access_list).map_err(D::Error::custom)?;
        }
        if !o.input.is_empty() {
            let h = o
                .input
                .strip_prefix("0x")
                .ok_or_else(|| D::Error::custom("input must start with 0x"))?;
            tx.data = hex::decode(h).map_err(D::Error::custom)?;
        }
        if !o.nonce.is_empty() {
            tx.nonce = parse_u64_auto(&o.nonce).map_err(D::Error::custom)?;
        }
        if !o.to.is_empty() {
            // "0x" or a full 20-byte address, never a shorter one
            to_item(&o.to).map_err(D::Error::custom)?;
            tx.to = o.to;
        }
        if !o.value.is_empty() {
            tx.value = parse_big_auto(&o.value).map_err(D::Error::custom)?;
        }
        if !o.chain_id.is_empty() {
            tx.chain_id = parse_u64_auto(&o.chain_id).map_err(D::Error::custom)?;
        }
        if !o.v.is_empty() {
            tx.y = parse_big_auto(&o.v).map_err(D::Error::custom)?;
        }
        if !o.r.is_empty() {
            tx.r = parse_big_auto(&o.r).map_err(D::Error::custom)?;
        }
        if !o.s.is_empty() {
            tx.s = parse_big_auto(&o.s).map_err(D::Error::custom)?;
        }
        // A signature makes this a signed transaction: `hash` and `to_bytes`
        // must cover it.
        tx.signed = tx.r.sign() != Sign::NoSign && tx.s.sign() != Sign::NoSign;
        // A legacy transaction's chain id is in its EIP-155 v when the JSON
        // does not give it.
        if tx.signed
            && tx.tx_type == EvmTxType::Legacy
            && o.chain_id.is_empty()
            && let Some(v) = tx.y.to_u64()
            && v >= 35
        {
            tx.chain_id = (v - 35) / 2;
        }
        Ok(tx)
    }
}
