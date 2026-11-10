//! The Fiat-Shamir transcript of `halo2_proofs`: BLAKE2b-512 personalized
//! with `Halo2-Transcript`, absorbing points and scalars under one-byte
//! prefixes and producing challenges by reducing 64 bytes of output
//! (`Blake2bRead` / `Blake2bWrite` with `Challenge255`).

use alloc::vec::Vec;

use purecrypto::hash::Blake2bMac;

use super::Error;
use crate::orchard::{Fp, vesta};

const PREFIX_CHALLENGE: u8 = 0;
const PREFIX_POINT: u8 = 1;
const PREFIX_SCALAR: u8 = 2;

/// The hash state shared by the prover and the verifier.
#[derive(Clone)]
pub(crate) struct Transcript {
    state: Blake2bMac,
}

impl Transcript {
    /// A new transcript.
    pub(crate) fn new() -> Self {
        Transcript {
            state: Blake2bMac::try_new_with_salt_personal(&[], 64, &[], b"Halo2-Transcript")
                .expect("valid BLAKE2b parameters"),
        }
    }

    /// Squeezes a challenge.
    pub(crate) fn squeeze_challenge(&mut self) -> Fp {
        self.state.update(&[PREFIX_CHALLENGE]);
        let mut out = [0u8; 64];
        self.state.clone().finalize_into(&mut out);
        Fp::from_uniform_bytes(&out)
    }

    /// Absorbs a point both sides know. The identity cannot be absorbed.
    pub(crate) fn common_point(&mut self, point: &vesta::Affine) -> Result<(), Error> {
        if bool::from(point.is_identity()) {
            return Err(Error::InvalidProof);
        }
        self.state.update(&[PREFIX_POINT]);
        self.state.update(&point.x().to_bytes());
        self.state.update(&point.y().to_bytes());
        Ok(())
    }

    /// Absorbs a scalar both sides know.
    pub(crate) fn common_scalar(&mut self, scalar: &Fp) {
        self.state.update(&[PREFIX_SCALAR]);
        self.state.update(&scalar.to_bytes());
    }
}

/// A transcript reading a proof.
pub(crate) struct TranscriptRead<'a> {
    pub(crate) transcript: Transcript,
    data: &'a [u8],
}

impl<'a> TranscriptRead<'a> {
    /// A transcript over the bytes of a proof.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        TranscriptRead {
            transcript: Transcript::new(),
            data,
        }
    }

    fn take(&mut self) -> Result<[u8; 32], Error> {
        let (head, rest) = self
            .data
            .split_first_chunk::<32>()
            .ok_or(Error::InvalidProof)?;
        self.data = rest;
        Ok(*head)
    }

    /// Reads a point of the proof and absorbs it.
    pub(crate) fn read_point(&mut self) -> Result<vesta::Affine, Error> {
        let bytes = self.take()?;
        let point = vesta::Affine::from_bytes(&bytes).ok_or(Error::InvalidProof)?;
        self.transcript.common_point(&point)?;
        Ok(point)
    }

    /// Reads a scalar of the proof and absorbs it.
    pub(crate) fn read_scalar(&mut self) -> Result<Fp, Error> {
        let bytes = self.take()?;
        let scalar = Fp::from_bytes(&bytes).ok_or(Error::InvalidProof)?;
        self.transcript.common_scalar(&scalar);
        Ok(scalar)
    }

    /// Reads `n` points.
    pub(crate) fn read_n_points(&mut self, n: usize) -> Result<Vec<vesta::Affine>, Error> {
        (0..n).map(|_| self.read_point()).collect()
    }

    /// Reads `n` scalars.
    pub(crate) fn read_n_scalars(&mut self, n: usize) -> Result<Vec<Fp>, Error> {
        (0..n).map(|_| self.read_scalar()).collect()
    }

    /// Squeezes a challenge.
    pub(crate) fn squeeze_challenge(&mut self) -> Fp {
        self.transcript.squeeze_challenge()
    }

    /// Whether the whole proof has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A transcript writing a proof.
pub(crate) struct TranscriptWrite {
    pub(crate) transcript: Transcript,
    out: Vec<u8>,
}

impl TranscriptWrite {
    /// A transcript writing a new proof.
    pub(crate) fn new() -> Self {
        TranscriptWrite {
            transcript: Transcript::new(),
            out: Vec::new(),
        }
    }

    /// Absorbs a point and appends it to the proof.
    pub(crate) fn write_point(&mut self, point: &vesta::Affine) -> Result<(), Error> {
        self.transcript.common_point(point)?;
        self.out.extend_from_slice(&point.to_bytes());
        Ok(())
    }

    /// Absorbs a scalar and appends it to the proof.
    pub(crate) fn write_scalar(&mut self, scalar: &Fp) {
        self.transcript.common_scalar(scalar);
        self.out.extend_from_slice(&scalar.to_bytes());
    }

    /// Squeezes a challenge.
    pub(crate) fn squeeze_challenge(&mut self) -> Fp {
        self.transcript.squeeze_challenge()
    }

    /// The proof.
    pub(crate) fn finalize(self) -> Vec<u8> {
        self.out
    }
}
