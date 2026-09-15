//! [`InlineBytes`]: a short byte string stored inline, for heap-free APIs that
//! return variable-length data (scripts, hashes, encodings) by value.

#[cfg(feature = "alloc")]
use crate::prelude::*;

/// Up to `N` bytes stored inline with their length. Dereferences to `[u8]`.
///
/// `N` must not exceed 255.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InlineBytes<const N: usize> {
    buf: [u8; N],
    len: u8,
}

impl<const N: usize> InlineBytes<N> {
    /// An empty value.
    pub const fn new() -> Self {
        InlineBytes {
            buf: [0u8; N],
            len: 0,
        }
    }

    /// Copies `data`, or returns `None` if it is longer than `N`.
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        let mut v = Self::new();
        v.extend_from_slice(data)?;
        Some(v)
    }

    /// The stored bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// The stored bytes, mutably.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len as usize]
    }

    /// Appends one byte, or returns `None` if full.
    pub fn push(&mut self, b: u8) -> Option<()> {
        self.extend_from_slice(&[b])
    }

    /// Appends `data`, or returns `None` (leaving the value unchanged) if it
    /// does not fit.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Option<()> {
        let start = self.len as usize;
        let end = start.checked_add(data.len()).filter(|&e| e <= N)?;
        self.buf[start..end].copy_from_slice(data);
        self.len = end as u8;
        Some(())
    }
}

impl<const N: usize> Default for InlineBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::ops::Deref for InlineBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<const N: usize> core::ops::DerefMut for InlineBytes<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl<const N: usize> AsRef<[u8]> for InlineBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<const N: usize> PartialEq<[u8]> for InlineBytes<N> {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl<const N: usize> core::fmt::Debug for InlineBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> From<InlineBytes<N>> for Vec<u8> {
    fn from(v: InlineBytes<N>) -> Vec<u8> {
        v.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_overflow() {
        let mut v = InlineBytes::<4>::new();
        assert!(v.is_empty());
        v.extend_from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(v.extend_from_slice(&[4, 5]), None);
        assert_eq!(&*v, &[1, 2, 3]);
        v.push(4).unwrap();
        assert_eq!(v.push(5), None);
        assert_eq!(InlineBytes::<4>::from_slice(&[1, 2, 3, 4]), Some(v));
        assert_eq!(InlineBytes::<4>::from_slice(&[0; 5]), None);
    }
}
