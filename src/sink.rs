//! Byte sinks for streaming encoders: the same serialization code can count
//! bytes, hash them, or write them into a caller buffer.

use purecrypto::hash::Digest;

pub(crate) trait Sink {
    fn put(&mut self, data: &[u8]);
}

/// Counts bytes.
#[derive(Default)]
pub(crate) struct Counter(pub usize);

impl Sink for Counter {
    fn put(&mut self, data: &[u8]) {
        self.0 += data.len();
    }
}

/// Feeds bytes into a hash.
pub(crate) struct HashSink<D: Digest>(pub D);

impl<D: Digest> Sink for HashSink<D> {
    fn put(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// Writes bytes into a caller buffer, remembering whether it overflowed.
pub(crate) struct SliceSink<'a> {
    out: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> SliceSink<'a> {
    pub(crate) fn new(out: &'a mut [u8]) -> Self {
        SliceSink {
            out,
            pos: 0,
            overflow: false,
        }
    }

    /// The number of bytes written, or `None` if the buffer was too small.
    pub(crate) fn finish(self) -> Option<usize> {
        (!self.overflow).then_some(self.pos)
    }
}

impl Sink for SliceSink<'_> {
    fn put(&mut self, data: &[u8]) {
        let end = self.pos + data.len();
        match self.out.get_mut(self.pos..end) {
            Some(dst) if !self.overflow => {
                dst.copy_from_slice(data);
                self.pos = end;
            }
            _ => self.overflow = true,
        }
    }
}
