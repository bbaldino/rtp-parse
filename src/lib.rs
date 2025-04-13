// use bit_cursor::{bit_cursor::BitCursor, bit_read::BitRead, bit_write::BitWrite};
use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec};
use bytes::Bytes;

use std::{
    fmt::{Debug, LowerHex},
    io::Seek,
    ops::Range,
};

use parsely::*;

pub mod rtcp;
// pub mod rtp;
pub mod util;

impl BitCursor<Bytes> {}

pub trait PacketBuffer: BitRead + Seek + Debug + LowerHex {
    /// Return the current cursor position of this buffer
    fn position(&self) -> u64;

    /// How many bytes remaining in this buffer.
    fn bytes_remaining(&self) -> usize;

    /// Get a sub buffer of this one, corresponding to the given range.  Note that advances in the
    /// given sub-buffer's position wll _not_ be reflected in the parent; you'll need to seek
    /// manually.
    ///
    /// # Example:
    /// TODO
    ///
    fn sub_buffer(&self, range: Range<usize>) -> impl PacketBuffer;

    fn consume_padding(&mut self);
}

impl PacketBuffer for BitCursor<BitVec<u8, Msb0>> {
    fn position(&self) -> u64 {
        BitCursor::position(self)
    }

    fn bytes_remaining(&self) -> usize {
        self.remaining_slice().len() / 8
    }

    fn sub_buffer(&self, range: Range<usize>) -> impl PacketBuffer {
        self.sub_cursor_new(range)
        // self.sub_cursor(range)
    }

    fn consume_padding(&mut self) {
        // TODO: ideally we'd re-use the slice impl here, but need sub_buffer/sub_cursor to support
        // RangeFrom
        while self.position() % 32 != 0 && self.bytes_remaining() > 0 {
            let byte = self.read_u8().expect("Read should succeed");
            if byte != 0x00 {
                self.seek(std::io::SeekFrom::Current(-1))
                    .expect("Seek backwards should succeed");
                return;
            }
        }
    }
}

impl PacketBuffer for BitCursor<&BitSlice<u8, Msb0>> {
    fn position(&self) -> u64 {
        BitCursor::position(self)
    }

    fn bytes_remaining(&self) -> usize {
        self.remaining_slice().len() / 8
    }

    fn sub_buffer(&self, range: Range<usize>) -> impl PacketBuffer {
        self.sub_cursor_new(range)
    }

    fn consume_padding(&mut self) {
        while self.position() % 32 != 0 && self.bytes_remaining() > 0 ]>).           if byte != 0x00 {
                self.seek(std::io::SeekFrom::Current(-1))
                    .expect("Seek backwards should succeed");
                return;
            }
        }
    }
}

pub trait PacketBufferMut: PacketBuffer + BitWrite {
    fn add_padding(&mut self);
}
impl<T> PacketBufferMut for T
where
    T: PacketBuffer + BitWrite,
{
    fn add_padding(&mut self) {
        while self.position() % 32 != 0 && self.bytes_remaining() > 0 {
            self.write_u8(0).expect("Write should succeed");
        }
    }
}
