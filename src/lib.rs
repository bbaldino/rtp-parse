use std::io::Seek;

use bitcursor::{bit_cursor::BitCursor, bit_read::BitRead, bit_write::BitWrite};
use bitvec::{field::BitField, order::BitOrder, slice::BitSlice, store::BitStore, vec::BitVec};

pub mod rtcp;
mod util;

pub trait PacketBuffer: BitRead + Seek {
    /// Return the current cursor position of this buffer
    fn position(&self) -> u64;

    /// How many bytes remaining in this buffer.
    fn bytes_remaining(&self) -> usize;
}

impl<T, O> PacketBuffer for BitCursor<BitVec<T, O>>
where
    T: BitStore,
    O: BitOrder,
    BitSlice<T, O>: BitField,
{
    fn position(&self) -> u64 {
        BitCursor::position(self)
    }

    fn bytes_remaining(&self) -> usize {
        self.remaining_slice().len() / 8
    }
}

pub trait PacketBufferMut: PacketBuffer + BitWrite {}
impl<T> PacketBufferMut for T where T: PacketBuffer + BitWrite {}
