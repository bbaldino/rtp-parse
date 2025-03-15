// use bit_cursor::{bit_cursor::BitCursor, bit_read::BitRead, bit_write::BitWrite};
// use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec};

pub mod rtcp;
// pub mod rtp;
pub mod util;

// pub trait PacketBuffer: BitRead + Seek + Debug + LowerHex {
//     /// Return the current cursor position of this buffer
//     fn position(&self) -> u64;
//
//     /// How many bytes remaining in this buffer.
//     fn bytes_remaining(&self) -> usize;
//
//     /// Get a sub buffer of this one, corresponding to the given range.  Note that advances in the
//     /// given sub-buffer's position wll _not_ be reflected in the parent; you'll need to seek
//     /// manually.
//     ///
//     /// # Example:
//     /// TODO
//     ///
//     fn sub_buffer(&self, range: Range<usize>) -> impl PacketBuffer;
// }

// impl PacketBuffer for BitCursor<BitVec<u8, Msb0>> {
//     fn position(&self) -> u64 {
//         BitCursor::position(self)
//     }
//
//     fn bytes_remaining(&self) -> usize {
//         self.remaining_slice().len() / 8
//     }
//
//     fn sub_buffer(&self, range: Range<usize>) -> impl PacketBuffer {
//         self.sub_cursor(range)
//     }
// }
//
// impl PacketBuffer for BitCursor<&BitSlice<u8, Msb0>> {
//     fn position(&self) -> u64 {
//         BitCursor::position(self)
//     }
//
//     fn bytes_remaining(&self) -> usize {
//         self.remaining_slice().len() / 8
//     }
//
//     fn sub_buffer(&self, range: Range<usize>) -> impl PacketBuffer {
//         self.sub_cursor(range)
//     }
// }
//
// pub trait PacketBufferMut: PacketBuffer + BitWrite {}
// impl<T> PacketBufferMut for T where T: PacketBuffer + BitWrite {}
