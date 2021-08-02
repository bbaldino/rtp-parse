use bytebuffer::{
    bit_read::BitRead, byte_buffer_exts::ByteBufferExts, sized_buffer::SizedByteBuffer,
};
use byteorder::ReadBytesExt;

/// PacketBuffer is a helper trait to encompass all the necessary trait impls used for parsing
/// packets
pub trait PacketBuffer: BitRead + ReadBytesExt + SizedByteBuffer + ByteBufferExts {}
impl<T> PacketBuffer for T where T: BitRead + ReadBytesExt + SizedByteBuffer + ByteBufferExts {}
