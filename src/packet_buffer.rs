use bytebuffer::{
    bit_read::BitRead, byte_buffer_exts::ByteBufferExts, sized_buffer::SizedByteBuffer,
};
use byteorder::ReadBytesExt;

pub trait PacketBuffer: BitRead + ReadBytesExt + SizedByteBuffer + ByteBufferExts {}
impl<T> PacketBuffer for T where T: BitRead + ReadBytesExt + SizedByteBuffer + ByteBufferExts {}
