use bytebuffer::byte_buffer::ByteBuffer;
use byteorder::ReadBytesExt;

/// PacketBuffer is a helper trait to encompass all the necessary trait impls used for parsing
/// packets
pub trait PacketBuffer: ByteBuffer + ReadBytesExt {}
impl<T> PacketBuffer for T where T: ByteBuffer {}
