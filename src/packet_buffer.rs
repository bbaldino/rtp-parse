use bytebuffer::bit_read::BitRead;
use byteorder::ReadBytesExt;

pub trait PacketBuffer: BitRead + ReadBytesExt {}
impl<T> PacketBuffer for T where T: BitRead + ReadBytesExt {}
