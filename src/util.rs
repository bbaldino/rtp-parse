use crate::packet_buffer::PacketBuffer;

const PADDING_BYTE: u8 = 0;

pub fn consume_padding<B: PacketBuffer>(buf: &mut B) {
    while buf.bytes_remaining() > 0 && buf.peek_u8().unwrap() == PADDING_BYTE {
        let _ = buf.read_u8();
    }
}
