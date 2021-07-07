use bitbuffer::readable_buf::ReadableBuf;

pub fn consume_padding(buf: &mut dyn ReadableBuf) {
    while buf.bytes_remaining() > 0 && buf.peek_u8().unwrap() == 0u8 {
        let _ = buf.read_u8();
    }
}
