use std::io::{Read, Seek, SeekFrom};

pub fn consume_padding<R: Read + Seek>(buf: &mut R) {
    let mut data_buf = [0u8; 1];
    loop {
        if buf.read_exact(&mut data_buf).is_ok() {
            if data_buf[0] != 0x00 {
                // We found the first non-padding byte, rewind back before it
                let _ = buf.seek(SeekFrom::Current(-1));
                break;
            }
        } else {
            break;
        }
    }
}
