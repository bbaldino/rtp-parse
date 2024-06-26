use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use anyhow::Result;
use bitcursor::ux::u7;
use bytes::BytesMut;

use super::{
    header_extensions::{read_header_extensions, SomeHeaderExtension},
    rtp_header::RtpHeader,
};

/// https://tools.ietf.org/html/rfc3550#section-5.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ...extensions (if present)...                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   payload                                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtpPacket {
    // Includes the fixed header and csrcs
    header: BytesMut,
    header_exts_buf: BytesMut,
    parsed_header_extensions: HashMap<u8, SomeHeaderExtension>,
    payload: BytesMut,
}

impl Display for RtpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.payload.as_ref())
    }
}

impl RtpPacket {
    pub fn payload_type(&self) -> u7 {
        RtpHeader::payload_type(&self.header)
    }

    pub fn get_extension_by_id(&self, id: u8) -> Option<&SomeHeaderExtension> {
        self.parsed_header_extensions.get(&id)
    }

    // TODO: this will give the "original" size of the packet, is that best? It's what we want for
    // incoming stats, but at other point we'll want the "actual" size of the packet (which may
    // have changed)
    pub fn size_bytes(&self) -> usize {
        self.header.len() + self.header_exts_buf.len() + self.payload.len()
    }
}

pub fn read_rtp_packet(buf: Vec<u8>) -> Result<RtpPacket> {
    // TODO: eventaully I think we'll have it where this was already a BytesMut type and we don't
    // have to copy it here
    let mut bytes = BytesMut::with_capacity(buf.len());
    bytes.extend_from_slice(&buf);
    let csrc_count = Into::<usize>::into(RtpHeader::csrc_count(&bytes));
    let header_length_bytes = 12 + 4 * csrc_count;
    let header = bytes.split_to(header_length_bytes);
    let header_extensions_length_bytes = ((((bytes[2] as u16) << 8) + bytes[3] as u16) + 1) * 4;

    let header_exts = bytes.split_to(header_extensions_length_bytes as usize);
    let parsed_header_extensions = read_header_extensions(header_exts.clone().into());

    Ok(RtpPacket {
        header,
        header_exts_buf: header_exts,
        parsed_header_extensions,
        payload: bytes,
    })
}

#[cfg(test)]
mod test {
    use super::read_rtp_packet;

    #[test]
    fn test_read_rtp_packet2() {
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0x90, 0xef, 0x16, 0xad, 0x65, 0xf3, 0xe1, 0x4e, 0x32, 0x0f, 0x22, 0x3a, 0xbe, 0xde,
            0x00, 0x01, 0x10, 0xff, 0x00, 0x00, 0x78, 0x0b, 0xe4, 0xc1, 0x36, 0xec, 0xc5, 0x8d,
            0x8c, 0x49, 0x46, 0x99, 0x04, 0xc5, 0xaa, 0xed, 0x92, 0xe7, 0x63, 0x4a, 0x3a, 0x18,
            0x98, 0xee, 0x62, 0xcb, 0x60, 0xff, 0x6c, 0x1b, 0x29, 0x00,
        ];

        let packet = read_rtp_packet(data).unwrap();
        println!("{:x?}", packet.header.as_ref());
        println!("{:x?}", packet.header_exts_buf.as_ref());
        println!("{:?}", packet.parsed_header_extensions);
        println!("{:x?}", packet.payload.as_ref());
        // dbg!(packet);
    }
}
