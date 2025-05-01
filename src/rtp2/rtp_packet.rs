use std::fmt::{Debug, Display};

use parsely_rs::*;

use super::{header_extensions::SomeHeaderExtension, rtp_header::RtpHeader};

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
    header: RtpHeader,
    payload: Bits,
}

impl Display for RtpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.payload.as_ref())
    }
}

impl RtpPacket {
    pub fn payload_type(&self) -> u7 {
        self.header.payload_type
    }

    pub fn ssrc(&self) -> u32 {
        self.header.ssrc
    }

    pub fn get_extension_by_id(&self, id: u8) -> Option<&SomeHeaderExtension> {
        self.header.extensions.get_by_id(id)
    }

    // TODO: this will give the "original" size of the packet, is that best? It's what we want for
    // incoming stats, but at other point we'll want the "actual" size of the packet (which may
    // have changed)
    pub fn size_bytes(&self) -> usize {
        todo!()
        // self.header.len() + self.header_exts_buf.len() + self.payload.len()
    }
}

impl ParselyRead<Bits> for RtpPacket {
    type Ctx = ();

    fn read<T: parsely_rs::ByteOrder>(
        buf: &mut Bits,
        _ctx: Self::Ctx,
    ) -> parsely_rs::ParselyResult<Self> {
        let header = RtpHeader::read::<T>(buf, ()).context("Reading field 'header'")?;
        let payload = buf.clone();

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod test {
    use crate::rtp2::header_extensions::{HeaderExtensions, OneByteHeaderExtension};

    use super::*;

    #[test]
    fn test_read_rtp_packet() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0x90, 0xef, 0x16, 0xad, 
            0x65, 0xf3, 0xe1, 0x4e, 
            0x32, 0x0f, 0x22, 0x3a, 
            // Extensions
            0xbe, 0xde, 0x00, 0x01, 
            0x10, 0xff, 0x00, 0x00, 
            // Payload
            0x78, 0x0b, 0xe4, 0xc1, 0x36, 0xec, 0xc5, 0x8d,
            0x8c, 0x49, 0x46, 0x99, 0x04, 0xc5, 0xaa, 0xed, 
            0x92, 0xe7, 0x63, 0x4a, 0x3a, 0x18, 0x98, 0xee, 
            0x62, 0xcb, 0x60, 0xff, 0x6c, 0x1b, 0x29, 0x00,
        ]);

        let mut extensions = HeaderExtensions::default();
        extensions.add_extension(OneByteHeaderExtension::new(
            u4::new(1),
            Bits::from_static_bytes(&[0xFF]),
        ));
        let expected_header = RtpHeader {
            version: u2::new(2),
            has_padding: false,
            has_extensions: true,
            csrc_count: u4::new(0),
            marked: true,
            payload_type: u7::new(111),
            seq_num: 5805,
            timestamp: 1710481742,
            ssrc: 839852602,
            csrcs: vec![],
            extensions,
        };
        #[rustfmt::skip]
        let expected_payload = Bits::from_static_bytes(&[
            0x78, 0x0b, 0xe4, 0xc1, 0x36, 0xec, 0xc5, 0x8d,
            0x8c, 0x49, 0x46, 0x99, 0x04, 0xc5, 0xaa, 0xed, 
            0x92, 0xe7, 0x63, 0x4a, 0x3a, 0x18, 0x98, 0xee, 
            0x62, 0xcb, 0x60, 0xff, 0x6c, 0x1b, 0x29, 0x00,
        ]);

        let packet = RtpPacket::read::<NetworkOrder>(&mut bits, ()).unwrap();
        assert_eq!(packet.header, expected_header);
        assert_eq!(packet.payload, expected_payload);
    }
}
