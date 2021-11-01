use anyhow::{Context, Result};
use byteorder::NetworkEndian;

use crate::{packet_buffer::PacketBuffer, validators::RequireEqual};

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|    SC   |  PT=SDES=202  |             length            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
///
/// length: 16 bits
///   The length of this RTCP packet in 32-bit words minus one,
///   including the header and any padding.  (The offset of one makes
///   zero a valid length and avoids a possible infinite loop in
///   scanning a compound RTCP packet, while counting 32-bit words
///   avoids a validity check for a multiple of 4.)
#[derive(Debug)]
pub struct RtcpHeader {
    pub version: u8,
    pub has_padding: bool,
    pub report_count: u8,
    pub packet_type: u8,
    pub length_field: u16,
}

impl RtcpHeader {
    pub const SIZE_BYTES: usize = 4;

    pub fn length_bytes(&self) -> usize {
        (self.length_field as usize + 1) * 4
    }
}

pub fn parse_rtcp_header<B: PacketBuffer>(buf: &mut B) -> Result<RtcpHeader> {
    Ok(RtcpHeader {
        version: buf.read_bits_as_u8(2).require_equal(2).context("version")?,
        has_padding: buf.read_bit_as_bool().context("has_padding")?,
        report_count: buf.read_bits_as_u8(5).context("report count")?,
        packet_type: buf.read_u8().context("packet type")?,
        length_field: buf.read_u16::<NetworkEndian>().context("length field")?,
    })
}

#[cfg(test)]
mod tests {
    use bytebuffer::byte_buffer_cursor::ByteBufferCursor;

    use crate::rtcp::rtcp_header::parse_rtcp_header;

    #[test]
    fn test_parse_rtcp_header() {
        let data: Vec<u8> = vec![0b10_1_00011, 89, 0x00, 0x05];

        let mut buf = ByteBufferCursor::new(data);

        let res = parse_rtcp_header(&mut buf);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.version, 2);
        assert_eq!(res.has_padding, true);
        assert_eq!(res.report_count, 3);
        assert_eq!(res.packet_type, 89);
        assert_eq!(res.length_field, 5);
        assert_eq!(res.length_bytes(), 24);
    }
}
