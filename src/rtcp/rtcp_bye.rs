use std::str::from_utf8;

use byteorder::NetworkEndian;

use crate::{
    error::RtpParseResult,
    packet_buffer::PacketBuffer,
    rtcp::rtcp_header::RtcpHeader,
    with_context::{with_context, Context},
};

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.6
///        0                   1                   2                   3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |V=2|P|    SC   |   PT=BYE=203  |             length            |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                           SSRC/CSRC                           |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       :                              ...                              :
///       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// (opt) |     length    |               reason for leaving            ...
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtcpByePacket {
    pub header: RtcpHeader,
    pub ssrcs: Vec<u32>,
    pub reason: Option<String>,
}

impl RtcpByePacket {
    pub const PT: u8 = 203;
}

pub fn parse_rtcp_bye<B: PacketBuffer>(
    header: RtcpHeader,
    buf: &mut B,
) -> RtpParseResult<RtcpByePacket> {
    with_context("rtcp bye", || {
        let ssrcs = (0..header.report_count)
            .map(|i| {
                buf.read_u32::<NetworkEndian>()
                    .with_context(format!("ssrc-{}", i).as_ref())
            })
            .collect::<RtpParseResult<Vec<u32>>>()?;

        if buf.bytes_remaining() == 0 {
            return Ok(RtcpByePacket {
                header,
                ssrcs,
                reason: None,
            });
        }

        let reason = with_context("reason", || {
            let reason_length = buf.read_u8().with_context("reason_length")? as usize;
            let mut reason_bytes = vec![0; reason_length];
            buf.read_exact(&mut reason_bytes)
                .with_context("reason bytes")?;
            match from_utf8(&reason_bytes) {
                Ok(s) => Ok(s.to_owned()),
                Err(e) => Err(e.into()),
            }
        })?;

        Ok(RtcpByePacket {
            header,
            ssrcs,
            reason: Some(reason),
        })
    })
}

#[cfg(test)]
mod tests {
    use bytebuffer::byte_buffer_cursor::ByteBufferCursor;

    use super::*;

    #[test]
    fn test_parse_success() {
        let rtcp_header = RtcpHeader {
            version: 2,
            has_padding: false,
            report_count: 2,
            packet_type: 203,
            length_field: 2,
        };
        let reason_str = "goodbye";
        let reason_bytes = reason_str.bytes();
        #[rustfmt::skip]
        let mut payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01, 
            // ssrc 2
            0x00, 0x00, 0x00, 0x02,
            // reason length
            reason_bytes.len() as u8
        ];
        // add reason bytes
        payload.extend(reason_bytes.collect::<Vec<u8>>());
        let mut buf = ByteBufferCursor::new(payload);
        let rtcp_bye = parse_rtcp_bye(rtcp_header, &mut buf).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert_eq!(rtcp_bye.reason.unwrap(), reason_str);
    }

    #[test]
    fn test_parse_success_no_reason() {
        let rtcp_header = RtcpHeader {
            version: 2,
            has_padding: false,
            report_count: 2,
            packet_type: 203,
            length_field: 2,
        };
        let payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01, // ssrc 2
            0x00, 0x00, 0x00, 0x02,
        ];
        let mut buf = ByteBufferCursor::new(payload);
        let rtcp_bye = parse_rtcp_bye(rtcp_header, &mut buf).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert!(rtcp_bye.reason.is_none());
    }

    #[test]
    fn test_missing_ssrc() {
        let rtcp_header = RtcpHeader {
            version: 2,
            has_padding: false,
            report_count: 2,
            packet_type: 203,
            length_field: 2,
        };

        // Report count (source count) is 2 in header, but we'll just have 1 SSRC in the payload
        let mut buf = ByteBufferCursor::new(vec![1, 2, 3, 4]);
        let result = parse_rtcp_bye(rtcp_header, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_bad_utf8_reason() {
        let rtcp_header = RtcpHeader {
            version: 2,
            has_padding: false,
            report_count: 2,
            packet_type: 203,
            length_field: 2,
        };
        #[rustfmt::skip]
        let payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01,
            // ssrc 2
            0x00, 0x00, 0x00, 0x02,
            // length 2, invalid utf 8
            0x02, 0xFF, 0xFF
        ];
        let mut buf = ByteBufferCursor::new(payload);
        let result = parse_rtcp_bye(rtcp_header, &mut buf);
        assert!(result.is_err());
    }
}
