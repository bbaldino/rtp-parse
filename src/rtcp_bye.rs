use std::str::from_utf8;

use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::{error::RtpParseResult, rtcp_header::RtcpHeader};

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

pub fn parse_rtcp_bye(
    header: RtcpHeader,
    buf: &mut dyn ReadableBuf,
) -> RtpParseResult<RtcpByePacket> {
    try_parse_field("rtcp bye", || {
        let ssrcs = try_parse_field("ssrcs", || {
            (0..header.report_count)
                .map(|i| try_parse_field(format!("ssrc-{}", i).as_ref(), || buf.read_u32()))
                .collect::<RtpParseResult<Vec<u32>>>()
        })?;

        if buf.bytes_remaining() == 0 {
            return Ok(RtcpByePacket {
                header,
                ssrcs,
                reason: None,
            });
        }

        let reason = try_parse_field("reason", || {
            let reason_length = try_parse_field("reason length", || buf.read_u8())? as usize;
            let reason_bytes = try_parse_field("reason bytes", || buf.read_bytes(reason_length))?;
            match from_utf8(reason_bytes) {
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
    use bitbuffer::bit_buffer::BitBuffer;

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
        #[cfg_attr(rustfmt, rustfmt_skip)]
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
        let mut buf = BitBuffer::new(payload);
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
        let mut buf = BitBuffer::new(payload);
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
        let mut buf = BitBuffer::new(vec![1, 2, 3, 4]);
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
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01,
            // ssrc 2
            0x00, 0x00, 0x00, 0x02,
            // length 2, invalid utf 8
            0x02, 0xFF, 0xFF
        ];
        let mut buf = BitBuffer::new(payload);
        let result = parse_rtcp_bye(rtcp_header, &mut buf);
        assert!(result.is_err());
    }
}
