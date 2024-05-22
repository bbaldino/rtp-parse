use std::str::from_utf8;

use anyhow::{Context, Result};
use bitcursor::{
    bit_read::BitRead, bit_read_exts::BitReadExts, bit_write::BitWrite,
    bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
};

use super::rtcp_header::{write_rtcp_header, RtcpHeader};

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

pub fn read_rtcp_bye<R: BitRead>(buf: &mut R, header: RtcpHeader) -> Result<RtcpByePacket> {
    let ssrcs = (0u32..header.report_count.into())
        .map(|i| {
            buf.read_u32::<NetworkOrder>()
                .with_context(|| format!("ssrc-{i}"))
        })
        .collect::<Result<Vec<u32>>>()?;

    // Try to read a BYE reason length
    let reason = {
        if let Ok(reason_length) = buf.read_u8() {
            let mut reason_bytes = vec![0; reason_length.into()];
            std::io::Read::read(buf, &mut reason_bytes).context("bye reason bytes")?;
            Some(
                from_utf8(&reason_bytes)
                    .context("convert bye reason from urf8")
                    .map(|str| str.to_owned())?,
            )
        } else {
            // Reason is optional, so if there was no data there just mark it as None.
            // TODO: technically I think we should only do this in the 'failed to fill buffer'
            // error case? Otherwise it could be a real error of some kind.
            None
        }
    };
    Ok(RtcpByePacket {
        header,
        ssrcs,
        reason,
    })
}

pub fn write_rtcp_bye<W: BitWrite>(buf: &mut W, packet: &RtcpByePacket) -> Result<()> {
    write_rtcp_header(buf, &packet.header).context("header")?;
    packet
        .ssrcs
        .iter()
        .enumerate()
        .map(|(i, ssrc)| {
            buf.write_u32::<NetworkOrder>(*ssrc)
                .with_context(|| format!("ssrc-{i}"))
        })
        .collect::<Result<Vec<()>>>()
        .context("ssrcs")?;

    if let Some(reason) = &packet.reason {
        let utf8_bytes = reason.as_bytes();
        buf.write_u8(utf8_bytes.len() as u8)
            .context("reason length")?;
        std::io::Write::write(buf, utf8_bytes).context("reason string")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcursor::{bit_cursor::BitCursor, ux::*};
    use bitvec::{order::Msb0, vec::BitVec};

    use super::*;

    #[test]
    fn test_parse_success() {
        let rtcp_header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(2),
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
        let mut buf = BitCursor::new(BitVec::<_, Msb0>::from_vec(payload));
        let rtcp_bye = read_rtcp_bye(&mut buf, rtcp_header).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert_eq!(rtcp_bye.reason.unwrap(), reason_str);
    }

    #[test]
    fn test_parse_success_no_reason() {
        let rtcp_header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(2),
            packet_type: 203,
            length_field: 2,
        };
        let payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01, // ssrc 2
            0x00, 0x00, 0x00, 0x02,
        ];
        let mut buf = BitCursor::new(BitVec::<u8, Msb0>::from_vec(payload));
        let rtcp_bye = read_rtcp_bye(&mut buf, rtcp_header).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert!(rtcp_bye.reason.is_none());
    }

    #[test]
    fn test_missing_ssrc() {
        let rtcp_header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(2),
            packet_type: 203,
            length_field: 2,
        };

        // Report count (source count) is 2 in header, but we'll just have 1 SSRC in the payload
        let mut buf = BitCursor::new(BitVec::<u8, Msb0>::from_vec(vec![1, 2, 3, 4]));
        let result = read_rtcp_bye(&mut buf, rtcp_header);
        assert!(result.is_err());
    }

    #[test]
    fn test_bad_utf8_reason() {
        let rtcp_header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(2),
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
        let mut buf = BitCursor::new(BitVec::<u8, Msb0>::from_vec(payload));
        let result = read_rtcp_bye(&mut buf, rtcp_header);
        assert!(result.is_err());
    }
}
