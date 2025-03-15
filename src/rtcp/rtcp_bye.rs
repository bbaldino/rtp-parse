use anyhow::Context;
use parsely::*;

use super::rtcp_header::RtcpHeader;

#[derive(Debug, PartialEq)]
pub struct RtcpByeReason(Option<String>);

impl RtcpByeReason {
    pub fn with_reason(reason: &str) -> Self {
        Self(Some(reason.to_owned()))
    }

    pub fn empty() -> Self {
        Self(None)
    }

    pub fn length_bytes(&self) -> usize {
        match self.0 {
            Some(ref s) => 1 + s.len(),
            None => 0,
        }
    }
}

impl RtcpByeReason {
    pub const EMPTY: RtcpByeReason = RtcpByeReason(None);
}

impl ParselyRead<()> for RtcpByeReason {
    fn read<T: ByteOrder, B: BitRead>(buf: &mut B, _ctx: ()) -> ParselyResult<Self> {
        // It's possible there isn't a reason and therefore isn't any data left to read.  In that
        // case we won't error: we'll just not have a reason.
        if let Ok(length_bytes) = buf.read_u8() {
            let mut data = vec![0; length_bytes as usize];
            buf.read_exact(&mut data).context("Reading reason data")?;
            let reason_str = String::from_utf8(data).context("Converting reason data to string")?;
            Ok(RtcpByeReason(Some(reason_str)))
        } else {
            Ok(RtcpByeReason(None))
        }
    }
}

impl ParselyWrite<()> for RtcpByeReason {
    fn write<T: ByteOrder, B: BitWrite>(&self, buf: &mut B, _ctx: ()) -> ParselyResult<()> {
        if let Some(ref reason) = self.0 {
            buf.write_u8(reason.len() as u8)
                .context("Writing reason string length")?;
            buf.write(reason.as_bytes())
                .context("Writing reason string")?;
        }

        Ok(())
    }
}

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
#[derive(Debug, PartialEq, ParselyRead, ParselyWrite)]
#[parsely_read(required_context("rtcp_header: RtcpHeader"))]
pub struct RtcpByePacket {
    #[parsely_read(assign_from = "rtcp_header")]
    #[parsely_write(sync_with("self.payload_length_bytes()", "self.ssrcs.len()"))]
    pub header: RtcpHeader,
    #[parsely_read(count = "header.report_count.into()")]
    pub ssrcs: Vec<u32>,
    pub reason: RtcpByeReason,
}

impl RtcpByePacket {
    pub const PT: u8 = 203;

    pub fn payload_length_bytes(&self) -> u16 {
        (self.ssrcs.len() * 4 + self.reason.length_bytes()) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RTCP_HEADER: RtcpHeader = RtcpHeader {
        version: u2::new(2),
        has_padding: false,
        report_count: u5::new(2),
        packet_type: 203,
        length_field: 2,
    };

    #[test]
    fn test_read_success() {
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
        let mut buf = BitCursor::from_vec(payload);
        let rtcp_bye =
            RtcpByePacket::read::<NetworkOrder, _>(&mut buf, (TEST_RTCP_HEADER,)).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert_eq!(rtcp_bye.reason.0.unwrap(), reason_str);
    }

    #[test]
    fn test_read_success_no_reason() {
        #[rustfmt::skip]
        let payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01, 
            // ssrc 2
            0x00, 0x00, 0x00, 0x02,
        ];
        let mut buf = BitCursor::from_vec(payload);
        let rtcp_bye =
            RtcpByePacket::read::<NetworkOrder, _>(&mut buf, (TEST_RTCP_HEADER,)).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert!(rtcp_bye.reason.0.is_none());
    }

    #[test]
    fn test_read_missing_ssrc() {
        // Report count (source count) is 2 in header, but we'll just have 1 SSRC in the payload
        let mut buf = BitCursor::from_vec(vec![1, 2, 3, 4]);
        let result = RtcpByePacket::read::<NetworkOrder, _>(&mut buf, (TEST_RTCP_HEADER,));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_bad_utf8_reason() {
        #[rustfmt::skip]
        let payload = vec![
            // ssrc 1
            0x00, 0x00, 0x00, 0x01,
            // ssrc 2
            0x00, 0x00, 0x00, 0x02,
            // length 2, invalid utf 8
            0x02, 0xFF, 0xFF
        ];
        let mut buf = BitCursor::from_vec(payload);
        let result = RtcpByePacket::read::<NetworkOrder, _>(&mut buf, (TEST_RTCP_HEADER,));
        assert!(result.is_err());
    }

    #[test]
    fn test_write_success() {
        let mut rtcp_bye = RtcpByePacket {
            header: TEST_RTCP_HEADER,
            ssrcs: vec![42],
            reason: RtcpByeReason::EMPTY,
        };
        rtcp_bye.sync(()).unwrap();
        let syncd_rtcp_header = rtcp_bye.header.clone();
        let buf = vec![0; 32];
        let mut cursor = BitCursor::from_vec(buf);

        rtcp_bye
            .write::<NetworkOrder, _>(&mut cursor, ())
            .expect("successful write");

        // Now read from the buffer and compare
        let data = cursor.into_inner();
        let mut read_cursor = BitCursor::new(data);
        let read_rtcp_header =
            RtcpHeader::read::<NetworkOrder, _>(&mut read_cursor, ()).expect("successul read");
        assert_eq!(read_rtcp_header, syncd_rtcp_header);
        let mut bye_subcursor = read_cursor
            .sub_cursor(0..((read_rtcp_header.payload_length_bytes().unwrap() * 8) as usize));
        let read_rtcp_bye =
            RtcpByePacket::read::<NetworkOrder, _>(&mut bye_subcursor, (read_rtcp_header,))
                .expect("successful read");

        assert_eq!(rtcp_bye, read_rtcp_bye);
    }

    #[test]
    fn test_write_success_with_reason() {
        let mut rtcp_bye = RtcpByePacket {
            header: TEST_RTCP_HEADER,
            ssrcs: vec![42],
            reason: RtcpByeReason::with_reason("Goodbye"),
        };
        rtcp_bye.sync(()).unwrap();
        let syncd_rtcp_header = rtcp_bye.header.clone();
        let buf = vec![0; 32];
        let mut cursor = BitCursor::from_vec(buf);

        rtcp_bye
            .write::<NetworkOrder, _>(&mut cursor, ())
            .expect("successful write");

        // Now read from the buffer and compare
        let data = cursor.into_inner();
        let mut read_cursor = BitCursor::new(data);
        let read_rtcp_header =
            RtcpHeader::read::<NetworkOrder, _>(&mut read_cursor, ()).expect("successul read");
        assert_eq!(read_rtcp_header, syncd_rtcp_header);
        let mut bye_subcursor = read_cursor
            .sub_cursor(0..((read_rtcp_header.payload_length_bytes().unwrap() * 8) as usize));
        let read_rtcp_bye =
            RtcpByePacket::read::<NetworkOrder, _>(&mut bye_subcursor, (read_rtcp_header,))
                .expect("successful read");

        assert_eq!(rtcp_bye, read_rtcp_bye);
    }
}
