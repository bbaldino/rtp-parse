use anyhow::Context;
use parsely_rs::*;

use super::rtcp_header::RtcpHeader;

#[derive(Debug, PartialEq)]
pub struct RtcpByeReason(String);

impl RtcpByeReason {
    pub fn new(reason: &str) -> Self {
        Self(reason.to_owned())
    }

    pub fn length_bytes(&self) -> usize {
        self.0.len()
    }
}

impl PartialEq<String> for RtcpByeReason {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<&str> for RtcpByeReason {
    fn eq(&self, other: &&str) -> bool {
        &self.0 == other
    }
}

impl<B: BitBuf> ParselyRead<B> for RtcpByeReason {
    type Ctx = ();
    fn read<T: ByteOrder>(buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<Self> {
        let length_bytes = buf.get_u8().context("Reading reason length bytes")?;
        let mut data = vec![0; length_bytes as usize];
        buf.try_copy_to_slice_bytes(&mut data[..])
            .context("Reading reason data")?;
        let reason_str = String::from_utf8(data).context("Converting reason data to string")?;
        Ok(RtcpByeReason(reason_str))
    }
}

impl_stateless_sync!(RtcpByeReason);

impl<B: BitBufMut> ParselyWrite<B> for RtcpByeReason {
    type Ctx = ();
    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        buf.put_u8(self.length_bytes() as u8)
            .context("Writing reason string length")?;
        buf.try_put_slice_bytes(self.0.as_bytes())
            .context("Writing reason string")?;

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
#[parsely(alignment = 4)]
pub struct RtcpByePacket {
    #[parsely_read(assign_from = "rtcp_header")]
    #[parsely_write(sync_with("self.payload_length_bytes()", "self.ssrcs.len().try_into()"))]
    pub header: RtcpHeader,
    #[parsely_read(count = "header.report_count.into()")]
    pub ssrcs: Vec<u32>,
    #[parsely_read(when = "buf.remaining_bytes() > 0")]
    pub reason: Option<RtcpByeReason>,
}

impl Default for RtcpByePacket {
    fn default() -> Self {
        let header = RtcpHeader {
            packet_type: RtcpByePacket::PT,
            ..Default::default()
        };
        Self {
            header,
            ssrcs: Default::default(),
            reason: Default::default(),
        }
    }
}

impl RtcpByePacket {
    pub const PT: u8 = 203;

    pub fn payload_length_bytes(&self) -> u16 {
        // The payload's length in bytes is the number of ssrcs * 4 plus the reason length and the
        // leading byte to describe its length (if there is a reason)
        let mut payload_length_bytes =
            self.ssrcs.len() * 4 + self.reason.as_ref().map_or(0, |r| r.length_bytes() + 1);

        while payload_length_bytes % 4 != 0 {
            payload_length_bytes += 1
        }
        payload_length_bytes as u16
    }

    pub fn add_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrcs.push(ssrc);
        self
    }

    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(RtcpByeReason::new(reason));
        self
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
        let mut bits = Bits::from_owner_bytes(payload);
        let rtcp_bye = RtcpByePacket::read::<NetworkOrder>(&mut bits, (TEST_RTCP_HEADER,)).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert_eq!(rtcp_bye.reason.unwrap(), reason_str);
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
        let mut bits = Bits::from_owner_bytes(payload);
        let rtcp_bye = RtcpByePacket::read::<NetworkOrder>(&mut bits, (TEST_RTCP_HEADER,)).unwrap();
        assert!(rtcp_bye.ssrcs.contains(&1u32));
        assert!(rtcp_bye.ssrcs.contains(&2u32));
        assert!(rtcp_bye.reason.is_none());
    }

    #[test]
    fn test_read_missing_ssrc() {
        // Report count (source count) is 2 in header, but we'll just have 1 SSRC in the payload
        let mut bits = Bits::from_static_bytes(&[1, 2, 3, 4]);
        let result = RtcpByePacket::read::<NetworkOrder>(&mut bits, (TEST_RTCP_HEADER,));
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
        let mut bits = Bits::from_owner_bytes(payload);
        let result = RtcpByePacket::read::<NetworkOrder>(&mut bits, (TEST_RTCP_HEADER,));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_consume_padding() {
        let reason_str = "g";
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
        // 2 bytes of padding
        payload.extend([0x00, 0x00]);
        let mut buf = Bits::from_owner_bytes(payload);
        let _rtcp_bye = RtcpByePacket::read::<NetworkOrder>(&mut buf, (TEST_RTCP_HEADER,))
            .expect("Successful read");
        // Make sure the buffer was fully consumed
        assert_eq!(buf.remaining_bytes(), 0);
    }

    #[test]
    fn test_sync() {
        let mut rtcp_bye = RtcpByePacket::default().add_ssrc(42);
        rtcp_bye.sync(()).unwrap();
        assert_eq!(rtcp_bye.header.packet_type, RtcpByePacket::PT);
        assert_eq!(rtcp_bye.header.report_count, 1);
        assert_eq!(rtcp_bye.header.length_field, 1);

        let mut rtcp_bye = rtcp_bye.with_reason("goodbye");
        rtcp_bye.sync(()).unwrap();
        assert_eq!(rtcp_bye.header.length_field, 3);
    }

    #[test]
    fn test_write_success() {
        let mut rtcp_bye = RtcpByePacket {
            header: TEST_RTCP_HEADER,
            ssrcs: vec![42],
            reason: None,
        };
        rtcp_bye.sync(()).unwrap();
        let syncd_rtcp_header = rtcp_bye.header.clone();
        let mut buf_mut = BitsMut::new();

        rtcp_bye
            .write::<NetworkOrder>(&mut buf_mut, ())
            .expect("successful write");

        // Now read from the buffer and compare
        let mut buf = buf_mut.freeze();
        let read_rtcp_header =
            RtcpHeader::read::<NetworkOrder>(&mut buf, ()).expect("successul read");
        assert_eq!(read_rtcp_header, syncd_rtcp_header);
        let payload_length_bytes = read_rtcp_header.payload_length_bytes().unwrap();
        let mut bye_subbuf = (&mut buf).take_bytes(payload_length_bytes as usize);
        let read_rtcp_bye =
            RtcpByePacket::read::<NetworkOrder>(&mut bye_subbuf, (read_rtcp_header,))
                .expect("successful read");

        assert_eq!(rtcp_bye, read_rtcp_bye);
    }

    #[test]
    fn test_write_success_with_reason() {
        let mut rtcp_bye = RtcpByePacket {
            header: TEST_RTCP_HEADER,
            ssrcs: vec![42],
            reason: Some(RtcpByeReason::new("Goodbye")),
        };
        rtcp_bye.sync(()).unwrap();
        let syncd_rtcp_header = rtcp_bye.header.clone();
        let mut buf_mut = BitsMut::new();

        rtcp_bye
            .write::<NetworkOrder>(&mut buf_mut, ())
            .expect("successful write");

        // Now read from the buffer and compare
        let mut buf = buf_mut.freeze();
        let read_rtcp_header =
            RtcpHeader::read::<NetworkOrder>(&mut buf, ()).expect("successul read");
        assert_eq!(read_rtcp_header, syncd_rtcp_header);
        let payload_length_bytes = read_rtcp_header.payload_length_bytes().unwrap();
        let mut bye_subbuf = (&mut buf).take_bytes(payload_length_bytes as usize);
        let read_rtcp_bye =
            RtcpByePacket::read::<NetworkOrder>(&mut bye_subbuf, (read_rtcp_header,))
                .expect("successful read");

        assert_eq!(rtcp_bye, read_rtcp_bye);
    }

    #[test]
    fn test_write_success_with_padding() {
        let mut rtcp_bye = RtcpByePacket {
            header: TEST_RTCP_HEADER,
            ssrcs: vec![42],
            reason: Some(RtcpByeReason::new("G")),
        };
        rtcp_bye.sync(()).unwrap();
        let mut buf_mut = BitsMut::new();

        rtcp_bye
            .write::<NetworkOrder>(&mut buf_mut, ())
            .expect("successful write");

        // Make sure we landed on a word boundary
        assert!(buf_mut.len() % 32 == 0);
    }
}
