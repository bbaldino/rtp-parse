use std::fmt::Debug;

use anyhow::{anyhow, Result};
use parsely_rs::*;

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
#[derive(Clone, Debug, PartialEq, Eq, ParselyRead, ParselyWrite)]
#[parsely_write(sync_args("payload_length_bytes: u16", "report_count_value: u5"))]
pub struct RtcpHeader {
    #[parsely(assertion = "|v: &u2| *v == 2")]
    pub version: u2,
    pub has_padding: bool,
    #[parsely_write(sync_func = "ParselyResult::Ok(report_count_value)")]
    pub report_count: u5,
    pub packet_type: u8,
    #[parsely_write(sync_func = "ParselyResult::Ok(payload_length_bytes / 4)")]
    pub length_field: u16,
}

impl Default for RtcpHeader {
    fn default() -> Self {
        Self {
            version: u2::new(2),
            has_padding: Default::default(),
            report_count: Default::default(),
            packet_type: Default::default(),
            length_field: Default::default(),
        }
    }
}

// When decrypting RTCP, we haven't parsed the packet yet but need to grab the sender SSRC to
// retrieve the proper srtcp context.  The sender SSRC isn't modeled as part of the header, as
// different RTCP packets use it differently, so this helper function can be used to retrieve it
// from an unparsed RTCP packet
pub fn get_sender_ssrc(buf: &[u8]) -> u32 {
    u32::from_be_bytes(buf[4..8].try_into().unwrap())
}

impl RtcpHeader {
    pub const SIZE_BYTES: usize = 4;

    /// The length of this RTCP packet's payload (i.e. excluding the header) in bytes
    pub fn payload_length_bytes(&self) -> Result<u16> {
        self.length_field
            .checked_mul(4)
            .ok_or(anyhow!("Invalid length field"))
    }

    pub fn report_count(mut self, report_count: u5) -> Self {
        self.report_count = report_count;
        self
    }

    pub fn packet_type(mut self, packet_type: u8) -> Self {
        self.packet_type = packet_type;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings, clippy::bool_assert_comparison)]
mod tests {
    use super::*;

    #[test]
    fn test_read_rtcp_header() {
        let mut buf = Bits::from_static_bytes(&[0b10_0_00001, 202, 0, 42]);

        let header = RtcpHeader::read::<NetworkOrder>(&mut buf, ())
            .context("rtcp header")
            .unwrap();
        assert_eq!(header.version, u2::new(2));
        assert_eq!(header.has_padding, false);
        assert_eq!(header.report_count, u5::new(1));
        assert_eq!(header.packet_type, 202);
        assert_eq!(header.length_field, 42);
    }

    #[test]
    fn test_write_rtcp_header() {
        let header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(1),
            packet_type: 1,
            length_field: 2,
        };

        let mut buf_mut = BitsMut::new();

        header
            .write::<NetworkOrder>(&mut buf_mut, ())
            .expect("successful write");

        let mut buf = buf_mut.freeze();
        let read_header = RtcpHeader::read::<NetworkOrder>(&mut buf, ())
            .context("rtcp header")
            .unwrap();
        assert_eq!(header, read_header);
    }
}
