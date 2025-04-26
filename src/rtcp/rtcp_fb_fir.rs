use parsely_rs::*;

use super::{
    rtcp_fb_header::RtcpFbHeader, rtcp_fb_packet::RtcpFbPsPacket, rtcp_header::RtcpHeader,
};

/// FIR FCI:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              SSRC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Seq nr.       |    Reserved                                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// From https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.1.2:
/// Within the common packet header for feedback messages (as defined in
/// section 6.1 of [RFC4585]), the "SSRC of packet sender" field
/// indicates the source of the request, and the "SSRC of media source"
/// is not used and SHALL be set to 0.  The SSRCs of the media senders to
/// which the FIR command applies are in the corresponding FCI entries.
/// A FIR message MAY contain requests to multiple media senders, using
/// one FCI entry per target media sender.
#[derive(Debug, ParselyRead, ParselyWrite, PartialEq)]
#[parsely_read(required_context("header: RtcpHeader", "fb_header: RtcpFbHeader"))]
pub struct RtcpFbFirPacket {
    #[parsely_read(assign_from = "header")]
    #[parsely(assertion = "|header: &RtcpHeader| header.report_count == RtcpFbFirPacket::FMT")]
    #[parsely_write(sync_with("self.payload_length_bytes()", "RtcpFbFirPacket::FMT"))]
    pub header: RtcpHeader,
    #[parsely_read(assign_from = "fb_header")]
    #[parsely(assertion = "|fb_header: &RtcpFbHeader| fb_header.media_source_ssrc == 0")]
    pub fb_header: RtcpFbHeader,
    #[parsely_read(while_pred = "buf.remaining_bytes() > 0")]
    pub fcis: Vec<RtcpFbFirFci>,
}

impl RtcpFbFirPacket {
    pub const FMT: u5 = u5::new(4);

    pub fn add_fci(mut self, fci: RtcpFbFirFci) -> Self {
        self.fcis.push(fci);
        self
    }

    pub fn payload_length_bytes(&self) -> u16 {
        // 8 bytes per FCI
        (self.fcis.len() * 8) as u16
    }
}

impl Default for RtcpFbFirPacket {
    fn default() -> Self {
        Self {
            header: RtcpHeader::default()
                .packet_type(RtcpFbPsPacket::PT)
                .report_count(RtcpFbFirPacket::FMT),
            fb_header: RtcpFbHeader::default().media_source_ssrc(0),
            fcis: Default::default(),
        }
    }
}

#[derive(Debug, ParselyRead, ParselyWrite, PartialEq)]
pub struct RtcpFbFirFci {
    ssrc: u32,
    seq_num: u8,
    _reserved: u24,
}

impl RtcpFbFirFci {
    pub const SIZE_BYTES: usize = 8;

    pub fn new(ssrc: u32, seq_num: u8) -> Self {
        Self {
            ssrc,
            seq_num,
            _reserved: u24::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rtcp::rtcp_fb_packet::RtcpFbPsPacket;

    use super::*;

    #[test]
    fn test_read_fci() {
        #[rustfmt::skip]
        let data = vec![
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // seq_num (1)
            0x01,
            // reserved
            0x00, 0x00, 0x00
        ];

        let mut buf = Bits::from_owner_bytes(data);

        let fci = RtcpFbFirFci::read::<_, NetworkOrder>(&mut buf, ()).expect("successful read");
        assert_eq!(fci.ssrc, 42);
        assert_eq!(fci.seq_num, 1);
    }

    #[test]
    fn test_write_fci() {
        let fci = RtcpFbFirFci::new(42, 1);
        let mut buf_mut = BitsMut::new();

        fci.write::<_, NetworkOrder>(&mut buf_mut, ())
            .expect("successful write");
        let mut buf = buf_mut.freeze();
        let read_fci =
            RtcpFbFirFci::read::<_, NetworkOrder>(&mut buf, ()).expect("successful read");
        assert_eq!(fci, read_fci);
    }

    #[test]
    fn test_read_rtcp_fb_fir_packet() {
        #[rustfmt::skip]
        let data = vec![
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // seq_num (1)
            0x01,
            // reserved
            0x00, 0x00, 0x00
        ];
        let mut buf = Bits::from_owner_bytes(data);
        let header = RtcpHeader {
            report_count: RtcpFbFirPacket::FMT,
            packet_type: RtcpFbPsPacket::PT,
            length_field: 4,
            ..Default::default()
        };
        let fb_header = RtcpFbHeader::new(42, 0);

        let fb_fir_packet = RtcpFbFirPacket::read::<_, NetworkOrder>(&mut buf, (header, fb_header))
            .expect("successful read");
        assert_eq!(buf.remaining_bytes(), 0);
        assert_eq!(fb_fir_packet.fcis.len(), 1);
        let fci = &fb_fir_packet.fcis[0];
        assert_eq!(fci.ssrc, 42);
        assert_eq!(fci.seq_num, 1);
    }

    #[test]
    fn test_read_rtcp_fb_fir_packet_multiple_fcis() {
        #[rustfmt::skip]
        let data = vec![
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // seq_num (1)
            0x01,
            // reserved
            0x00, 0x00, 0x00,
            // ssrc (43)
            0x00, 0x00, 0x00, 0x2b,
            // seq_num (2)
            0x02,
            // reserved
            0x00, 0x00, 0x00,
        ];
        let mut buf = Bits::from_owner_bytes(data);
        let header = RtcpHeader {
            report_count: RtcpFbFirPacket::FMT,
            packet_type: RtcpFbPsPacket::PT,
            length_field: 6,
            ..Default::default()
        };
        let fb_header = RtcpFbHeader::new(42, 0);

        let fb_fir_packet = RtcpFbFirPacket::read::<_, NetworkOrder>(&mut buf, (header, fb_header))
            .expect("successful read");
        assert_eq!(buf.remaining_bytes(), 0);
        assert_eq!(fb_fir_packet.fcis.len(), 2);
        let fci = &fb_fir_packet.fcis[0];
        assert_eq!(fci.ssrc, 42);
        assert_eq!(fci.seq_num, 1);
        let fci = &fb_fir_packet.fcis[1];
        assert_eq!(fci.ssrc, 43);
        assert_eq!(fci.seq_num, 2);
    }

    #[test]
    fn test_default() {
        let rtcp_fb_fir = RtcpFbFirPacket::default();
        assert_eq!(RtcpFbPsPacket::PT, rtcp_fb_fir.header.packet_type);
        assert_eq!(RtcpFbFirPacket::FMT, rtcp_fb_fir.header.report_count);
        assert_eq!(0, rtcp_fb_fir.fb_header.media_source_ssrc);
    }

    #[test]
    fn test_sync() {
        let mut rtcp_fb_fir = RtcpFbFirPacket::default()
            .add_fci(RtcpFbFirFci::new(42, 1))
            .add_fci(RtcpFbFirFci::new(43, 2));

        rtcp_fb_fir.sync(()).expect("successful sync");
        assert_eq!(RtcpFbPsPacket::PT, rtcp_fb_fir.header.packet_type);
        assert_eq!(RtcpFbFirPacket::FMT, rtcp_fb_fir.header.report_count);
        assert_eq!(0, rtcp_fb_fir.fb_header.media_source_ssrc);
    }

    #[test]
    fn test_write() {
        let mut rtcp_fb_fir = RtcpFbFirPacket::default()
            .add_fci(RtcpFbFirFci::new(42, 1))
            .add_fci(RtcpFbFirFci::new(43, 2));
        rtcp_fb_fir.sync(()).unwrap();
        let mut buf_mut = BitsMut::new();

        rtcp_fb_fir
            .write::<_, NetworkOrder>(&mut buf_mut, ())
            .unwrap();
        let mut buf = buf_mut.freeze();

        let rtcp_header = RtcpHeader::read::<_, NetworkOrder>(&mut buf, ()).unwrap();
        let rtcp_fb_header = RtcpFbHeader::read::<_, NetworkOrder>(&mut buf, ()).unwrap();
        let read_rtcp_fb_fir =
            RtcpFbFirPacket::read::<_, NetworkOrder>(&mut buf, (rtcp_header, rtcp_fb_header))
                .unwrap();
        assert_eq!(rtcp_fb_fir, read_rtcp_fb_fir);
    }
}
