use crate::{PacketBuffer, PacketBufferMut};
use anyhow::{bail, Context};
use parsely::*;

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

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
#[parsely_read(
    buffer_type = "PacketBuffer",
    required_context("header: RtcpHeader", "fb_header: RtcpFbHeader")
)]
#[parsely_write(buffer_type = "PacketBufferMut")]
pub struct RtcpFbFirPacket {
    #[parsely_read(assign_from = "header")]
    pub header: RtcpHeader,
    #[parsely_read(assign_from = "fb_header")]
    #[parsely(assertion = "|fb_header: &RtcpFbHeader| fb_header.media_source_ssrc == 0")]
    pub fb_header: RtcpFbHeader,
    #[parsely_read(while_pred = "buf.bytes_remaining() > 0")]
    pub fcis: Vec<RtcpFbFirFci>,
}

impl RtcpFbFirPacket {
    pub const FMT: u5 = u5::new(4);
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
    use std::io::Seek;

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

        let mut cursor = BitCursor::from_vec(data);

        let fci = RtcpFbFirFci::read::<NetworkOrder>(&mut cursor, ()).expect("successful read");
        assert_eq!(fci.ssrc, 42);
        assert_eq!(fci.seq_num, 1);
    }

    #[test]
    fn test_write_fci() {
        let fci = RtcpFbFirFci::new(42, 1);
        let data = vec![0; 8];
        let mut cursor = BitCursor::from_vec(data);

        fci.write::<NetworkOrder>(&mut cursor, ())
            .expect("successful write");
        let _ = cursor.rewind();
        let read_fci =
            RtcpFbFirFci::read::<NetworkOrder>(&mut cursor, ()).expect("successful read");
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
        let header = RtcpHeader::default();
    }
}
