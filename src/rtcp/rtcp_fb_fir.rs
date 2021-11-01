use anyhow::{Context, Result};
use byteorder::NetworkEndian;

use crate::packet_buffer::PacketBuffer;

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

/// RTCP FB header:
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of packet sender                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of media source                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
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
#[derive(Debug)]
pub struct RtcpFbFirPacket {
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    ssrc: u32,
    seq_num: u8,
}

impl RtcpFbFirPacket {
    pub const FMT: u8 = 4;
}

pub fn parse_rtcp_fb_fir<B: PacketBuffer>(
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    buf: &mut B,
) -> Result<RtcpFbFirPacket> {
    let ssrc = buf.read_u32::<NetworkEndian>().context("ssrc")?;
    let seq_num = buf.read_u8().context("seq num")?;
    let _reserved = buf.read_u24::<NetworkEndian>().context("reserved")?;
    Ok(RtcpFbFirPacket {
        header,
        fb_header,
        ssrc,
        seq_num,
    })
}
