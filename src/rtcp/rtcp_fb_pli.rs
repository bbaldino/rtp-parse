use anyhow::{Context, Result};

use crate::{packet_buffer::PacketBuffer, validators::RequireEqual};

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

/// https://datatracker.ietf.org/doc/html/rfc4585#section-6.3.1
///
/// The PLI FB message is identified by PT=PSFB and FMT=1.
/// There MUST be exactly one PLI contained in the FCI field.
///
/// PLI does not require parameters.  Therefore, the length field MUST be
/// 2, and there MUST NOT be any Feedback Control Information.
#[derive(Debug)]
pub struct RtcpFbPliPacket {
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
}

impl RtcpFbPliPacket {
    pub const FMT: u8 = 1;
}

pub fn parse_rtcp_fb_pli<B: PacketBuffer>(
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    _buf: &mut B,
) -> Result<RtcpFbPliPacket> {
    header
        .length_field
        .require_equal(2)
        .context("rtcp fb pli length")?;
    Ok(RtcpFbPliPacket { header, fb_header })
}
