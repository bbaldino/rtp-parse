use anyhow::{Context, Result};

use crate::{PacketBuffer, PacketBufferMut};

use super::{
    rtcp_fb_header::{write_rtcp_fb_header, RtcpFbHeader},
    rtcp_header::{write_rtcp_header, RtcpHeader},
};
use bitcursor::ux::u5;

///
/// https://tools.ietf.org/html/rfc4585#section-6.3.1
///
/// PLI does not require parameters.  Therefore, the length field MUST be
///  2, and there MUST NOT be any Feedback Control Information.
#[derive(Debug)]
pub struct RtcpFbPliPacket {
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
}

impl RtcpFbPliPacket {
    pub const FMT: u5 = u5::new(1);
}

pub fn read_rtcp_fb_pli<B: PacketBuffer>(
    _buf: &mut B,
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
) -> Result<RtcpFbPliPacket> {
    Ok(RtcpFbPliPacket { header, fb_header })
}

pub fn write_rtcp_fb_pli<B: PacketBufferMut>(buf: &mut B, fb_pli: &RtcpFbPliPacket) -> Result<()> {
    write_rtcp_header(buf, &fb_pli.header).context("rtcp header")?;
    write_rtcp_fb_header(buf, &fb_pli.fb_header).context("fb header")?;

    Ok(())
}
