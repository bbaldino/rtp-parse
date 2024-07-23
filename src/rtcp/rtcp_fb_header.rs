use anyhow::{Context, Result};
use bit_cursor::{
    bit_read_exts::BitReadExts, bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
};

use crate::{PacketBuffer, PacketBufferMut};

/// https://datatracker.ietf.org/doc/html/rfc4585#section-6.1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of packet sender                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of media source                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtcpFbHeader {
    pub sender_ssrc: u32,
    pub media_source_ssrc: u32,
}

pub fn read_rtcp_fb_header<B: PacketBuffer>(buf: &mut B) -> Result<RtcpFbHeader> {
    let sender_ssrc = buf.read_u32::<NetworkOrder>().context("sender ssrc")?;
    let media_source_ssrc = buf.read_u32::<NetworkOrder>().context("media ssrc")?;

    Ok(RtcpFbHeader {
        sender_ssrc,
        media_source_ssrc,
    })
}

pub fn write_rtcp_fb_header<B: PacketBufferMut>(
    buf: &mut B,
    fb_header: &RtcpFbHeader,
) -> Result<()> {
    buf.write_u32::<NetworkOrder>(fb_header.sender_ssrc)
        .context("sender ssrc")?;
    buf.write_u32::<NetworkOrder>(fb_header.media_source_ssrc)
        .context("media_source_ssrc")?;

    Ok(())
}
