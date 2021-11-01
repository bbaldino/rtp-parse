use anyhow::{Context, Result};
use byteorder::NetworkEndian;

use crate::packet_buffer::PacketBuffer;

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

pub fn parse_rtcp_fb_header<B: PacketBuffer>(buf: &mut B) -> Result<RtcpFbHeader> {
    Ok(RtcpFbHeader {
        sender_ssrc: buf.read_u32::<NetworkEndian>().context("sender ssrc")?,
        media_source_ssrc: buf
            .read_u32::<NetworkEndian>()
            .context("media source ssrc")?,
    })
}
