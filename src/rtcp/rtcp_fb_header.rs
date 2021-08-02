use byteorder::NetworkEndian;

use crate::{
    error::RtpParseResult,
    packet_buffer::PacketBuffer,
    with_context::{with_context, Context},
};

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

pub fn parse_rtcp_fb_header<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<RtcpFbHeader> {
    with_context("rtcp fb header", || {
        Ok(RtcpFbHeader {
            sender_ssrc: buf
                .read_u32::<NetworkEndian>()
                .with_context("sender ssrc")?,
            media_source_ssrc: buf
                .read_u32::<NetworkEndian>()
                .with_context("media source ssrc")?,
        })
    })
}
