use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::error::RtpParseResult;

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

pub fn parse_rtcp_fb_header(buf: &mut dyn ReadableBuf) -> RtpParseResult<RtcpFbHeader> {
    try_parse_field("rtcp fb header", || {
        Ok(RtcpFbHeader {
            sender_ssrc: try_parse_field("sender ssrc", || buf.read_u32())?,
            media_source_ssrc: try_parse_field("media source ssrc", || buf.read_u32())?,
        })
    })
}
