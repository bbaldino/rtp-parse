use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::error::RtpParseResult;

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.1
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// sender |              NTP timestamp, most significant word             |
/// info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |             NTP timestamp, least significant word             |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         RTP timestamp                         |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                     sender's packet count                     |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                      sender's octet count                     |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#[derive(Debug)]
pub struct RtcpSenderInfo {
    pub ntp_timestamp_msw: u32,
    pub ntp_timestamp_lsw: u32,
    pub rtp_timestamp: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
}

pub fn parse_rtcp_sender_info(buf: &mut dyn ReadableBuf) -> RtpParseResult<RtcpSenderInfo> {
    try_parse_field("sender info", || {
        Ok(RtcpSenderInfo {
            ntp_timestamp_msw: try_parse_field("ntp timestamp msw", || buf.read_u32())?,
            ntp_timestamp_lsw: try_parse_field("ntp timestamp lsw", || buf.read_u32())?,
            rtp_timestamp: try_parse_field("rtp timestamp", || buf.read_u32())?,
            sender_packet_count: try_parse_field("sender packet count", || buf.read_u32())?,
            sender_octet_count: try_parse_field("sender octet count", || buf.read_u32())?,
        })
    })
}
