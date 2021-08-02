use byteorder::NetworkEndian;

use crate::{
    error::RtpParseResult,
    packet_buffer::PacketBuffer,
    with_context::{with_context, Context},
};

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

pub fn parse_rtcp_sender_info<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<RtcpSenderInfo> {
    with_context("sender info", || {
        Ok(RtcpSenderInfo {
            ntp_timestamp_msw: buf
                .read_u32::<NetworkEndian>()
                .with_context("ntp timestamp msw")?,
            ntp_timestamp_lsw: buf
                .read_u32::<NetworkEndian>()
                .with_context("ntp timestamp lsw")?,
            rtp_timestamp: buf
                .read_u32::<NetworkEndian>()
                .with_context("rtp timestamp")?,
            sender_packet_count: buf
                .read_u32::<NetworkEndian>()
                .with_context("sender packet counter")?,
            sender_octet_count: buf
                .read_u32::<NetworkEndian>()
                .with_context("sender octet count")?,
        })
    })
}
