use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::error::RtpParseResult;

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.1
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// header |V=2|P|    RC   |   PT=SR=200   |             length            |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         SSRC of sender                        |
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
/// report |                 SSRC_1 (SSRC of first source)                 |
/// block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   1    | fraction lost |       cumulative number of packets lost       |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |           extended highest sequence number received           |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                      interarrival jitter                      |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         last SR (LSR)                         |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                   delay since last SR (DLSR)                  |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// report |                 SSRC_2 (SSRC of second source)                |
/// block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   2    :                               ...                             :
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
///        |                  profile-specific extensions                  |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtcpReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_lost: u32,
    pub extended_highest_seq_num: u32,
    pub interarrival_jitter: u32,
    pub last_sr_timestamp: u32,
    pub delay_since_last_sr: u32,
}

pub fn parse_rtcp_report_blocks(
    num_blocks: usize,
    buf: &mut dyn ReadableBuf,
) -> RtpParseResult<Vec<RtcpReportBlock>> {
    try_parse_field("report blocks", || {
        (0..num_blocks)
            .map(|i| {
                try_parse_field(format!("report block {}", i).as_ref(), || {
                    parse_rtcp_report_block(buf)
                })
            })
            .collect::<RtpParseResult<Vec<RtcpReportBlock>>>()
    })
}

pub fn parse_rtcp_report_block(buf: &mut dyn ReadableBuf) -> RtpParseResult<RtcpReportBlock> {
    Ok(RtcpReportBlock {
        ssrc: try_parse_field("ssrc", || buf.read_u32())?,
        fraction_lost: try_parse_field("fraction lost", || buf.read_u8())?,
        cumulative_lost: try_parse_field("cumulative lost", || buf.read_u24())?,
        extended_highest_seq_num: try_parse_field("extended highest seq num", || buf.read_u32())?,
        interarrival_jitter: try_parse_field("interarrival jitter", || buf.read_u32())?,
        last_sr_timestamp: try_parse_field("last sr timestamp", || buf.read_u32())?,
        delay_since_last_sr: try_parse_field("delay since last sr", || buf.read_u32())?,
    })
}
