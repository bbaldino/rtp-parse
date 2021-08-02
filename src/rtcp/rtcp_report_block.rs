use byteorder::NetworkEndian;

use crate::{
    error::RtpParseResult,
    packet_buffer::PacketBuffer,
    with_context::{with_context, Context},
};

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

pub fn parse_rtcp_report_blocks<B: PacketBuffer>(
    num_blocks: usize,
    buf: &mut B,
) -> RtpParseResult<Vec<RtcpReportBlock>> {
    with_context("report blocks", || {
        (0..num_blocks)
            .map(|i| {
                parse_rtcp_report_block(buf).with_context(format!("report block{}", i).as_ref())
            })
            .collect::<RtpParseResult<Vec<RtcpReportBlock>>>()
    })
}

pub fn parse_rtcp_report_block<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<RtcpReportBlock> {
    Ok(RtcpReportBlock {
        ssrc: buf.read_u32::<NetworkEndian>().with_context("ssrc")?,
        fraction_lost: buf.read_u8().with_context("fraction lost")?,
        cumulative_lost: buf
            .read_u24::<NetworkEndian>()
            .with_context("cumulative lost")?,
        extended_highest_seq_num: buf
            .read_u32::<NetworkEndian>()
            .with_context("extended highest seq num")?,
        interarrival_jitter: buf
            .read_u32::<NetworkEndian>()
            .with_context("interarrival jitter")?,
        last_sr_timestamp: buf
            .read_u32::<NetworkEndian>()
            .with_context("last sr timestamp")?,
        delay_since_last_sr: buf
            .read_u32::<NetworkEndian>()
            .with_context("delay since last SR")?,
    })
}
