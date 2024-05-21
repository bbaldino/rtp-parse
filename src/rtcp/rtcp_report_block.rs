use anyhow::{Context, Result};
use bitcursor::bit_write::BitWrite;
use bitcursor::bit_write_exts::BitWriteExts;
use bitcursor::ux::*;
use bitcursor::{bit_read::BitRead, bit_read_exts::BitReadExts, byte_order::NetworkOrder};

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
    pub cumulative_lost: u24,
    pub extended_highest_seq_num: u32,
    pub interarrival_jitter: u32,
    pub last_sr_timestamp: u32,
    pub delay_since_last_sr: u32,
}

pub fn read_rtcp_report_block<R: BitRead>(buf: &mut R) -> Result<RtcpReportBlock> {
    Ok(RtcpReportBlock {
        ssrc: buf.read_u32::<NetworkOrder>().context("ssrc")?,
        fraction_lost: buf.read_u8().context("fraction_lost")?,
        cumulative_lost: buf.read_u24::<NetworkOrder>().context("fraction_lost")?,
        extended_highest_seq_num: buf.read_u32::<NetworkOrder>().context("cumulative_lost")?,
        interarrival_jitter: buf
            .read_u32::<NetworkOrder>()
            .context("interarrival_jitter")?,
        last_sr_timestamp: buf
            .read_u32::<NetworkOrder>()
            .context("last_sr_timestamp")?,
        delay_since_last_sr: buf
            .read_u32::<NetworkOrder>()
            .context("delay_since_last_sr")?,
    })
}

pub fn write_rtcp_report_block<W: BitWrite>(
    buf: &mut W,
    rtcp_report_block: &RtcpReportBlock,
) -> Result<()> {
    buf.write_u32::<NetworkOrder>(rtcp_report_block.ssrc)
        .context("ssrc")?;
    buf.write_u8(rtcp_report_block.fraction_lost)
        .context("fraction_lost")?;
    buf.write_u24::<NetworkOrder>(rtcp_report_block.cumulative_lost)
        .context("cumulative_lost")?;
    buf.write_u32::<NetworkOrder>(rtcp_report_block.extended_highest_seq_num)
        .context("extended_highest_seq_num")?;
    buf.write_u32::<NetworkOrder>(rtcp_report_block.interarrival_jitter)
        .context("interarrival_jitter")?;
    buf.write_u32::<NetworkOrder>(rtcp_report_block.last_sr_timestamp)
        .context("last_sr_timestamp")?;
    buf.write_u32::<NetworkOrder>(rtcp_report_block.delay_since_last_sr)
        .context("delay_since_last_sr")?;

    Ok(())
}
