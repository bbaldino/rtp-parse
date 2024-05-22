use anyhow::{Context, Result};
use bitcursor::{
    bit_read::BitRead, bit_read_exts::BitReadExts, bit_write::BitWrite,
    bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
};

use crate::rtcp::rtcp_report_block::read_rtcp_report_block;

use super::{
    rtcp_header::{write_rtcp_header, RtcpHeader},
    rtcp_report_block::{write_rtcp_report_block, RtcpReportBlock},
};

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.2
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// header |V=2|P|    RC   |   PT=RR=201   |             length            |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                     SSRC of packet sender                     |
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
///
#[derive(Debug)]
pub struct RtcpRrPacket {
    pub header: RtcpHeader,
    pub sender_ssrc: u32,
    pub report_blocks: Vec<RtcpReportBlock>,
}

impl RtcpRrPacket {
    pub const PT: u8 = 201;
}

pub fn read_rtcp_rr<R: BitRead>(buf: &mut R, header: RtcpHeader) -> Result<RtcpRrPacket> {
    let sender_ssrc = buf.read_u32::<NetworkOrder>().context("sender ssrc")?;
    let report_blocks = (0u32..header.report_count.into())
        .map(|i| read_rtcp_report_block(buf).with_context(|| format!("report block {i}")))
        .collect::<Result<Vec<RtcpReportBlock>>>()
        .context("report blocks")?;

    Ok(RtcpRrPacket {
        header,
        sender_ssrc,
        report_blocks,
    })
}

pub fn write_rtcp_rr<W: BitWrite>(buf: &mut W, packet: &RtcpRrPacket) -> Result<()> {
    write_rtcp_header(buf, &packet.header).context("header")?;
    buf.write_u32::<NetworkOrder>(packet.sender_ssrc)
        .context("sender ssrc")?;
    packet
        .report_blocks
        .iter()
        .enumerate()
        .map(|(i, rb)| {
            write_rtcp_report_block(buf, rb).with_context(|| format!("report block {i}"))
        })
        .collect::<Result<Vec<()>>>()
        .context("report blocks")?;
    Ok(())
}
