use std::fmt::Debug;

use anyhow::{Context, Result};
use bitcursor::{
    bit_read_exts::BitReadExts, bit_write::BitWrite, bit_write_exts::BitWriteExts,
    byte_order::NetworkOrder,
};

use crate::{
    rtcp::{
        rtcp_header::write_rtcp_header,
        rtcp_report_block::{read_rtcp_report_block, write_rtcp_report_block},
        rtcp_sender_info::{read_rtcp_sender_info, write_rtcp_sender_info},
    },
    PacketBuffer,
};

use super::{
    rtcp_header::RtcpHeader, rtcp_report_block::RtcpReportBlock, rtcp_sender_info::RtcpSenderInfo,
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
pub struct RtcpSrPacket {
    pub header: RtcpHeader,
    pub sender_ssrc: u32,
    pub sender_info: RtcpSenderInfo,
    pub report_blocks: Vec<RtcpReportBlock>,
}

impl RtcpSrPacket {
    pub const PT: u8 = 200;
}

pub fn read_rtcp_sr<B: PacketBuffer>(buf: &mut B, header: RtcpHeader) -> Result<RtcpSrPacket> {
    let sender_ssrc = buf.read_u32::<NetworkOrder>().context("sender ssrc")?;
    let sender_info = read_rtcp_sender_info(buf).context("sender info")?;
    let report_blocks = (0u32..header.report_count.into())
        .map(|i| read_rtcp_report_block(buf).with_context(|| format!("report block {i}")))
        .collect::<Result<Vec<RtcpReportBlock>>>()
        .context("report blocks")?;

    Ok(RtcpSrPacket {
        header,
        sender_ssrc,
        sender_info,
        report_blocks,
    })
}

pub fn write_rtcp_sr<W: BitWrite>(buf: &mut W, packet: &RtcpSrPacket) -> Result<()> {
    write_rtcp_header(buf, &packet.header).context("header")?;
    buf.write_u32::<NetworkOrder>(packet.sender_ssrc)
        .context("sender ssrc")?;
    write_rtcp_sender_info(buf, &packet.sender_info).context("sender info")?;
    packet
        .report_blocks
        .iter()
        .enumerate()
        .map(|(i, rb)| {
            write_rtcp_report_block(buf, rb).with_context(|| format!("report block {i}"))
        })
        .collect::<Result<Vec<()>>>()
        .context("report blocks")?;
    todo!()
}
