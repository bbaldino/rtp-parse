use byteorder::NetworkEndian;

use crate::{
    error::RtpParseResult,
    packet_buffer::PacketBuffer,
    with_context::{with_context, Context},
};

use super::{
    rtcp_header::RtcpHeader,
    rtcp_report_block::{parse_rtcp_report_blocks, RtcpReportBlock},
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

pub fn parse_rtcp_rr<B: PacketBuffer>(
    header: RtcpHeader,
    buf: &mut B,
) -> RtpParseResult<RtcpRrPacket> {
    with_context("rtcp rr", || {
        let num_report_blocks = header.report_count as usize;
        Ok(RtcpRrPacket {
            header,
            sender_ssrc: buf
                .read_u32::<NetworkEndian>()
                .with_context("sender ssrc")?,
            report_blocks: parse_rtcp_report_blocks(num_report_blocks, buf)?,
        })
    })
}
