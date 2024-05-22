use anyhow::{Context, Result};

use crate::{
    rtcp::{rtcp_bye::read_rtcp_bye, rtcp_header::read_rtcp_header},
    PacketBuffer,
};

use super::{
    rtcp_bye::RtcpByePacket,
    rtcp_rr::{read_rtcp_rr, RtcpRrPacket},
    rtcp_sdes::{read_rtcp_sdes, RtcpSdesPacket},
    rtcp_sr::{read_rtcp_sr, RtcpSrPacket},
};

pub enum SomeRtcpPacket {
    CompoundRtcpPacket(Vec<SomeRtcpPacket>),
    RtcpByePacket(RtcpByePacket),
    RtcpSrPacket(RtcpSrPacket),
    RtcpRrPacket(RtcpRrPacket),
    RtcpSdesPacket(RtcpSdesPacket),
}

pub fn parse_single_rtcp_packet<B: PacketBuffer>(buf: &mut B) -> Result<SomeRtcpPacket> {
    let header = read_rtcp_header(buf).context("rtcp header")?;

    match header.packet_type {
        RtcpByePacket::PT => Ok(SomeRtcpPacket::RtcpByePacket(
            read_rtcp_bye(buf, header).context("rtcp bye")?,
        )),
        RtcpSrPacket::PT => Ok(SomeRtcpPacket::RtcpSrPacket(
            read_rtcp_sr(buf, header).context("rtcp sr")?,
        )),
        RtcpRrPacket::PT => Ok(SomeRtcpPacket::RtcpRrPacket(
            read_rtcp_rr(buf, header).context("rtcp sr")?,
        )),
        RtcpSdesPacket::PT => Ok(SomeRtcpPacket::RtcpSdesPacket(
            read_rtcp_sdes(buf, header).context("rtcp sdes")?,
        )),
        pt => panic!("Unhandled packet type {pt}"),
    }
}
