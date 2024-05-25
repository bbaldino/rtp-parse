use std::fmt::LowerHex;

use anyhow::{anyhow, bail, Context, Result};

use crate::{
    rtcp::{
        rtcp_bye::read_rtcp_bye,
        rtcp_fb_nack::read_rtcp_fb_nack,
        rtcp_fb_tcc::{read_rtcp_fb_tcc, RtcpFbTccPacket},
        rtcp_header::read_rtcp_header,
    },
    PacketBuffer,
};

use super::{
    rtcp_bye::RtcpByePacket,
    rtcp_fb_fir::{read_rtcp_fb_fir, RtcpFbFirPacket},
    rtcp_fb_header::read_rtcp_fb_header,
    rtcp_fb_nack::RtcpFbNackPacket,
    rtcp_fb_packet::{RtcpFbPsPacket, RtcpFbTlPacket},
    rtcp_header::RtcpHeader,
    rtcp_rr::{read_rtcp_rr, RtcpRrPacket},
    rtcp_sdes::{read_rtcp_sdes, RtcpSdesPacket},
    rtcp_sr::{read_rtcp_sr, RtcpSrPacket},
};

#[derive(Debug)]
pub enum SomeRtcpPacket {
    CompoundRtcpPacket(Vec<SomeRtcpPacket>),
    RtcpByePacket(RtcpByePacket),
    RtcpSrPacket(RtcpSrPacket),
    RtcpRrPacket(RtcpRrPacket),
    RtcpSdesPacket(RtcpSdesPacket),
    RtcpFbNackPacket(RtcpFbNackPacket),
    RtcpFbFirPacket(RtcpFbFirPacket),
    RtcpFbTccPacket(RtcpFbTccPacket),
    UnknownRtcpPacket {
        header: RtcpHeader,
        payload: Vec<u8>,
    },
}

pub fn parse_rtcp_packet<B: PacketBuffer + LowerHex>(buf: &mut B) -> Result<SomeRtcpPacket> {
    let mut packets: Vec<SomeRtcpPacket> = Vec::new();

    let mut sub_packet_num = 1;
    // println!("parsing packet, buf: {buf:x}");
    while buf.bytes_remaining() >= RtcpHeader::SIZE_BYTES {
        let packet = parse_single_rtcp_packet(buf)
            .with_context(|| format!("sub packet {sub_packet_num}"))?;
        packets.push(packet);
        sub_packet_num += 1;
    }

    match packets.len() {
        0 => Err(anyhow!("No valid packets found")),
        1 => Ok(packets.remove(0)),
        _ => Ok(SomeRtcpPacket::CompoundRtcpPacket(packets)),
    }
}

pub fn parse_single_rtcp_packet<B: PacketBuffer>(buf: &mut B) -> Result<SomeRtcpPacket> {
    // println!("Parsing single rtcp packet: {buf:x}");
    let header = read_rtcp_header(buf).context("rtcp header")?;
    let payload_length = header
        .payload_length_bytes()
        .context("header length field")? as usize;
    let payload_length_bits = payload_length * 8;
    let mut payload_buffer = buf.sub_buffer(0..(payload_length * 8));

    let result = match header.packet_type {
        RtcpByePacket::PT => Ok(SomeRtcpPacket::RtcpByePacket(
            read_rtcp_bye(&mut payload_buffer, header).context("rtcp bye")?,
        )),
        RtcpSrPacket::PT => Ok(SomeRtcpPacket::RtcpSrPacket(
            read_rtcp_sr(&mut payload_buffer, header).context("rtcp sr")?,
        )),
        RtcpRrPacket::PT => Ok(SomeRtcpPacket::RtcpRrPacket(
            read_rtcp_rr(&mut payload_buffer, header).context("rtcp sr")?,
        )),
        RtcpSdesPacket::PT => Ok(SomeRtcpPacket::RtcpSdesPacket(
            read_rtcp_sdes(&mut payload_buffer, header).context("rtcp sdes")?,
        )),
        RtcpFbPsPacket::PT | RtcpFbTlPacket::PT => {
            let fb_header = read_rtcp_fb_header(&mut payload_buffer).context("fb header")?;
            match (header.packet_type, header.report_count) {
                (RtcpFbPsPacket::PT, RtcpFbFirPacket::FMT) => Ok(SomeRtcpPacket::RtcpFbFirPacket(
                    read_rtcp_fb_fir(&mut payload_buffer, header, fb_header)
                        .context("rtcp fb fir")?,
                )),
                (RtcpFbTlPacket::PT, RtcpFbTccPacket::FMT) => Ok(SomeRtcpPacket::RtcpFbTccPacket(
                    read_rtcp_fb_tcc(&mut payload_buffer, header, fb_header)
                        .context("rtcp fb tcc")?,
                )),
                (RtcpFbTlPacket::PT, RtcpFbNackPacket::FMT) => {
                    Ok(SomeRtcpPacket::RtcpFbNackPacket(
                        read_rtcp_fb_nack(&mut payload_buffer, header, fb_header)
                            .context("rtcp fb nack")?,
                    ))
                }
                (pt, fmt) => bail!("Unsuppsorted RTCP FB packet, pt {pt} fmt {fmt}"),
            }
        }
        pt => bail!("Unsupported packet type {pt}"),
    };
    drop(payload_buffer);
    if result.is_ok() {
        buf.seek(std::io::SeekFrom::Current(payload_length_bits as i64))?;
    }
    result
}
