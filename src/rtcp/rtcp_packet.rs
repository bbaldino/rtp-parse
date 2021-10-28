use crate::{
    error::{InvalidLengthValue, RtpParseResult, UnrecognizedPacketType},
    packet_buffer::PacketBuffer,
    rtcp::rtcp_bye::{parse_rtcp_bye, RtcpByePacket},
    rtcp::{
        rtcp_fb_fir::parse_rtcp_fb_fir,
        rtcp_fb_tcc::parse_rtcp_fb_tcc,
        rtcp_rr::{parse_rtcp_rr, RtcpRrPacket},
    },
    rtcp::{
        rtcp_fb_header::parse_rtcp_fb_header,
        rtcp_header::{parse_rtcp_header, RtcpHeader},
    },
    rtcp::{
        rtcp_fb_pli::parse_rtcp_fb_pli,
        rtcp_sdes::{parse_rtcp_sdes, RtcpSdesPacket},
    },
    with_context::{with_context, Context},
};

use super::{
    rtcp_fb_fir::RtcpFbFirPacket,
    rtcp_fb_nack::{parse_rtcp_fb_nack, RtcpFbNackPacket},
    rtcp_fb_packet::{RtcpFbPsPacket, RtcpFbTlPacket},
    rtcp_fb_pli::RtcpFbPliPacket,
    rtcp_fb_tcc::RtcpFbTccPacket,
    rtcp_sr::{parse_rtcp_sr, RtcpSrPacket},
};

#[derive(Debug)]
pub enum SomeRtcpPacket {
    CompoundRtcpPacket(Vec<SomeRtcpPacket>),
    RtcpSdesPacket(RtcpSdesPacket),
    RtcpByePacket(RtcpByePacket),
    RtcpRrPacket(RtcpRrPacket),
    RtcpSrPacket(RtcpSrPacket),
    RtcpFbNackPacket(RtcpFbNackPacket),
    RtcpFbFirPacket(RtcpFbFirPacket),
    RtcpFbPliPacket(RtcpFbPliPacket),
    RtcpFbTccPacket(RtcpFbTccPacket),
}

pub fn parse_rtcp_packet<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<SomeRtcpPacket> {
    let mut packets: Vec<SomeRtcpPacket> = Vec::new();

    let mut packet_num = 1;
    while buf.bytes_remaining() > RtcpHeader::SIZE_BYTES {
        let packet =
            parse_single_rtcp_packet(buf).with_context(format!("sub packet {}", packet_num))?;
        packets.push(packet);
        packet_num += 1;
    }

    match packets.len() {
        1 => Ok(packets.remove(0)),
        _ => Ok(SomeRtcpPacket::CompoundRtcpPacket(packets)),
    }
}

pub fn parse_single_rtcp_packet<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<SomeRtcpPacket> {
    with_context("rtcp_packet", || {
        let max_packet_size = buf.bytes_remaining();
        let header = parse_rtcp_header(buf)?;
        if header.length_bytes() > max_packet_size {
            return Err(Box::new(InvalidLengthValue {
                length_field_bytes: header.length_bytes(),
                buf_remaining_bytes: max_packet_size,
            }));
        }
        match header.packet_type {
            RtcpSdesPacket::PT => Ok(SomeRtcpPacket::RtcpSdesPacket(parse_rtcp_sdes(
                buf, header,
            )?)),
            RtcpByePacket::PT => Ok(SomeRtcpPacket::RtcpByePacket(parse_rtcp_bye(header, buf)?)),
            RtcpRrPacket::PT => Ok(SomeRtcpPacket::RtcpRrPacket(parse_rtcp_rr(header, buf)?)),
            RtcpSrPacket::PT => Ok(SomeRtcpPacket::RtcpSrPacket(parse_rtcp_sr(header, buf)?)),
            RtcpFbPsPacket::PT => {
                let rtcp_fb_header = parse_rtcp_fb_header(buf)?;
                match header.report_count {
                    RtcpFbPliPacket::FMT => Ok(SomeRtcpPacket::RtcpFbPliPacket(parse_rtcp_fb_pli(
                        header,
                        rtcp_fb_header,
                        buf,
                    )?)),
                    RtcpFbFirPacket::FMT => Ok(SomeRtcpPacket::RtcpFbFirPacket(parse_rtcp_fb_fir(
                        header,
                        rtcp_fb_header,
                        buf,
                    )?)),
                    _ => todo!(),
                }
            }
            RtcpFbTlPacket::PT => {
                let rtcp_fb_header = parse_rtcp_fb_header(buf)?;
                match header.report_count {
                    RtcpFbNackPacket::FMT => Ok(SomeRtcpPacket::RtcpFbNackPacket(
                        parse_rtcp_fb_nack(header, rtcp_fb_header, buf)?,
                    )),
                    RtcpFbTccPacket::FMT => Ok(SomeRtcpPacket::RtcpFbTccPacket(parse_rtcp_fb_tcc(
                        header,
                        rtcp_fb_header,
                        buf,
                    )?)),
                    _ => todo!(),
                }
            }
            pt @ _ => Err(Box::new(UnrecognizedPacketType(pt))),
        }
    })
}
