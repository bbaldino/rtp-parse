use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::{
    error::{InvalidLengthValue, RtpParseResult, UnrecognizedPacketType},
    rtcp::rtcp_bye::{parse_rtcp_bye, RtcpByePacket},
    rtcp::{
        rtcp_fb_fir::parse_rtcp_fb_fir,
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
};

use super::{
    rtcp_fb_fir::RtcpFbFirPacket,
    rtcp_fb_nack::{parse_rtcp_fb_nack, RtcpFbNackPacket},
    rtcp_fb_packet::{RtcpFbPsPacket, RtcpFbTlPacket},
    rtcp_fb_pli::RtcpFbPliPacket,
    rtcp_sr::{parse_rtcp_sr, RtcpSrPacket},
};

pub enum SomeRtcpPacket {
    CompoundRtcpPacket(Vec<SomeRtcpPacket>),
    RtcpSdesPacket(RtcpSdesPacket),
    RtcpByePacket(RtcpByePacket),
    RtcpRrPacket(RtcpRrPacket),
    RtcpSrPacket(RtcpSrPacket),
    RtcpFbNackPacket(RtcpFbNackPacket),
    RtcpFbFirPacket(RtcpFbFirPacket),
    RtcpFbPliPacket(RtcpFbPliPacket),
}

pub fn parse_rtcp_packet(buf: &mut dyn ReadableBuf) -> RtpParseResult<SomeRtcpPacket> {
    let mut packets: Vec<SomeRtcpPacket> = Vec::new();

    while buf.bytes_remaining() > RtcpHeader::SIZE_BYTES {
        match parse_single_rtcp_packet(buf) {
            Ok(packet) => packets.push(packet),
            Err(e) => return Err(e),
        };
    }
    match packets.len() {
        1 => todo!(),
        _ => Ok(SomeRtcpPacket::CompoundRtcpPacket(packets)),
    }
}

pub fn parse_single_rtcp_packet(buf: &mut dyn ReadableBuf) -> RtpParseResult<SomeRtcpPacket> {
    try_parse_field("rtcp_packet", || {
        let max_packet_size = buf.bytes_remaining();
        let mut header_buf = buf.sub_buffer(4)?;
        let header = parse_rtcp_header(&mut header_buf)?;
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
                    _ => todo!(),
                }
            }
            pt @ _ => Err(Box::new(UnrecognizedPacketType(pt))),
        }
    })
}
