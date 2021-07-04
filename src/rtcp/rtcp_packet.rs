use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::{
    error::{InvalidLengthValue, RtpParseResult, UnrecognizedPacketType},
    rtcp::rtcp_bye::{parse_rtcp_bye, RtcpByePacket},
    rtcp::rtcp_header::{parse_rtcp_header, RtcpHeader},
    rtcp::rtcp_sdes::{parse_rtcp_sdes, RtcpSdesPacket},
};

pub enum SomeRtcpPacket {
    CompoundRtcpPacket(Vec<SomeRtcpPacket>),
    RtcpSdesPacket(RtcpSdesPacket),
    RtcpByePacket(RtcpByePacket),
}
pub struct RtcpPacket;

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
            pt @ _ => Err(Box::new(UnrecognizedPacketType(pt))),
        }
    })
}
