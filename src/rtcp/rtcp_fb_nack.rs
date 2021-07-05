use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::packet_parsing::try_parse_field;

use crate::error::RtpParseResult;

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

/// https://datatracker.ietf.org/doc/html/rfc4585#section-6.2.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            PID                |             BLP               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug)]
pub struct RtcpFbNackPacket {
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    missing_seq_nums: Vec<u16>,
}

impl RtcpFbNackPacket {
    pub const FMT: u8 = 1;
}

pub fn parse_rtcp_fb_nack(
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    buf: &mut dyn ReadableBuf,
) -> RtpParseResult<RtcpFbNackPacket> {
    try_parse_field("rtcp fb nack payload", || {
        let mut missing_seq_nums = Vec::<u16>::new();
        while buf.bytes_remaining() >= NackBlock::SIZE_BYTES {
            missing_seq_nums.extend(parse_nack_block(buf)?.missing_seq_nums);
        }
        Ok(RtcpFbNackPacket {
            header,
            fb_header,
            missing_seq_nums,
        })
    })
}

struct NackBlock {
    missing_seq_nums: Vec<u16>,
}

impl NackBlock {
    pub const SIZE_BYTES: usize = 2;
}

fn parse_nack_block(buf: &mut dyn ReadableBuf) -> RtpParseResult<NackBlock> {
    try_parse_field("nack block", || {
        let packet_id = try_parse_field("packet id", || buf.read_u16())?;
        let blp = try_parse_field("blp", || buf.read_u16())?;
        Ok(NackBlock {
            missing_seq_nums: parse_missing_seq_nums(packet_id, blp),
        })
    })
}

fn parse_missing_seq_nums(packet_id: u16, blp: u16) -> Vec<u16> {
    let mut missing_seq_nums = Vec::<u16>::new();
    missing_seq_nums.push(packet_id);
    for shift_amount in 0..16 {
        if (blp >> shift_amount) & 0x1 == 1 {
            missing_seq_nums.push(packet_id + shift_amount + 1);
        }
    }
    missing_seq_nums
}
