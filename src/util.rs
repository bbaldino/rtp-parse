use std::{
    io::{Read, Seek, SeekFrom},
    ops::RangeInclusive,
};

use crate::rtcp::rtcp_header::RtcpHeader;

pub fn consume_padding<R: Read + Seek>(buf: &mut R) {
    let mut data_buf = [0u8; 1];
    loop {
        if buf.read_exact(&mut data_buf).is_ok() {
            if data_buf[0] != 0x00 {
                // We found the first non-padding byte, rewind back before it
                let _ = buf.seek(SeekFrom::Current(-1));
                break;
            }
        } else {
            break;
        }
    }
}

//
// "The process for demultiplexing a packet is as follows.  The receiver
// looks at the first byte of the packet."
//
// +----------------+
// |        [0..3] -+--> forward to STUN
// |                |
// |      [16..19] -+--> forward to ZRTP
// |                |
// |      [20..63] -+--> forward to DTLS
// |                |
// |      [64..79] -+--> forward to TURN Channel
// |                |
// |    [128..191] -+--> forward to RTP/RTCP
// +----------------+
//
// See [https://tools.ietf.org/html/rfc7983#section-7]
//
//
// RTP/RTCP are further demultiplexed based on the packet type (second byte)
const DTLS_RANGE: RangeInclusive<u8> = 20..=63;
const RTP_RTCP_RANGE: RangeInclusive<u8> = 128..=191;
const RTCP_PACKET_TYPE_RANGE: RangeInclusive<u8> = 192..=223;

pub fn looks_like_rtp(buf: &[u8]) -> bool {
    // TODO: use RtpHeader::SIZE_BYTES constant when it exists
    if buf.len() < 12 {
        return false;
    }

    RTP_RTCP_RANGE.contains(&buf[0]) && !RTCP_PACKET_TYPE_RANGE.contains(&buf[1])
}

pub fn looks_like_rtcp(buf: &[u8]) -> bool {
    if buf.len() < RtcpHeader::SIZE_BYTES {
        return false;
    }

    RTP_RTCP_RANGE.contains(&buf[0]) && RTCP_PACKET_TYPE_RANGE.contains(&buf[1])
}

pub fn looks_like_dtls(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }

    DTLS_RANGE.contains(&buf[0])
}
