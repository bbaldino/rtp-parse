use parsely::*;

/// https://datatracker.ietf.org/doc/html/rfc4585#section-6.1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of packet sender                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  SSRC of media source                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, ParselyRead, ParselyWrite, PartialEq)]
pub struct RtcpFbHeader {
    pub sender_ssrc: u32,
    pub media_source_ssrc: u32,
}

impl RtcpFbHeader {
    pub fn new(sender_ssrc: u32, media_source_ssrc: u32) -> Self {
        Self {
            sender_ssrc,
            media_source_ssrc,
        }
    }
}
