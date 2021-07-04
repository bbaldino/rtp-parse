use std::str::from_utf8;

use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::error::{PacketParseResult, ToPacketParseResult};
use packet_parsing::field_buffer::FieldBuffer;
use packet_parsing::packet_parsing::{try_parse_field_group, Mappable};

use crate::rtcp_header::RtcpHeader;

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.5
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// header |V=2|P|    SC   |  PT=SDES=202  |             length            |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// chunk  |                          SSRC/CSRC_1                          |
///   1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                           SDES items                          |
///        |                              ...                              |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// chunk  |                          SSRC/CSRC_2                          |
///   2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                           SDES items                          |
///        |                              ...                              |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

pub enum SdesItem {
    Cname { user_and_domain_name: String },
}

pub struct SdesChunk {
    ssrc: u32,
    sdes_item: SdesItem,
}

pub struct RtcpSdesPacket {
    pub header: RtcpHeader,
    pub chunks: Vec<SdesChunk>,
}

pub fn parse_rtcp_sdes(
    buf: &mut dyn ReadableBuf,
    header: RtcpHeader,
) -> PacketParseResult<RtcpSdesPacket> {
    todo!()
}

pub fn parse_sdes_chunk(buf: &mut dyn ReadableBuf) -> PacketParseResult<SdesChunk> {
    try_parse_field_group("sdes chunk", || {
        Ok(SdesChunk {
            ssrc: buf.read_u32_field("ssrc")?,
            sdes_item: parse_sdes_item(buf)?,
        })
    })
}

///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |      ID       |     length    | value                       ...
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

pub fn parse_sdes_item(buf: &mut dyn ReadableBuf) -> PacketParseResult<SdesItem> {
    let id = buf.read_u8_field("id")?;
    let length = buf.read_u8_field("length")? as usize;
    //let bytes = buf.read_bytes(length).to_ppr("sdes data")?.to_owned();
    let bytes = buf.read_bytes_field(length, "sdes item value");
    let x = from_utf8(bytes);
    todo!()
}
