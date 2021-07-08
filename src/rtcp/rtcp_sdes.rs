use std::str::from_utf8;

use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::error::PacketParseResult;
use packet_parsing::packet_parsing::try_parse_field;

use crate::error::RtpParseResult;
use crate::rtcp::rtcp_header::RtcpHeader;

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
#[derive(Debug)]
pub enum SdesItem {
    Empty,
    Cname(String),
    Unknown { item_type: u8, data: Vec<u8> },
}

#[derive(Debug)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub sdes_item: SdesItem,
}

#[derive(Debug)]
pub struct RtcpSdesPacket {
    pub header: RtcpHeader,
    pub chunks: Vec<SdesChunk>,
}

impl RtcpSdesPacket {
    pub const PT: u8 = 202;
}

pub fn parse_rtcp_sdes(
    buf: &mut dyn ReadableBuf,
    header: RtcpHeader,
) -> PacketParseResult<RtcpSdesPacket> {
    try_parse_field("rtcp sdes", || {
        let num_chunks = header.report_count as usize;
        Ok(RtcpSdesPacket {
            header,
            chunks: parse_sdes_chunks(buf, num_chunks)?,
        })
    })
}

pub fn parse_sdes_chunks(
    buf: &mut dyn ReadableBuf,
    num_chunks: usize,
) -> PacketParseResult<Vec<SdesChunk>> {
    (0..num_chunks)
        .map(|_| parse_sdes_chunk(buf))
        .collect::<RtpParseResult<Vec<SdesChunk>>>()
}

pub fn parse_sdes_chunk(buf: &mut dyn ReadableBuf) -> PacketParseResult<SdesChunk> {
    try_parse_field("sdes chunk", || {
        Ok(SdesChunk {
            ssrc: try_parse_field("ssrc", || buf.read_u32())?,
            sdes_item: parse_sdes_item(buf)?,
        })
    })
}

pub fn parse_rtcp_sdes_items(buf: &mut dyn ReadableBuf) -> RtpParseResult<Vec<SdesItem>> {
    let mut sdes_items: Vec<SdesItem> = Vec::new();
    loop {
        match parse_sdes_item(buf) {
            Ok(SdesItem::Empty) => break,
            Ok(item) => sdes_items.push(item),
            Err(e) => return Err(e),
        }
    }
    Ok(sdes_items)
}

///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |      ID       |     length    | value                       ...
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub fn parse_sdes_item(buf: &mut dyn ReadableBuf) -> RtpParseResult<SdesItem> {
    try_parse_field("sdes item", || {
        let id = try_parse_field("id", || buf.read_u8())?;
        match id {
            0 => Ok(SdesItem::Empty),
            t @ _ => {
                let length = try_parse_field("length", || buf.read_u8())?;
                let bytes = try_parse_field("data", || buf.read_bytes(length as usize))?;

                // Now parse the payload according to the actual SDES item type
                match t {
                    1 => match from_utf8(bytes) {
                        Ok(s) => Ok(SdesItem::Cname(s.to_owned())),
                        Err(e) => Err(e.into()),
                    },
                    t @ _ => Ok(SdesItem::Unknown {
                        item_type: t,
                        data: bytes.to_vec(),
                    }),
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use bitbuffer::bit_buffer::BitBuffer;

    use super::*;

    #[test]
    fn test_parse_sdes_item_success() {
        let str = "hello, world!";
        let data = str.bytes();
        let mut item_data = vec![0x1, data.len() as u8];
        item_data.extend(data.collect::<Vec<u8>>());

        let mut buf = BitBuffer::new(item_data);
        let sdes_item = parse_sdes_item(&mut buf).unwrap();
        match sdes_item {
            SdesItem::Cname(v) => assert_eq!(v, str),
            _ => assert!(false, "Wrong SdesItem type"),
        }
    }

    #[test]
    fn test_parse_sdes_item_bad_data() {
        let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut item_data = vec![0x1, data.len() as u8];
        item_data.extend(data);

        let mut buf = BitBuffer::new(item_data);
        let res = parse_sdes_item(&mut buf);
        assert!(res.is_err());
    }

    // TODO:
    // parse_sdes_items (make sure we stop when seeing empty, correctly parse to end of buffer
    // parse_sdes_chunk success | failure in chunk | failure in item
    // parse_sdes_chunks
    // parse_rtcp_sdes success | failure in chunk
}
