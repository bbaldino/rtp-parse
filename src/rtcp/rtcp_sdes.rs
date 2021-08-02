use std::str::from_utf8;

use byteorder::NetworkEndian;

use crate::error::RtpParseResult;
use crate::packet_buffer::PacketBuffer;
use crate::rtcp::rtcp_header::RtcpHeader;
use crate::with_context::{with_context, Context};

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

pub fn parse_rtcp_sdes<B: PacketBuffer>(
    buf: &mut B,
    header: RtcpHeader,
) -> RtpParseResult<RtcpSdesPacket> {
    with_context("rtcp sdes", || {
        let num_chunks = header.report_count as usize;
        Ok(RtcpSdesPacket {
            header,
            chunks: parse_sdes_chunks(buf, num_chunks)?,
        })
    })
}

pub fn parse_sdes_chunks<B: PacketBuffer>(
    buf: &mut B,
    num_chunks: usize,
) -> RtpParseResult<Vec<SdesChunk>> {
    (0..num_chunks)
        .map(|_| parse_sdes_chunk(buf))
        .collect::<RtpParseResult<Vec<SdesChunk>>>()
}

pub fn parse_sdes_chunk<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<SdesChunk> {
    with_context("sdes chunk", || {
        Ok(SdesChunk {
            ssrc: buf.read_u32::<NetworkEndian>().with_context("ssrc")?,
            sdes_item: parse_sdes_item(buf)?,
        })
    })
}

pub fn parse_rtcp_sdes_items<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<Vec<SdesItem>> {
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

/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ID       |     length    | value                       ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub fn parse_sdes_item<B: PacketBuffer>(buf: &mut B) -> RtpParseResult<SdesItem> {
    with_context("sdes item", || {
        let id = buf.read_u8().with_context("id")?;
        match id {
            0 => Ok(SdesItem::Empty),
            t => {
                let length = buf.read_u8().with_context("length")? as usize;
                let mut bytes = vec![0; length];
                buf.read_exact(&mut bytes).with_context("item bytes")?;

                // Now parse the payload according to the actual SDES item type
                match t {
                    1 => match from_utf8(&bytes) {
                        Ok(s) => Ok(SdesItem::Cname(s.to_owned())),
                        Err(e) => Err(e.into()),
                    },
                    t => Ok(SdesItem::Unknown {
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
    use bytebuffer::{byte_buffer_cursor::ByteBufferCursor, sized_buffer::SizedByteBuffer};

    use super::*;

    fn create_cname_item_bytes(str: &str) -> Vec<u8> {
        let data = str.bytes();
        let mut item_data = vec![0x1, data.len() as u8];
        item_data.extend(data.collect::<Vec<u8>>());

        item_data
    }

    #[test]
    fn test_parse_sdes_item_success() {
        let str = "hello, world!";
        let item_data = create_cname_item_bytes(str);

        let mut buf = ByteBufferCursor::new(item_data);
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

        let mut buf = ByteBufferCursor::new(item_data);
        let res = parse_sdes_item(&mut buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_sdes_items() {
        let str = "hello, world!";
        let item_1 = create_cname_item_bytes(str);
        let item_2 = vec![0]; // Empty item
        let mut items: Vec<u8> = vec![];
        items.extend(item_1);
        items.extend(item_2);

        let mut buf = ByteBufferCursor::new(items);
        let sdes_items = parse_rtcp_sdes_items(&mut buf).unwrap();
        assert_eq!(sdes_items.len(), 1);
        assert_eq!(buf.bytes_remaining(), 0);
    }

    // TODO:
    // parse_sdes_chunk success | failure in chunk | failure in item
    // parse_sdes_chunks
    // parse_rtcp_sdes success | failure in chunk
}
