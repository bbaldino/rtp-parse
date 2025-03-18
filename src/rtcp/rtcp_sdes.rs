use std::str::from_utf8;

use anyhow::{Context, Result};
use parsely::*;

use super::rtcp_header::RtcpHeader;

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
///   Items are contiguous, i.e., items are not individually padded to a
///     32-bit boundary.  Text is not null terminated because some multi-
///     octet encodings include null octets.  The list of items in each chunk
///     MUST be terminated by one or more null octets, the first of which is
///     interpreted as an item type of zero to denote the end of the list.
///     No length octet follows the null item type octet, but additional null
///     octets MUST be included if needed to pad until the next 32-bit
///     boundary.  Note that this padding is separate from that indicated by
///     the P bit in the RTCP header.  A chunk with zero items (four null
///     octets) is valid but useless.
#[derive(Debug, ParselyRead, ParselyWrite)]
#[parsely_read(required_context("header: RtcpHeader"))]
pub struct RtcpSdesPacket {
    #[parsely_read(assign_from = "header")]
    pub header: RtcpHeader,
    #[parsely_read(count = "header.report_count.into()")]
    pub chunks: Vec<SdesChunk>,
}

impl RtcpSdesPacket {
    pub const PT: u8 = 202;
}

/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ID       |     length    | value                       ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub enum SdesItem {
    Empty,
    Cname(String),
    Unknown { item_type: u8, data: Vec<u8> },
}

impl ParselyRead<()> for SdesItem {
    fn read<T: parsely::ByteOrder, B: parsely::BitRead>(
        buf: &mut B,
        _ctx: (),
    ) -> parsely::ParselyResult<Self> {
        let id = buf.read_u8().context("id")?;

        if id == 0 {
            return Ok(SdesItem::Empty);
        }
        let length = buf.read_u8().context("length")? as usize;
        let mut value_bytes = vec![0u8; length];
        buf.read_exact(&mut value_bytes).context("value")?;
        match id {
            1 => Ok(SdesItem::Cname(from_utf8(&value_bytes)?.to_owned())),
            t => Ok(SdesItem::Unknown {
                item_type: t,
                data: value_bytes.to_vec(),
            }),
        }
    }
}

impl ParselyWrite<()> for SdesItem {
    fn write<T: ByteOrder, B: BitWrite>(&self, buf: &mut B, _ctx: ()) -> ParselyResult<()> {
        match self {
            SdesItem::Empty => {
                buf.write_u8(0).context("id")?;
            }
            SdesItem::Cname(value) => {
                buf.write_u8(1).context("id")?;
                let bytes = value.as_bytes();
                buf.write_u8(bytes.len() as u8).context("length")?;
                buf.write(bytes).context("value")?;
            }
            SdesItem::Unknown { item_type, data } => {
                buf.write_u8(*item_type).context("id")?;
                buf.write(data).context("value")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub sdes_items: Vec<SdesItem>,
}

impl ParselyRead<()> for SdesChunk {
    fn read<T: ByteOrder, B: BitRead>(buf: &mut B, _ctx: ()) -> ParselyResult<Self> {
        let ssrc = buf.read_u32::<NetworkOrder>().context("ssrc")?;
        let mut sdes_items: Vec<SdesItem> = Vec::new();
        loop {
            let sdes_item = SdesItem::read::<T, _>(buf, ()).context("item")?;
            if matches!(sdes_item, SdesItem::Empty) {
                break;
            }
            sdes_items.push(sdes_item);
        }

        // TODO: need to consume padding here, but B needs to be Seek.  Can the rtp lib use a new
        // trait that's BitRead + Seek?  We'd need a way in Parsely to support adding extra
        // constraints--is that possible?
        // Or maybe we can get away with relying on the header's length field to know the end and
        // don't need to explicitly consume the padding...but it's nice to be able to verify the
        // slice was fully 'consumed' after reading to validate.
        // consume_padding(buf);

        Ok(SdesChunk { ssrc, sdes_items })
    }
}

impl ParselyWrite<()> for SdesChunk {
    fn write<T: ByteOrder, B: BitWrite>(&self, buf: &mut B, _ctx: ()) -> ParselyResult<()> {
        buf.write_u32::<NetworkOrder>(self.ssrc).context("ssrc")?;
        self.sdes_items
            .iter()
            .enumerate()
            .map(|(i, sdes_item)| {
                sdes_item
                    .write::<T, _>(buf, ())
                    .with_context(|| format!("Sdes item {i}"))
            })
            .collect::<Result<Vec<()>>>()
            .context("Sdes items")?;

        SdesItem::Empty
            .write::<T, _>(buf, ())
            .context("Terminating empty sdes item")?;

        // TODO: I'm wondering about doing the padding here: what if the buffer we're given is a slice
        // which doesn't have the proper context of the overall alignment? Also, we'll need some trait
        // to be able to even add padding here to some alignment.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_cname_item_bytes(str: &str) -> Vec<u8> {
        let data = str.bytes();
        let mut item_data = vec![0x1, data.len() as u8];
        item_data.extend(data.collect::<Vec<u8>>());

        item_data
    }

    #[test]
    fn test_read_sdes_item_success() {
        let str = "hello, world!";
        let item_data = create_cname_item_bytes(str);

        let mut buf = BitCursor::from_vec(item_data);
        let sdes_item = SdesItem::read::<NetworkOrder, _>(&mut buf, ()).expect("successful read");
        match sdes_item {
            SdesItem::Cname(v) => assert_eq!(v, str),
            _ => panic!("Wrong SdesItem type"),
        }
    }

    #[test]
    fn test_read_sdes_item_bad_data() {
        let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut item_data = vec![0x1, data.len() as u8];
        item_data.extend(data);

        let mut buf = BitCursor::from_vec(item_data);
        let res = SdesItem::read::<NetworkOrder, _>(&mut buf, ());
        assert!(res.is_err());
    }

    #[test]
    fn test_read_sdes() {
        let header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(1),
            packet_type: 202,
            length_field: 6,
        };
        #[rustfmt::skip]
        let sdes_chunk = vec![
            // ssrc
            0xa8, 0x9c, 0x2a, 0xc5,
            // Cname, length 16, value 6EENBH+pFqtpT6SF
            0x01, 0x10, 0x36, 0x45, 0x45, 0x4e, 0x42, 0x48, 0x2b, 0x70, 0x46, 0x71, 0x74, 0x70, 0x54, 0x36, 0x53, 0x46,
            // Empty sdes item to finish
            0x00,
        ];
        let mut cursor = BitCursor::from_vec(sdes_chunk);

        let sdes = RtcpSdesPacket::read::<NetworkOrder, _>(&mut cursor, (header,))
            .expect("Successful read");
        assert_eq!(sdes.chunks.len(), 1);
        let chunk = sdes.chunks.first().expect("sdes chunk");
        assert_eq!(chunk.ssrc, 2828806853);
    }

    // TODO:
    // read: test that trailing padding is consumed
    // parse_sdes_chunk success | failure in chunk | failure in item
    // parse_sdes_chunks
    // parse_rtcp_sdes success | failure in chunk
    // write: test that trailing padding is added
}
