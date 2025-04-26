use std::str::from_utf8;

use anyhow::{Context, Result};
use parsely_rs::*;

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
#[derive(Debug, ParselyRead, ParselyWrite, PartialEq)]
#[parsely_read(required_context("header: RtcpHeader"))]
pub struct RtcpSdesPacket {
    #[parsely_read(assign_from = "header")]
    #[parsely_write(sync_with("self.payload_length_bytes()", "u5::new(self.chunks.len() as u8)"))]
    #[parsely(assertion = "|header: &RtcpHeader| header.packet_type == RtcpSdesPacket::PT")]
    pub header: RtcpHeader,
    #[parsely_read(count = "header.report_count.into()")]
    pub chunks: Vec<SdesChunk>,
}

impl Default for RtcpSdesPacket {
    fn default() -> Self {
        Self {
            header: RtcpHeader {
                packet_type: RtcpSdesPacket::PT,
                ..Default::default()
            },
            chunks: Default::default(),
        }
    }
}

impl RtcpSdesPacket {
    pub const PT: u8 = 202;

    pub fn add_chunk(mut self, chunk: SdesChunk) -> Self {
        self.chunks.push(chunk);
        self
    }

    pub fn payload_length_bytes(&self) -> u16 {
        self.chunks.iter().map(|i| i.length_bytes()).sum()
    }
}

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.5
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ID       |     length    | value                       ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq)]
pub enum SdesItem {
    Empty,
    Cname(String),
    Unknown { item_type: u8, data: Vec<u8> },
}

impl SdesItem {
    pub fn cname(cname: &str) -> Self {
        SdesItem::Cname(cname.to_owned())
    }

    pub fn length_bytes(&self) -> u16 {
        // All items (except 'empty') take up:
        // 1 byte for the type
        // 1 byte for the length
        // N bytes for the data
        match self {
            SdesItem::Empty => 1,
            SdesItem::Cname(s) => 1 + 1 + s.len() as u16,
            SdesItem::Unknown { data, .. } => 1 + 1 + data.len() as u16,
        }
    }
}

impl ParselyRead for SdesItem {
    type Ctx = ();
    fn read<B: BitBuf, T: ByteOrder>(buf: &mut B, _ctx: ()) -> ParselyResult<Self> {
        let id = buf.get_u8().context("id")?;

        if id == 0 {
            return Ok(SdesItem::Empty);
        }
        let length = buf.get_u8().context("length")? as usize;
        let mut value_bytes = vec![0u8; length];
        buf.try_copy_to_slice_bytes(&mut value_bytes)
            .context("value")?;
        match id {
            1 => Ok(SdesItem::Cname(from_utf8(&value_bytes)?.to_owned())),
            t => Ok(SdesItem::Unknown {
                item_type: t,
                data: value_bytes.to_vec(),
            }),
        }
    }
}

impl_stateless_sync!(SdesItem);

impl ParselyWrite for SdesItem {
    type Ctx = ();
    fn write<B: BitBufMut, T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        match self {
            SdesItem::Empty => {
                buf.put_u8(0).context("id")?;
            }
            SdesItem::Cname(value) => {
                buf.put_u8(1).context("id")?;
                let bytes = value.as_bytes();
                buf.put_u8(bytes.len() as u8).context("length")?;
                buf.try_put_slice_bytes(bytes).context("value")?;
            }
            SdesItem::Unknown { item_type, data } => {
                buf.put_u8(*item_type).context("id")?;
                buf.put_u8(data.len() as u8).context("length")?;
                buf.try_put_slice_bytes(&data[..]).context("value")?;
            }
        }
        Ok(())
    }
}

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.5
///         0                   1                   2                   3
///         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// chunk  |                          SSRC/CSRC                            |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                           SDES items                          |
///        |                              ...                              |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#[derive(Debug, PartialEq)]
pub struct SdesChunk {
    pub ssrc: u32,
    /// Note that an empty SdesItem does _not_ need to be explicitly added here: that is handled
    /// when writing the chunk to a buffer
    pub sdes_items: Vec<SdesItem>,
}

impl SdesChunk {
    pub fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            sdes_items: Vec::new(),
        }
    }

    pub fn new_with_items(ssrc: u32, sdes_items: Vec<SdesItem>) -> Self {
        Self { ssrc, sdes_items }
    }

    pub fn add_item(mut self, item: SdesItem) -> Self {
        self.sdes_items.push(item);
        self
    }

    pub fn length_bytes(&self) -> u16 {
        let mut length_bytes = 4 + self
            .sdes_items
            .iter()
            .map(|i| i.length_bytes())
            .sum::<u16>();

        while length_bytes % 4 != 0 {
            length_bytes += 1;
        }

        length_bytes
    }
}

impl ParselyRead for SdesChunk {
    type Ctx = ();
    fn read<B: BitBuf, T: ByteOrder>(buf: &mut B, _ctx: ()) -> ParselyResult<Self> {
        let remaining_start = buf.remaining_bytes();
        let ssrc = buf.get_u32::<NetworkOrder>().context("ssrc")?;
        let mut sdes_items: Vec<SdesItem> = Vec::new();
        loop {
            let sdes_item = SdesItem::read::<_, T>(buf, ()).context("item")?;
            if matches!(sdes_item, SdesItem::Empty) {
                break;
            }
            sdes_items.push(sdes_item);
        }
        let mut consumed = remaining_start - buf.remaining_bytes();
        while consumed % 4 != 0 {
            buf.get_u8().unwrap();
            consumed += 1;
        }

        Ok(SdesChunk { ssrc, sdes_items })
    }
}

impl_stateless_sync!(SdesChunk);

impl ParselyWrite for SdesChunk {
    type Ctx = ();
    fn write<B: BitBufMut, T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        let remaining_start = buf.remaining_mut_bytes();
        buf.put_u32::<NetworkOrder>(self.ssrc).context("ssrc")?;
        self.sdes_items
            .iter()
            .enumerate()
            .map(|(i, sdes_item)| {
                sdes_item
                    .write::<_, T>(buf, ())
                    .with_context(|| format!("Sdes item {i}"))
            })
            .collect::<Result<Vec<()>>>()
            .context("Sdes items")?;

        SdesItem::Empty
            .write::<_, T>(buf, ())
            .context("Terminating empty sdes item")?;

        let mut amount_written = remaining_start - buf.remaining_mut_bytes();
        while amount_written % 4 != 0 {
            buf.put_u8(0).context("padding")?;
            amount_written += 1;
        }

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

        let mut bits = Bits::from_owner_bytes(item_data);
        let sdes_item = SdesItem::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
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

        let mut bits = Bits::from_owner_bytes(item_data);
        let res = SdesItem::read::<_, NetworkOrder>(&mut bits, ());
        assert!(res.is_err());
    }

    #[test]
    fn test_read_sdes_item() {
        // Cname item
        let data = create_cname_item_bytes("hello");
        let mut bits = Bits::from_owner_bytes(data);

        let item = SdesItem::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        match item {
            SdesItem::Cname(s) => assert_eq!("hello", s),
            _ => panic!("Expected cname item"),
        }
        // unknown item
        let data: Vec<u8> = vec![0x6, 0x4, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut bits = Bits::from_owner_bytes(data);

        let item = SdesItem::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        match item {
            SdesItem::Unknown { item_type, data } => {
                assert_eq!(item_type, 6);
                assert_eq!(&data[..], [0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("Expected unknown item"),
        }
    }

    #[test]
    fn test_write_sdes_item() {
        let item = SdesItem::cname("hello");
        let mut bits_mut = BitsMut::new();

        item.write::<_, NetworkOrder>(&mut bits_mut, ())
            .expect("successful write");

        let mut bits = bits_mut.freeze();

        let read_item = SdesItem::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        assert_eq!(item, read_item);
    }

    #[test]
    fn test_write_unknown_sdes_item() {
        let item = SdesItem::Unknown {
            item_type: 0x5,
            data: vec![0x42, 0x24],
        };
        let mut bits_mut = BitsMut::new();

        item.write::<_, NetworkOrder>(&mut bits_mut, ())
            .expect("successful write");

        let mut bits = bits_mut.freeze();

        let read_item = SdesItem::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        assert_eq!(item, read_item);
    }

    #[test]
    fn test_read_sdes_chunk() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // Cname, length 16, value hello
            0x01, 0x5, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Empty sdes item to finish
            0x00,
        ]);

        let chunk = SdesChunk::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        assert_eq!(bits.remaining_bytes(), 0);
        assert_eq!(chunk.ssrc, 42);
        assert_eq!(chunk.sdes_items.len(), 1);
        let item = &chunk.sdes_items[0];
        assert_eq!(item, &SdesItem::cname("hello"));
    }

    #[test]
    fn tesd_read_sdes_chunks() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // Cname, length 16, value hello
            0x01, 0x5, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Unknown
            0x04, 0x2, 0x42, 0x24,
            // Empty sdes item to finish
            0x00,
        ]);

        let chunk = SdesChunk::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        assert_eq!(bits.remaining_bytes(), 0);
        assert_eq!(chunk.ssrc, 42);
        assert_eq!(chunk.sdes_items.len(), 2);
        let item = &chunk.sdes_items[0];
        assert_eq!(item, &SdesItem::cname("hello"));
        let item = &chunk.sdes_items[1];
        assert_eq!(
            item,
            &SdesItem::Unknown {
                item_type: 0x4,
                data: vec![0x42, 0x24]
            }
        );
    }

    #[test]
    fn test_read_sdes_chunks_no_termination() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // Cname, length 16, value hello
            0x01, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Unknown
            0x04, 0x2, 0x42, 0x24,
            // No empty item to finish
        ]);

        let chunk = SdesChunk::read::<_, NetworkOrder>(&mut bits, ());
        assert!(chunk.is_err());
    }

    #[test]
    fn test_write_sdes_chunk() {
        let chunk = SdesChunk::new(42)
            .add_item(SdesItem::cname("hello"))
            .add_item(SdesItem::Unknown {
                item_type: 5,
                data: vec![0x42, 0x24],
            });

        let mut bits_mut = BitsMut::new();
        chunk
            .write::<_, NetworkOrder>(&mut bits_mut, ())
            .expect("successful write");
        let mut bits = bits_mut.freeze();
        let read_chunk =
            SdesChunk::read::<_, NetworkOrder>(&mut bits, ()).expect("successful read");
        assert_eq!(chunk, read_chunk);
    }

    #[test]
    fn test_read_sdes() {
        let header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(1),
            packet_type: 202,
            length_field: 4,
        };
        #[rustfmt::skip]
        let mut sdes_chunk_bits = Bits::from_static_bytes(&[
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // Cname, length 16, value hello
            0x01, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Unknown
            0x04, 0x2, 0x42, 0x24,
            // Empty sdes item to finish
            0x00,
        ]);

        let sdes = RtcpSdesPacket::read::<_, NetworkOrder>(&mut sdes_chunk_bits, (header,))
            .expect("Successful read");
        assert_eq!(sdes_chunk_bits.remaining_bytes(), 0);
        assert_eq!(sdes.chunks.len(), 1);
        let chunk = &sdes.chunks[0];
        assert_eq!(chunk.ssrc, 42);
        assert_eq!(chunk.sdes_items.len(), 2);
    }

    #[test]
    fn test_read_sdes_multiple_chunks() {
        let header = RtcpHeader {
            version: u2::new(2),
            has_padding: false,
            report_count: u5::new(2),
            packet_type: 202,
            length_field: 9,
        };
        #[rustfmt::skip]
        let mut sdes_chunks_bits = Bits::from_static_bytes(&[
            // ssrc (42)
            0x00, 0x00, 0x00, 0x2a,
            // Cname, length 16, value hello
            0x01, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Unknown
            0x04, 0x2, 0x42, 0x24,
            // Empty sdes item to finish
            0x00,
            // ssrc (43)
            0x00, 0x00, 0x00, 0x2b,
            // Unknown
            0x04, 0x4, 0x42, 0x24, 0x42, 0x24,
            // Cname, length 16, value hello
            0x01, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Empty item
            0x00, 
            // Padding
            0x00, 0x00
        ]);

        let sdes = RtcpSdesPacket::read::<_, NetworkOrder>(&mut sdes_chunks_bits, (header,))
            .expect("Successful read");
        assert_eq!(sdes_chunks_bits.remaining_bytes(), 0);
        assert_eq!(sdes.chunks.len(), 2);
        let chunk = &sdes.chunks[0];
        assert_eq!(chunk.ssrc, 42);
        assert_eq!(chunk.sdes_items.len(), 2);
        let chunk = &sdes.chunks[1];
        assert_eq!(chunk.ssrc, 43);
        assert_eq!(chunk.sdes_items.len(), 2);
    }

    #[test]
    fn test_sync_rtcp_sdes() {
        let mut rtcp_sdes = RtcpSdesPacket::default()
            .add_chunk(SdesChunk::new(42).add_item(SdesItem::cname("hello")))
            .add_chunk(SdesChunk::new(43).add_item(SdesItem::cname("world")));

        rtcp_sdes.sync(()).expect("successful sync");
        assert_eq!(rtcp_sdes.header.packet_type, RtcpSdesPacket::PT);
        assert_eq!(rtcp_sdes.header.report_count, 2);
        // payload has 2 chunks.
        //   Each chunk has one ssrc and one cname item and one empty terminator:
        //     Ssrc take 4
        //     Cname item takes 1 (type) + 1 (length) + 5 (hello/world are each 5) = 7 bytes
        //     Empty is 1
        //     4 + 7 + 1 = 12 (no padding needed)
        //   12 * 2 = 24 -> 6 words
        assert_eq!(rtcp_sdes.header.length_field, 6);
    }

    #[test]
    fn test_write_rtcp_sdes() {
        let mut rtcp_sdes = RtcpSdesPacket::default()
            .add_chunk(SdesChunk::new(42).add_item(SdesItem::cname("hello")))
            .add_chunk(SdesChunk::new(43).add_item(SdesItem::cname("world")));

        rtcp_sdes.sync(()).expect("successful sync");

        let mut bits_mut = BitsMut::new();

        rtcp_sdes
            .write::<_, NetworkOrder>(&mut bits_mut, ())
            .expect("successful write");

        let mut bits = bits_mut.freeze();
        let rtcp_header = RtcpHeader::read::<_, NetworkOrder>(&mut bits, ()).expect("rtcp header");
        let read_rtcp_sdes = RtcpSdesPacket::read::<_, NetworkOrder>(&mut bits, (rtcp_header,))
            .expect("successful read");
        assert_eq!(read_rtcp_sdes, rtcp_sdes);
    }
}
