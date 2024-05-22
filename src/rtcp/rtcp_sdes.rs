use std::str::from_utf8;

use anyhow::{Context, Result};
use bitcursor::{
    bit_read_exts::BitReadExts, bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
};

use crate::{util::consume_padding, PacketBuffer, PacketBufferMut};

use super::rtcp_header::{write_rtcp_header, RtcpHeader};

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
#[derive(Debug)]
pub struct RtcpSdesPacket {
    pub header: RtcpHeader,
    pub chunks: Vec<SdesChunk>,
}

impl RtcpSdesPacket {
    pub const PT: u8 = 202;
}

pub fn read_rtcp_sdes<B: PacketBuffer>(buf: &mut B, header: RtcpHeader) -> Result<RtcpSdesPacket> {
    let num_chunks = header.report_count;
    let chunks = (0u8..num_chunks.into())
        .map(|i| read_sdes_chunk(buf).with_context(|| format!("chunk {i}")))
        .collect::<Result<Vec<SdesChunk>>>()
        .context("sdes chunks")?;

    Ok(RtcpSdesPacket { header, chunks })
}

pub fn write_rtcp_sdes<B: PacketBufferMut>(buf: &mut B, rtcp_sdes: &RtcpSdesPacket) -> Result<()> {
    write_rtcp_header(buf, &rtcp_sdes.header).context("header")?;
    rtcp_sdes
        .chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| write_sdes_chunk(buf, chunk).with_context(|| format!("chunk {i}")))
        .collect::<Result<Vec<()>>>()
        .context("chunks")?;

    Ok(())
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

pub fn read_sdes_item<R: PacketBuffer>(buf: &mut R) -> Result<SdesItem> {
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

pub fn write_sdes_item<W: PacketBufferMut>(buf: &mut W, sdes_item: &SdesItem) -> Result<()> {
    match sdes_item {
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

#[derive(Debug)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub sdes_items: Vec<SdesItem>,
}

pub fn read_sdes_chunk<R: PacketBuffer>(buf: &mut R) -> Result<SdesChunk> {
    let ssrc = buf.read_u32::<NetworkOrder>().context("ssrc")?;
    let mut sdes_items: Vec<SdesItem> = Vec::new();
    loop {
        let sdes_item = read_sdes_item(buf).context("item")?;
        if matches!(sdes_item, SdesItem::Empty) {
            break;
        }
        sdes_items.push(sdes_item);
    }

    consume_padding(buf);

    Ok(SdesChunk { ssrc, sdes_items })
}

pub fn write_sdes_chunk<W: PacketBufferMut>(buf: &mut W, sdes_chunk: &SdesChunk) -> Result<()> {
    buf.write_u32::<NetworkOrder>(sdes_chunk.ssrc)
        .context("ssrc")?;
    sdes_chunk
        .sdes_items
        .iter()
        .enumerate()
        .map(|(i, sdes_item)| {
            write_sdes_item(buf, sdes_item).with_context(|| format!("sdes item {i}"))
        })
        .collect::<Result<Vec<()>>>()
        .context("sdes items")?;

    write_sdes_item(buf, &SdesItem::Empty).context("empty item")?;

    // TODO: I'm wondering about doing the padding here: what if the buffer we're given is a slice
    // which doesn't have the proper context of the overall alignment? Also, we'll need some trait
    // to be able to even add padding here to some alignment.

    Ok(())
}
