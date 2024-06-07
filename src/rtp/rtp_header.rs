use std::io::Seek;

use anyhow::{Context, Result};
use bitcursor::{
    bit_cursor::BitCursor, bit_read::BitRead, bit_read_exts::BitReadExts, byte_order::NetworkOrder,
    ux::*,
};

use super::header_extensions::{parse_header_extensions, SomeHeaderExtension};

/// * https://tools.ietf.org/html/rfc3550#section-5.1
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ...extensions (if present)...                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtpHeader {
    pub version: u2,
    pub has_padding: bool,
    pub has_extensions: bool,
    pub csrc_count: u4,
    pub marked: bool,
    pub payload_type: u7,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extensions: Vec<SomeHeaderExtension>,
}

impl RtpHeader {
    pub fn get_extension_by_id(&self, id: u8) -> Option<&SomeHeaderExtension> {
        self.extensions.iter().find(|e| e.has_id(id))
    }
}

pub fn read_rtp_header<R: BitRead>(buf: &mut R) -> Result<RtpHeader> {
    let version = buf.read_u2().context("version")?;
    let has_padding = buf.read_bool().context("has_padding")?;
    let has_extensions = buf.read_bool().context("has_extensions")?;
    let csrc_count = buf.read_u4().context("csrc_count")?;
    let marked = buf.read_bool().context("marked")?;
    let payload_type = buf.read_u7().context("payload_type")?;
    let sequence_number = buf.read_u16::<NetworkOrder>().context("payload_type")?;
    let timestamp = buf.read_u32::<NetworkOrder>().context("timestamp")?;
    let ssrc = buf.read_u32::<NetworkOrder>().context("ssrc")?;
    // TODO: I think we need to impl 'Step' on the uX types to get 'map' here to be able to do
    // (u4::ZERO..csrc_count).map(...)
    let csrcs = (0u32..csrc_count.into())
        .map(|i| {
            buf.read_u32::<NetworkOrder>()
                .with_context(|| format!("csrc-{i}"))
        })
        .collect::<Result<Vec<u32>>>()
        .context("csrcs")?;
    let extensions = parse_header_extensions(buf).context("header extensions")?;

    Ok(RtpHeader {
        version,
        has_padding,
        has_extensions,
        csrc_count,
        marked,
        payload_type,
        sequence_number,
        timestamp,
        ssrc,
        csrcs,
        extensions,
    })
}

pub struct RtpHeader2;

impl RtpHeader2 {
    pub fn version(buf: &[u8]) -> u2 {
        u2::new((buf[0] & 0b11000000) >> 6)
    }

    pub fn has_padding(buf: &[u8]) -> bool {
        (buf[0] & 0b00100000) != 0
    }

    pub fn has_extensions(buf: &[u8]) -> bool {
        (buf[0] & 0b00010000) != 0
    }

    pub fn csrc_count(buf: &[u8]) -> u4 {
        u4::new(buf[0] & 0b00001111)
    }

    pub fn marked(buf: &[u8]) -> bool {
        (buf[1] & 0b10000000) != 0
    }

    pub fn payload_type(buf: &[u8]) -> u7 {
        u7::new(buf[1] & 0b01111111)
    }

    /// Returns the offset into the given buffer where the top-level extensions header would
    /// start, if this packet contains extensions.
    pub fn extensions_start_offset(buf: &[u8]) -> usize {
        let csrc_count: usize = RtpHeader2::csrc_count(buf).into();
        12 + csrc_count * 4
    }

    pub fn payload_offset(buf: &[u8]) -> usize {
        RtpHeader2::extensions_start_offset(buf)
            + RtpHeader2::header_extensions_length_bytes(buf) as usize
    }

    /// Returns the length of the extensions (including the extensions header) in bytes.  If
    /// has_extensions is false, returns 0.
    pub fn header_extensions_length_bytes(buf: &[u8]) -> u16 {
        if RtpHeader2::has_extensions(buf) {
            let mut cursor = BitCursor::new(buf);
            let ext_offset = RtpHeader2::extensions_start_offset(buf);
            cursor
                // Add 2 more to get to the length field
                .seek(std::io::SeekFrom::Start((ext_offset as u64 + 2) * 8))
                .unwrap();
            let length_field = cursor.read_u16::<NetworkOrder>().unwrap();

            // 4 for the extensions header (type + length fields)
            4 + length_field * 4
        } else {
            0
        }
    }
}
