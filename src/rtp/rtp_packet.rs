use std::{fmt::Debug, io::Write, ops::Range};

use anyhow::Result;
use bitcursor::{bit_cursor::BitCursor, ux::u7};

use super::{
    header_extensions::{parse_header_extensions, SomeHeaderExtension},
    rtp_header::RtpHeader,
};

/// https://tools.ietf.org/html/rfc3550#section-5.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
/// |                   payload                                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct RtpPacket {
    buf: Vec<u8>,
    header_extensions: Vec<SomeHeaderExtension>,
    pending_header_extension_ops: Vec<PendingHeaderExtensionOperation>,
    payload: SliceDesc,
}

impl RtpPacket {
    pub fn payload_type(&self) -> u7 {
        RtpHeader::payload_type(&self.buf)
    }

    pub fn payload(&self) -> &[u8] {
        &self.buf[self.payload.range()]
    }

    pub fn get_extension_by_id(&self, id: u8) -> Option<&SomeHeaderExtension> {
        self.header_extensions.iter().find(|e| e.has_id(id))
    }

    /// Return the original size of this packet in bytes.
    pub fn size_bytes(&self) -> u32 {
        self.buf.len() as u32
    }
}

impl Debug for RtpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "extensions: {:x?}\npayload: {:x?}",
            self.header_extensions,
            self.payload()
        )
    }
}

enum PendingHeaderExtensionOperation {
    Remove {
        id: u8,
    },
    Add {
        ext: super::header_extensions::SomeHeaderExtension,
    },
}

struct SliceDesc {
    offset: usize,
    length: usize,
}

impl SliceDesc {
    fn range(&self) -> Range<usize> {
        self.offset..(self.offset + self.length)
    }
}

pub fn read_rtp_packet(buf: Vec<u8>) -> Result<RtpPacket> {
    let mut bit_cursor = BitCursor::new(&buf[RtpHeader::extensions_start_offset(&buf)..]);
    let header_extensions = parse_header_extensions(&mut bit_cursor).unwrap();

    let payload_start = RtpHeader::payload_offset(&buf);
    let payload_length = buf.len() - payload_start;
    let payload_slice = SliceDesc {
        offset: payload_start,
        length: payload_length,
    };

    Ok(RtpPacket {
        buf,
        header_extensions,
        pending_header_extension_ops: Vec::new(),
        payload: payload_slice,
    })
}
