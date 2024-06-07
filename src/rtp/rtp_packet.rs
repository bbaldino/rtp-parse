use std::{fmt::Debug, io::Read, ops::Range};

use anyhow::{Context, Result};
use bitcursor::{bit_cursor::BitCursor, ux::u7};

use crate::PacketBuffer;

use super::rtp_header::{read_rtp_header, RtpHeader, RtpHeader2};

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
#[derive(Debug)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    pub fn payload_type(&self) -> u7 {
        self.header.payload_type
    }
}

pub fn read_rtp_packet(data: Vec<u8>) -> Result<RtpPacket> {
    let mut cursor = BitCursor::from_vec(data);
    let header = read_rtp_header(&mut cursor).context("rtp header")?;
    let payload_len = cursor.bytes_remaining();
    let mut payload = vec![0u8; payload_len];
    cursor.read_exact(&mut payload).context("payload")?;

    Ok(RtpPacket { header, payload })
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

pub struct RtpPacket2 {
    buf: Vec<u8>,
    header_extensions: Option<SliceDesc>,
    pending_header_extensions: Vec<PendingHeaderExtensionOperation>,
    payload: SliceDesc,
}

impl RtpPacket2 {
    pub fn payload_type(&self) -> u7 {
        RtpHeader2::payload_type(&self.buf)
    }

    pub fn extensions(&self) -> Option<&[u8]> {
        self.header_extensions
            .as_ref()
            .map(|he_desc| &self.buf[he_desc.range()])
    }

    pub fn payload(&self) -> &[u8] {
        &self.buf[self.payload.range()]
    }
}

impl Debug for RtpPacket2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "extensions: {:x?}\npayload: {:x?}",
            self.extensions(),
            self.payload()
        )
    }
}

pub fn read_rtp_packet2(buf: Vec<u8>) -> Result<RtpPacket2> {
    let extensions_slice = if RtpHeader2::has_extensions(&buf) {
        let csrc_len: usize = Into::<usize>::into(RtpHeader2::csrc_count(&buf)) * 4;
        let extensions_start = 12 + csrc_len;
        let extensions_length = RtpHeader2::header_extensions_length_bytes(&buf) as usize;
        Some(SliceDesc {
            offset: extensions_start,
            length: extensions_length,
        })
    } else {
        None
    };

    let payload_start = RtpHeader2::payload_offset(&buf);
    let payload_length = buf.len() - payload_start;
    let payload_slice = SliceDesc {
        offset: payload_start,
        length: payload_length,
    };

    Ok(RtpPacket2 {
        buf,
        header_extensions: extensions_slice,
        pending_header_extensions: Vec::new(),
        payload: payload_slice,
    })
}
