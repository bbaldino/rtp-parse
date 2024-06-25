use std::{collections::HashMap, fmt::Debug, io::Write, ops::Range};

use anyhow::Result;
use bitcursor::{bit_cursor::BitCursor, ux::u7};
use bytes::{Bytes, BytesMut};

use super::{
    header_extensions::{
        parse_header_extensions, read_header_extensions, SomeHeaderExtension, SomeHeaderExtension2,
    },
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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct RtpPacket2 {
    // Includes the fixed header and csrcs
    header: BytesMut,
    header_exts_buf: BytesMut,
    // We lazily parse the header extensions
    parsed_header_extensions: HashMap<u8, SomeHeaderExtension2>,
    payload: BytesMut,
    pending_header_extension_ops: Vec<PendingHeaderExtensionOperation>,
}

impl RtpPacket2 {
    pub fn payload_type(&self) -> u7 {
        RtpHeader::payload_type(&self.header)
    }

    pub fn get_extension_by_id(&self, id: u8) -> Option<&SomeHeaderExtension2> {
        self.parsed_header_extensions.get(&id)
    }
}

pub fn read_rtp_packet2(buf: Vec<u8>) -> Result<RtpPacket2> {
    // TODO: eventaully I think we'll have it where this was already a BytesMut type and we don't
    // have to copy it here
    let mut bytes = BytesMut::with_capacity(buf.len());
    bytes.extend_from_slice(&buf);
    let csrc_count = Into::<usize>::into(RtpHeader::csrc_count(&bytes));
    let header_length_bytes = 12 + 4 * csrc_count;
    let header = bytes.split_to(header_length_bytes);
    let header_extensions_length_bytes = ((((bytes[2] as u16) << 8) + bytes[3] as u16) + 1) * 4;

    let header_exts = bytes.split_to(header_extensions_length_bytes as usize);
    let parsed_header_extensions = read_header_extensions(header_exts.clone().into());

    Ok(RtpPacket2 {
        header,
        header_exts_buf: header_exts,
        parsed_header_extensions,
        payload: bytes,
        pending_header_extension_ops: Vec::new(),
    })
}

#[cfg(test)]
mod test {
    use super::read_rtp_packet2;

    #[test]
    fn test_read_rtp_packet2() {
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0x90, 0xef, 0x16, 0xad, 0x65, 0xf3, 0xe1, 0x4e, 0x32, 0x0f, 0x22, 0x3a, 0xbe, 0xde,
            0x00, 0x01, 0x10, 0xff, 0x00, 0x00, 0x78, 0x0b, 0xe4, 0xc1, 0x36, 0xec, 0xc5, 0x8d,
            0x8c, 0x49, 0x46, 0x99, 0x04, 0xc5, 0xaa, 0xed, 0x92, 0xe7, 0x63, 0x4a, 0x3a, 0x18,
            0x98, 0xee, 0x62, 0xcb, 0x60, 0xff, 0x6c, 0x1b, 0x29, 0x00,
        ];

        let packet = read_rtp_packet2(data).unwrap();
        println!("{:x?}", packet.header.as_ref());
        println!("{:x?}", packet.header_exts_buf.as_ref());
        println!("{:?}", packet.parsed_header_extensions);
        println!("{:x?}", packet.payload.as_ref());
        // dbg!(packet);
    }
}
