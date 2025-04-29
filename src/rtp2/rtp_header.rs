use parsely_rs::*;
use std::io::Seek;

use crate::rtp2::header_extensions::read_header_extensions;

use super::header_extensions::HeaderExtensions;

/// An RTP header
///
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
pub struct RtpHeader {
    fixed_header: Bits,
    csrcs: Bits,
    extensions: HeaderExtensions,
}

impl RtpHeader {
    pub fn version(&self) -> u2 {
        (&self.fixed_header[..2]).as_u2()
    }

    pub fn has_padding(&self) -> bool {
        self.fixed_header[3]
    }

    pub fn has_extensions(&self) -> bool {
        self.fixed_header[4]
    }

    pub fn csrc_count(&self) -> u4 {
        (&self.fixed_header[4..8]).as_u4()
    }

    pub fn marked(&self) -> bool {
        self.fixed_header[8]
    }

    pub fn payload_type(&self) -> u7 {
        (&self.fixed_header[9..16]).as_u7()
    }

    pub fn seq_num(&self) -> u16 {
        u16::from_be_bytes(self.fixed_header.chunk_bytes()[2..3].try_into().unwrap())
    }

    pub fn timestamp(&self) -> u32 {
        u32::from_be_bytes(self.fixed_header.chunk_bytes()[4..8].try_into().unwrap())
    }

    pub fn ssrc(&self) -> u32 {
        u32::from_be_bytes(self.fixed_header.chunk_bytes()[8..12].try_into().unwrap())
    }

    ///// Returns the length of the extensions (including the extensions header) in bytes.  If
    ///// has_extensions is false, returns 0.
    //pub fn header_extensions_length_bytes(buf: &[u8]) -> u16 {
    //    if RtpHeader::has_extensions(buf) {
    //        let mut cursor = BitCursor::new(buf);
    //        let ext_offset = RtpHeader::extensions_start_offset(buf);
    //        cursor
    //            // Add 2 more to get to the length field
    //            .seek(std::io::SeekFrom::Start((ext_offset as u64 + 2) * 8))
    //            .unwrap();
    //        let length_field = cursor.get_u16::<NetworkOrder>().unwrap();
    //
    //        // 4 for the extensions header (type + length fields)
    //        4 + length_field * 4
    //    } else {
    //        0
    //    }
    //}
}

// RtpPacket {
//  RtpHeader {
//      fixed,
//      csrcs,
//      extensions
//  }
//  payload
// }

pub fn read_rtcp_header(buf: &mut Bits) -> ParselyResult<RtpHeader> {
    // The first 12 bytes are the fixed header
    let fixed_header = buf.split_to_bytes(12);
    // TODO: would be nice to be able to leverage the header logic to get this...
    let num_csrcs = (&fixed_header[4..8]).as_u4();
    let csrcs = buf.split_to_bytes(num_csrcs.into());
    let header_extensions = read_header_extensions(buf)?;

    todo!()
}
