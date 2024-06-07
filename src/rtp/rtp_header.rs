use std::io::Seek;

use bitcursor::{
    bit_cursor::BitCursor, bit_read_exts::BitReadExts, byte_order::NetworkOrder, ux::*,
};

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
pub struct RtpHeader;

impl RtpHeader {
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

    pub fn seq_num(buf: &[u8]) -> u16 {
        let seq_num_b1 = buf[3] as u16;
        let seq_num_b2 = buf[4] as u16;
        (seq_num_b1 << 8) | seq_num_b2
    }

    /// Returns the offset into the given buffer where the top-level extensions header would
    /// start, if this packet contains extensions.
    pub fn extensions_start_offset(buf: &[u8]) -> usize {
        let csrc_count: usize = RtpHeader::csrc_count(buf).into();
        12 + csrc_count * 4
    }

    pub fn payload_offset(buf: &[u8]) -> usize {
        RtpHeader::extensions_start_offset(buf)
            + RtpHeader::header_extensions_length_bytes(buf) as usize
    }

    /// Returns the length of the extensions (including the extensions header) in bytes.  If
    /// has_extensions is false, returns 0.
    pub fn header_extensions_length_bytes(buf: &[u8]) -> u16 {
        if RtpHeader::has_extensions(buf) {
            let mut cursor = BitCursor::new(buf);
            let ext_offset = RtpHeader::extensions_start_offset(buf);
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
