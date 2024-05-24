use std::fmt::{Debug, LowerHex};

use anyhow::{anyhow, bail, Context, Result};
use bitcursor::{
    bit_read::BitRead, bit_read_exts::BitReadExts, bit_write::BitWrite,
    bit_write_exts::BitWriteExts, byte_order::NetworkOrder, ux::*,
};

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|    SC   |  PT=SDES=202  |             length            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
///
/// length: 16 bits
///   The length of this RTCP packet in 32-bit words minus one,
///   including the header and any padding.  (The offset of one makes
///   zero a valid length and avoids a possible infinite loop in
///   scanning a compound RTCP packet, while counting 32-bit words
///   avoids a validity check for a multiple of 4.)
#[derive(Debug, PartialEq, Eq)]
pub struct RtcpHeader {
    pub version: u2,
    pub has_padding: bool,
    pub report_count: u5,
    pub packet_type: u8,
    pub length_field: u16,
}

impl RtcpHeader {
    pub const SIZE_BYTES: usize = 4;

    /// The length of this RTCP packet's payload (i.e. excluding the header) in bytes
    pub fn payload_length_bytes(&self) -> Result<u16> {
        self.length_field
            .checked_mul(4)
            .ok_or(anyhow!("Invalid length field"))
    }
}

pub fn read_rtcp_header<R: BitRead + Debug + LowerHex>(buf: &mut R) -> Result<RtcpHeader> {
    Ok(RtcpHeader {
        version: buf.read_u2().context("version")?,
        has_padding: buf.read_bool().context("has_padding")?,
        report_count: buf.read_u5().context("report_count")?,
        packet_type: buf.read_u8().context("packet_type")?,
        length_field: buf.read_u16::<NetworkOrder>().context("length_field")?,
    })
}

pub fn write_rtcp_header<W: BitWrite>(buf: &mut W, header: &RtcpHeader) -> Result<()> {
    buf.write_u2(header.version).context("version")?;
    buf.write_bool(header.has_padding).context("has_padding")?;
    buf.write_u5(header.report_count).context("report_count")?;
    buf.write_u8(header.packet_type).context("packet_type")?;
    buf.write_u16::<NetworkOrder>(header.length_field)
        .context("length_field")?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings, clippy::bool_assert_comparison)]
mod tests {
    use bitcursor::bit_cursor::BitCursor;
    use bitvec::{order::Msb0, vec::BitVec};

    use super::*;

    #[test]
    fn test_read_rtcp_header() {
        let data: Vec<u8> = vec![0b10_0_00001, 202, 0, 42];
        let mut cursor = BitCursor::new(BitVec::<_, Msb0>::from_vec(data));

        let header = read_rtcp_header(&mut cursor)
            .context("rtcp header")
            .unwrap();
        assert_eq!(header.version, u2::new(2));
        assert_eq!(header.has_padding, false);
        assert_eq!(header.report_count, u5::new(1));
        assert_eq!(header.packet_type, 202);
        assert_eq!(header.length_field, 42);
    }

    #[test]
    fn test_write_rtcp_header() {
        let header = RtcpHeader {
            version: u2::new(1),
            has_padding: false,
            report_count: u5::new(1),
            packet_type: 1,
            length_field: 2,
        };

        let data: Vec<u8> = vec![0; 4];
        let bv = BitVec::<_, Msb0>::from_vec(data);
        let mut cursor = BitCursor::new(bv);

        write_rtcp_header(&mut cursor, &header).expect("successful write");
        let data = cursor.into_inner();

        let mut read_cursor = BitCursor::new(data);
        let read_header = read_rtcp_header(&mut read_cursor)
            .context("rtcp header")
            .unwrap();
        assert_eq!(header, read_header);
    }
}
