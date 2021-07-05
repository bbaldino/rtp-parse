use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::{
    error::{PacketParseResult, ValidationError, ValidationResult},
    packet_parsing::try_parse_field,
    validators::{RequireEqual, Validatable},
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
#[derive(Debug)]
pub struct RtcpHeader {
    pub version: u8,
    pub has_padding: bool,
    pub report_count: u8,
    pub packet_type: u8,
    pub length_field: u16,
}

impl RtcpHeader {
    pub const SIZE_BYTES: usize = 4;

    pub fn length_bytes(&self) -> usize {
        (self.length_field as usize + 1) * 4
    }
}

fn validate_packet_type(packet_type: &u8) -> ValidationResult {
    match packet_type {
        90..=120 => Ok(()),
        _ => Err(ValidationError(format!(
            "Expected value between 90 and 120, got {}",
            packet_type
        ))),
    }
}

pub fn parse_rtcp_header(buf: &mut dyn ReadableBuf) -> PacketParseResult<RtcpHeader> {
    try_parse_field("rtcp header", || {
        Ok(RtcpHeader {
            version: try_parse_field("version", || buf.read_bits_as_u8(2)?.require_value(2))?,
            has_padding: try_parse_field("has_padding", || buf.read_bit_as_bool())?,
            report_count: try_parse_field("report count", || buf.read_bits_as_u8(5))?,
            packet_type: try_parse_field("packet_type", || {
                buf.read_u8()?.validate(validate_packet_type)
            })?,
            length_field: try_parse_field("length field", || buf.read_u16())?,
        })
    })
}

#[cfg(test)]
mod tests {
    use bitbuffer::bit_buffer::BitBuffer;

    use super::*;

    #[test]
    fn test_parse_rtcp_header() {
        let data: Vec<u8> = vec![0b10_1_00011, 89, 0x00, 0x05];

        let mut buf = BitBuffer::new(data);

        if let Err(e) = parse_rtcp_header(&mut buf) {
            println!("{}", e);
        }
    }
}
