use bitbuffer::readable_buf::ReadableBuf;
use packet_parsing::{
    error::{PacketParseResult, ValidationError, ValidationResult},
    field_buffer::FieldBuffer,
    packet_parsing::try_parse_field_group,
};

pub struct RtcpHeader {
    pub version: u8,
    pub has_padding: bool,
    pub report_count: u8,
    pub packet_type: u8,
    pub length_field: u16,
}

fn validate_packet_type(packet_type: u8) -> ValidationResult {
    match packet_type {
        90..=120 => Ok(()),
        _ => Err(ValidationError(format!(
            "Expected value between 90 and 120, got {}",
            packet_type
        ))),
    }
}

fn validate_version(version: u8) -> ValidationResult {
    match version {
        2 => Ok(()),
        _ => Err(ValidationError(format!(
            "Expected version 2, got {}",
            version
        ))),
    }
}

pub fn parse_rtcp_header(buf: &mut dyn ReadableBuf) -> PacketParseResult<RtcpHeader> {
    try_parse_field_group("rtcp header", || {
        let packet_size = buf.bytes_remaining();
        Ok(RtcpHeader {
            version: buf.read_bits_as_u8_field_and_validate(2, "version", validate_version)?,
            has_padding: buf.read_bool_field("has padding")?,
            report_count: buf.read_bits_as_u8_field(5, "report count")?,
            packet_type: buf.read_u8_field_and_validate("packet type", validate_packet_type)?,
            length_field: buf.read_u16_field_and_validate("length field", |length_field| {
                // I don't know that this is how we'd want to validate the size...but could work
                // (another way would be doing it at a higher level after the header had been
                // parsed and validating how much 'space' was left in the buffer to make sure they
                // match)
                if (length_field + 1) * 4 > packet_size as u16 {
                    Err(ValidationError(format!("Length field says packet is {} bytes long, but buffer is only {} bytes long", ((length_field + 1) * 4), packet_size)))
                } else {
                    Ok(())
                }
            })?,
        })
    })
}

#[cfg(test)]
mod tests {
    use bitbuffer::bit_buffer::BitBuffer;

    use super::*;

    #[test]
    fn test_parse_rtcp_header() {
        let data: Vec<u8> = vec![0b10_1_00011, 90, 0x00, 0x05];

        let mut buf = BitBuffer::new(data);

        if let Err(e) = parse_rtcp_header(&mut buf) {
            println!("{}", e);
        }
    }
}
