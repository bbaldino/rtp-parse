use thiserror::Error;

pub type RtpParseResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Error, Debug)]
#[error("Unrecognized RTCP packet type {0}")]
pub struct UnrecognizedPacketType(pub u8);

#[derive(Error, Debug)]
#[error("Invalid length value: length field showed {length_field_bytes} bytes, but buffer only had {buf_remaining_bytes} bytes remaining")]
pub struct InvalidLengthValue {
    pub length_field_bytes: usize,
    pub buf_remaining_bytes: usize,
}
