use std::io::Seek;

use bitcursor::{bit_read::BitRead, bit_write::BitWrite};

pub mod rtcp;
mod util;

pub trait PacketBuffer: BitRead + Seek {}
impl<T> PacketBuffer for T where T: BitRead + Seek {}

pub trait PacketBufferMut: BitWrite + Seek {}
impl<T> PacketBufferMut for T where T: BitWrite + Seek {}
