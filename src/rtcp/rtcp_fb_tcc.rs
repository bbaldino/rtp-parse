use anyhow::{Context, Result};
use byteorder::NetworkEndian;
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

use crate::{packet_buffer::PacketBuffer, util::consume_padding};

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

use PacketReport::{
    ReceivedPacketLargeOrNegativeDelta, ReceivedPacketSmallDelta, UnreceivedPacket,
};
use PacketStatusSymbol::{NotReceived, ReceivedLargeOrNegativeDelta, ReceivedSmallDelta};

#[derive(Error, Debug)]
#[error("Invalid TCC packet status symbol {}", 0)]
struct InvalidPacketStatusSymbol(u8);

#[derive(Error, Debug)]
#[error("Invalid TCC packet status symbol size {}", 0)]
struct InvalidSymbolSize(u8);

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PacketStatusSymbol {
    NotReceived = 0,
    ReceivedSmallDelta = 1,
    ReceivedLargeOrNegativeDelta = 2,
}

impl PacketStatusSymbol {
    pub fn delta_size(&self) -> usize {
        match self {
            NotReceived => 0,
            ReceivedSmallDelta => 1,
            ReceivedLargeOrNegativeDelta => 2,
        }
    }
}

impl TryFrom<u8> for PacketStatusSymbol {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, anyhow::Error> {
        match value {
            0 => Ok(NotReceived),
            1 => Ok(ReceivedSmallDelta),
            2 => Ok(ReceivedLargeOrNegativeDelta),
            s @ _ => Err(InvalidPacketStatusSymbol(s).into()),
        }
    }
}

/// The chunk types
/// The iterators for the chunk types
/// The enum to wrap the chunk types

struct RleChunk {
    symbol: PacketStatusSymbol,
    run_length: usize,
}

struct RleIterator {
    rle: RleChunk,
    curr_index: usize,
}

impl Iterator for RleIterator {
    type Item = PacketStatusSymbol;
    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_index == self.rle.run_length {
            None
        } else {
            self.curr_index += 1;
            Some(self.rle.symbol)
        }
    }
}

impl IntoIterator for RleChunk {
    type Item = PacketStatusSymbol;
    type IntoIter = RleIterator;
    fn into_iter(self) -> Self::IntoIter {
        RleIterator {
            rle: self,
            curr_index: 0,
        }
    }
}

struct SvChunk {
    symbols: Vec<PacketStatusSymbol>,
}

impl IntoIterator for SvChunk {
    type Item = PacketStatusSymbol;
    type IntoIter = <Vec<PacketStatusSymbol> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.symbols.into_iter()
    }
}

enum SomePacketStatusChunk {
    RleChunk(RleChunk),
    SvChunk(SvChunk),
}

enum SomePacketStatusChunkIterator {
    RleChunkIterator(RleIterator),
    SvChunkIterator(std::vec::IntoIter<PacketStatusSymbol>),
}

impl Iterator for SomePacketStatusChunkIterator {
    type Item = PacketStatusSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SomePacketStatusChunkIterator::RleChunkIterator(i) => i.next(),
            SomePacketStatusChunkIterator::SvChunkIterator(i) => i.next(),
        }
    }
}

impl IntoIterator for SomePacketStatusChunk {
    type Item = PacketStatusSymbol;
    type IntoIter = SomePacketStatusChunkIterator;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SomePacketStatusChunk::RleChunk(rle) => {
                SomePacketStatusChunkIterator::RleChunkIterator(rle.into_iter())
            }
            SomePacketStatusChunk::SvChunk(sv) => {
                SomePacketStatusChunkIterator::SvChunkIterator(sv.into_iter())
            }
        }
    }
}

pub trait PacketStatusChunk: IntoIterator<Item = PacketStatusSymbol> {
    fn num_status_symbols(&self) -> usize;
}

impl PacketStatusChunk for SomePacketStatusChunk {
    fn num_status_symbols(&self) -> usize {
        match self {
            SomePacketStatusChunk::RleChunk(rle) => rle.run_length,
            SomePacketStatusChunk::SvChunk(sv) => sv.symbols.len(),
        }
    }
}

/// ```text
/// A run length chunk starts with 0 bit, followed by a packet status
/// symbol and the run length of that symbol.
///
///     0                   1
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |T| S |       Run Length        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// chunk type (T):  1 bit A zero identifies this as a run length chunk.
///
/// packet status symbol (S):  2 bits The symbol repeated in this run.
///             See above.
///
/// run length (L):  13 bits An unsigned integer denoting the run length.
/// ```
fn parse_run_length_packet_status_chunk_from_u16(chunk: u16) -> Result<RleChunk> {
    let symbol: PacketStatusSymbol = (((chunk & 0b01100000_00000000) >> 13) as u8).try_into()?;
    let run_length = (chunk & 0b00011111_11111111) as usize;
    Ok(RleChunk { symbol, run_length })
}

/// ```text
/// A status vector chunk starts with a 1 bit to identify it as a vector
/// chunk, followed by a symbol size bit and then 7 or 14 symbols,
/// depending on the size bit.
///
///      0                   1
///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |T|S|       symbol list         |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// chunk type (T):  1 bit A one identifies this as a status vector
///             chunk.
///
/// symbol size (S):  1 bit A zero means this vector contains only
///             "packet received" (0) and "packet not received" (1)
///             symbols.  This means we can compress each symbol to just
///             one bit, 14 in total.  A one means this vector contains
///             the normal 2-bit symbols, 7 in total.
///
/// symbol list:  14 bits A list of packet status symbols, 7 or 14 in
///             total.
/// ```
fn parse_status_vector_chunk_from_u16(chunk: u16, max_symbol_count: usize) -> Result<SvChunk> {
    let mut chunk = chunk;
    let symbol_size = (chunk & 0b01000000_00000000) >> 14;
    let mut symbols = match symbol_size {
        0 => {
            // 1 bit symbols
            let mut symbols: Vec<PacketStatusSymbol> = vec![PacketStatusSymbol::NotReceived; 14];
            let mask = 0b1;

            // Parse all the symbols...we'll chop some off the end later if the chunk wasn't 'full'
            for i in (0..14).rev() {
                let symbol: PacketStatusSymbol = ((chunk & mask) as u8).try_into()?;
                chunk >>= 1;
                symbols[i] = symbol;
            }
            symbols
        }
        1 => {
            // 2 bit symbols
            let mut symbols: Vec<PacketStatusSymbol> = vec![PacketStatusSymbol::NotReceived; 7];
            let mask = 0b11;

            // Parse all the symbols...we'll chop some off the end later if the chunk wasn't 'full'
            for i in (0..7).rev() {
                let symbol: PacketStatusSymbol = ((chunk & mask) as u8).try_into()?;
                chunk >>= 2;
                symbols[i] = symbol;
            }
            symbols
        }
        s @ _ => return Err(InvalidSymbolSize(s as u8).into()),
    };
    // Now truncate the symbols to size, if needed
    symbols.truncate(max_symbol_count);
    Ok(SvChunk { symbols })
}

fn parse_packet_status_chunk_from_u16(
    data: u16,
    max_symbol_count: usize,
) -> Result<SomePacketStatusChunk> {
    let chunk_type = (data & 0x8000) >> 15;
    match chunk_type {
        0 => {
            // rle
            Ok(SomePacketStatusChunk::RleChunk(
                parse_run_length_packet_status_chunk_from_u16(data).context("rle chunk")?,
            ))
        }
        1 => {
            // sv
            Ok(SomePacketStatusChunk::SvChunk(
                parse_status_vector_chunk_from_u16(data, max_symbol_count).context("sv chunk")?,
            ))
        }
        _ => todo!(),
    }
}

#[derive(Debug, PartialEq)]
pub enum PacketReport {
    UnreceivedPacket { seq_num: u16 },
    ReceivedPacketSmallDelta { seq_num: u16, delta_ticks: u8 },
    ReceivedPacketLargeOrNegativeDelta { seq_num: u16, delta_ticks: i16 },
}

/// https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01#section-3.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|  FMT=15 |    PT=205     |           length              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     SSRC of packet sender                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      SSRC of media source                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      base sequence number     |      packet status count      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 reference time                | fb pkt. count |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          packet chunk         |         packet chunk          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                                                               .
/// .                                                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         packet chunk          |  recv delta   |  recv delta   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                                                               .
/// .                                                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           recv delta          |  recv delta   | zero padding  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// packet status count:  16 bits The number of packets this feedback
///  contains status for, starting with the packet identified
///  by the base sequence number.
///
/// feedback packet count:  8 bits A counter incremented by one for each
///  feedback packet sent.  Used to detect feedback packet
///  losses.
#[derive(Debug)]
pub struct RtcpFbTccPacket {
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    packet_reports: Vec<PacketReport>,
}

impl RtcpFbTccPacket {
    pub const FMT: u8 = 15;
}
pub fn parse_rtcp_fb_tcc<B: PacketBuffer>(
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
    buf: &mut B,
) -> Result<RtcpFbTccPacket> {
    let packet_reports = parse_tcc_payload(buf)?;
    Ok(RtcpFbTccPacket {
        header,
        fb_header,
        packet_reports,
    })
}

fn parse_tcc_payload<B: PacketBuffer>(buf: &mut B) -> Result<Vec<PacketReport>> {
    let base_seq_num = buf.read_u16::<NetworkEndian>().context("base seq num")?;
    let packet_status_count = buf
        .read_u16::<NetworkEndian>()
        .context("packet status count")? as usize;
    let _reference_time = buf.read_u24::<NetworkEndian>().context("reference time")?;
    let feedback_packet_count = buf.read_u8().context("feedback packet count")?;

    let mut num_status_remaining = packet_status_count as usize;

    // while there are still statuses to be parsed, parse the next packet chunk
    let mut chunks: Vec<SomePacketStatusChunk> = Vec::with_capacity(packet_status_count as usize);
    while num_status_remaining > 0 {
        let chunk_data = buf.read_u16::<NetworkEndian>().context("chunk data")?;
        let chunk = parse_packet_status_chunk_from_u16(chunk_data, num_status_remaining)?;
        num_status_remaining -= chunk.num_status_symbols();
        chunks.push(chunk);
    }

    let mut curr_seq_num = base_seq_num;
    let mut packet_reports: Vec<PacketReport> = Vec::with_capacity(feedback_packet_count as usize);
    for chunk in chunks {
        for symbol in chunk {
            match symbol.delta_size() {
                0 => packet_reports.push(UnreceivedPacket {
                    seq_num: curr_seq_num,
                }),
                1 => packet_reports.push(ReceivedPacketSmallDelta {
                    seq_num: curr_seq_num,
                    delta_ticks: buf.read_u8()?,
                }),
                2 => packet_reports.push(ReceivedPacketLargeOrNegativeDelta {
                    seq_num: curr_seq_num,
                    delta_ticks: buf.read_u16::<NetworkEndian>().context("delta ticks")? as i16,
                }),
                s @ _ => unreachable!("Got a TCC delta size of {}", s),
            };
            curr_seq_num = curr_seq_num.wrapping_add(1);
        }
    }
    consume_padding(buf);
    Ok(packet_reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytebuffer::{byte_buffer_cursor::ByteBufferCursor, sized_buffer::SizedByteBuffer};
    use PacketStatusSymbol::{NotReceived, ReceivedLargeOrNegativeDelta, ReceivedSmallDelta};

    #[test]
    fn test_parse_sv_chunk() {
        // SV, 2 bit symbols: LD, SD, SD
        let data: u16 = 0b11_10_01_01_00_00_00_00;
        let sv_chunk = parse_status_vector_chunk_from_u16(data, 3).unwrap();
        assert_eq!(sv_chunk.symbols.len(), 3);
        assert_eq!(sv_chunk.symbols[0], ReceivedLargeOrNegativeDelta);
        assert_eq!(sv_chunk.symbols[1], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[2], ReceivedSmallDelta);

        // SV, 2 bit symbols: LD, SD, SD, SD, SD, LD, SD
        let data: u16 = 0b11_10_01_01_01_01_10_01;
        let sv_chunk = parse_status_vector_chunk_from_u16(data, 10).unwrap();
        assert_eq!(sv_chunk.symbols.len(), 7);
        assert_eq!(sv_chunk.symbols[0], ReceivedLargeOrNegativeDelta);
        assert_eq!(sv_chunk.symbols[1], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[2], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[3], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[4], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[5], ReceivedLargeOrNegativeDelta);
        assert_eq!(sv_chunk.symbols[6], ReceivedSmallDelta);

        // SV, 1 bit symbols: NR, SD, NR, NR, SD
        let data: u16 = 0b10_0_1_0_0_1_0_0_0_0_0_0_0_0_0;
        let sv_chunk = parse_status_vector_chunk_from_u16(data, 5).unwrap();
        assert_eq!(sv_chunk.symbols.len(), 5);
        assert_eq!(sv_chunk.symbols[0], NotReceived);
        assert_eq!(sv_chunk.symbols[1], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[2], NotReceived);
        assert_eq!(sv_chunk.symbols[3], NotReceived);
        assert_eq!(sv_chunk.symbols[4], ReceivedSmallDelta);

        // SV, 1 bit symbols: NR, SD, NR, NR, SD, SD, SD, SD, NR, NR, NR, SD, SD, SD
        let data: u16 = 0b10_0_1_0_0_1_1_1_1_0_0_0_1_1_1;
        let sv_chunk = parse_status_vector_chunk_from_u16(data, 20).unwrap();
        assert_eq!(sv_chunk.symbols.len(), 14);
        assert_eq!(sv_chunk.symbols[0], NotReceived);
        assert_eq!(sv_chunk.symbols[1], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[2], NotReceived);
        assert_eq!(sv_chunk.symbols[3], NotReceived);
        assert_eq!(sv_chunk.symbols[4], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[5], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[6], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[7], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[8], NotReceived);
        assert_eq!(sv_chunk.symbols[9], NotReceived);
        assert_eq!(sv_chunk.symbols[10], NotReceived);
        assert_eq!(sv_chunk.symbols[11], ReceivedSmallDelta);
        assert_eq!(sv_chunk.symbols[12], ReceivedSmallDelta);
    }

    #[test]
    fn test_parse_rle_chunk() {
        // RLE, SD, 200 run length
        let data: u16 = 0b0_01_0000011001000;
        let rle_chunk = parse_run_length_packet_status_chunk_from_u16(data).unwrap();
        assert_eq!(rle_chunk.run_length, 200);
        assert_eq!(rle_chunk.symbol, ReceivedSmallDelta);
    }

    #[test]
    fn test_parse_packet_status_chunk() {
        // SV, 2 bit symbols: LD, SD, SD
        let data: u16 = 0b11_10_01_01_00_00_00_00;

        let res = parse_packet_status_chunk_from_u16(data, 3).unwrap();
        assert_eq!(res.num_status_symbols(), 3);
        assert!(matches!(res, SomePacketStatusChunk::SvChunk(..)));

        // RLE, SD, 200 run length
        let data: u16 = 0b0_01_0000011001000;
        let res = parse_packet_status_chunk_from_u16(data, 500).unwrap();
        assert_eq!(res.num_status_symbols(), 200);
        assert!(matches!(res, SomePacketStatusChunk::RleChunk(..)));
    }

    #[test]
    fn test_parse_entire_payload() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let data: Vec<u8> = vec![
            // Base seq num = 0xFFFA, packet status count = 9
            0xFF, 0xFA, 0x00, 0x09,
            // Reference time = 1683633 (107752512ms), feedpack packet count = 87
            0x19, 0xB0, 0xB1, 0x57,
            // Chunks
            // RLE, SD, length = 9,
            0x20, 0x09,
            // Deltas (9), one byte each
            0xD8, 0x00,
            0x18, 0x14, 0x18, 0x14,
            0x18, 0x14, 0x18,
            // Recv delta padding
            0x00
        ];
        let mut buf = ByteBufferCursor::new(data);
        let tcc = parse_tcc_payload(&mut buf).unwrap();
        assert_eq!(tcc.len(), 9);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        let expected: Vec<PacketReport> = vec![
            ReceivedPacketSmallDelta {
                seq_num: 65530,
                delta_ticks: 216,
            },
            ReceivedPacketSmallDelta {
                seq_num: 65531,
                delta_ticks: 0,
            },
            ReceivedPacketSmallDelta {
                seq_num: 65532,
                delta_ticks: 24,
            },
            ReceivedPacketSmallDelta {
                seq_num: 65533,
                delta_ticks: 20,
            },
            ReceivedPacketSmallDelta {
                seq_num: 65534,
                delta_ticks: 24,
            },
            ReceivedPacketSmallDelta {
                seq_num: 65535,
                delta_ticks: 20,
            },
            ReceivedPacketSmallDelta {
                seq_num: 0,
                delta_ticks: 24,
            },
            ReceivedPacketSmallDelta {
                seq_num: 1,
                delta_ticks: 20,
            },
            ReceivedPacketSmallDelta {
                seq_num: 2,
                delta_ticks: 24,
            },
        ];
        assert_eq!(tcc, expected);
        assert_eq!(buf.bytes_remaining(), 0);
    }
}
