use anyhow::{anyhow, bail, Context, Result};
use bitcursor::{bit_read_exts::BitReadExts, byte_order::NetworkOrder, ux::*};

use crate::{util::consume_padding, PacketBuffer};

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

const U1_ZERO: u1 = u1::new(0);
const U1_ONE: u1 = u1::new(1);
const U2_ZERO: u2 = u2::new(0);
const U2_ONE: u2 = u2::new(1);
const U2_TWO: u2 = u2::new(2);

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
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
    pub packet_reports: Vec<PacketReport>,
    pub reference_time: u24,
    pub feedback_packet_count: u8,
}

impl RtcpFbTccPacket {
    pub const FMT: u5 = u5::new(15);
}

pub fn read_rtcp_fb_tcc<B: PacketBuffer>(
    buf: &mut B,
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
) -> Result<RtcpFbTccPacket> {
    let base_seq_num = buf.read_u16::<NetworkOrder>().context("base seq num")?;
    let packet_status_count = buf
        .read_u16::<NetworkOrder>()
        .context("packet status count")?;
    let reference_time = buf.read_u24::<NetworkOrder>().context("reference time")?;
    let feedback_packet_count = buf.read_u8().context("feedback packet count")?;

    let mut num_status_remaining = packet_status_count;

    let mut chunks: Vec<SomePacketStatusChunk> = Vec::new();
    while num_status_remaining > 0 {
        let chunk = read_some_packet_status_chunk(buf, num_status_remaining as usize)
            .context("packet status chunk")?;
        num_status_remaining -= chunk.num_symbols();
        chunks.push(chunk);
    }
    let mut curr_seq_num = base_seq_num;
    let mut packet_reports: Vec<PacketReport> = Vec::new();
    for chunk in chunks {
        for status_symbol in chunk {
            match status_symbol.delta_size_bytes() {
                0 => packet_reports.push(PacketReport::UnreceivedPacket {
                    seq_num: curr_seq_num,
                }),
                1 => {
                    let delta_ticks = buf
                        .read_u8()
                        .with_context(|| format!("delta ticks for packet {curr_seq_num}"))?;
                    packet_reports.push(PacketReport::ReceivedPacketSmallDelta {
                        seq_num: curr_seq_num,
                        delta_ticks,
                    });
                }
                2 => {
                    // TODO: will the 'as' cast handle the negative delta correctly?
                    let delta_ticks = buf
                        .read_u16::<NetworkOrder>()
                        .with_context(|| format!("delta ticks for packet {curr_seq_num}"))?
                        as i16;
                    packet_reports.push(PacketReport::ReceivedPacketLargeOrNegativeDelta {
                        seq_num: curr_seq_num,
                        delta_ticks,
                    });
                }
                delta_size_bytes => bail!("Invalid delta size: {delta_size_bytes} bytes"),
            }
            curr_seq_num = curr_seq_num.wrapping_add(1);
        }
    }
    consume_padding(buf);
    Ok(RtcpFbTccPacket {
        header,
        fb_header,
        packet_reports,
        reference_time,
        feedback_packet_count,
    })
}

#[derive(Debug, PartialEq)]
pub enum PacketReport {
    UnreceivedPacket { seq_num: u16 },
    ReceivedPacketSmallDelta { seq_num: u16, delta_ticks: u8 },
    ReceivedPacketLargeOrNegativeDelta { seq_num: u16, delta_ticks: i16 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PacketStatusSymbol {
    NotReceived = 0,
    ReceivedSmallDelta = 1,
    ReceivedLargeOrNegativeDelta = 2,
}

impl PacketStatusSymbol {
    fn delta_size_bytes(&self) -> usize {
        match self {
            PacketStatusSymbol::NotReceived => 0,
            PacketStatusSymbol::ReceivedSmallDelta => 1,
            PacketStatusSymbol::ReceivedLargeOrNegativeDelta => 2,
        }
    }
}

impl From<u1> for PacketStatusSymbol {
    fn from(value: u1) -> Self {
        match value {
            U1_ZERO => PacketStatusSymbol::NotReceived,
            U1_ONE => PacketStatusSymbol::ReceivedSmallDelta,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<u2> for PacketStatusSymbol {
    type Error = anyhow::Error;

    fn try_from(value: u2) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            U2_ZERO => Ok(PacketStatusSymbol::NotReceived),
            U2_ONE => Ok(PacketStatusSymbol::ReceivedSmallDelta),
            U2_TWO => Ok(PacketStatusSymbol::ReceivedLargeOrNegativeDelta),
            pss => Err(anyhow!("Invalid 2 bit packet status symbol: {pss}")),
        }
    }
}

/// A status vector chunk starts with a 1 bit to identify it as a vector
/// chunk, followed by a symbol size bit and then 7 or 14 symbols,
/// depending on the size bit.
///
/// ```text
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
#[derive(Debug, Clone, PartialEq)]
pub struct StatusVectorChunk(Vec<PacketStatusSymbol>);

impl IntoIterator for StatusVectorChunk {
    type Item = PacketStatusSymbol;

    type IntoIter = <Vec<PacketStatusSymbol> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

///
/// This method assumes buf's position is at the symbol-size bit.
pub fn read_status_vector_chunk<B: PacketBuffer>(
    buf: &mut B,
    max_symbol_count: usize,
) -> Result<StatusVectorChunk> {
    let symbol_size = buf.read_u1().context("symbol size")?;
    let mut packet_status_symbols = match symbol_size {
        U1_ZERO => {
            // 1 bit symbols
            (0..14)
                .map(|i| {
                    buf.read_u1()
                        .with_context(|| format!("packet status symbol {i}"))
                        .map(|v| v.into())
                })
                .collect::<Result<Vec<PacketStatusSymbol>>>()
                .context("1 bit packet status symbols")
        }
        U1_ONE => {
            // 2 bit symbols
            (0..7)
                .map(|i| {
                    buf.read_u2()
                        .with_context(|| format!("packet status symbol {i}"))?
                        .try_into()
                        .context("converting u2 to packet status symbol")
                })
                .collect::<Result<Vec<PacketStatusSymbol>>>()
                .context("2 bit packet status symbols")
        }
        _ => unreachable!("u1 can only be 0 or 1"),
    }?;

    // Even when the number of packet status symbols is less than the entire 14 bits, we still need
    // to consume the entire chunk, so we read all the symbols above to consume the proper amount
    // of the buffer and then chop off any symbols that shouldn't actually be included here.
    packet_status_symbols.truncate(max_symbol_count);

    Ok(StatusVectorChunk(packet_status_symbols))
}

/// A run length chunk starts with 0 bit, followed by a packet status
/// symbol and the run length of that symbol.
/// ```text
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLengthEncodingChunk {
    pub symbol: PacketStatusSymbol,
    pub run_length: u13,
}

pub struct RunLengthEncodingIterator {
    symbol: PacketStatusSymbol,
    curr_idx: u32,
    length: u32,
}

impl Iterator for RunLengthEncodingIterator {
    type Item = PacketStatusSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_idx < self.length {
            self.curr_idx += 1;
            Some(self.symbol)
        } else {
            None
        }
    }
}

impl IntoIterator for RunLengthEncodingChunk {
    type Item = PacketStatusSymbol;

    type IntoIter = RunLengthEncodingIterator;

    fn into_iter(self) -> Self::IntoIter {
        RunLengthEncodingIterator {
            symbol: self.symbol,
            curr_idx: 0,
            length: self.run_length.into(),
        }
    }
}

///
/// This method assumes buf's position is at the packet status symbol bit
pub fn read_run_length_encoding_chunk<B: PacketBuffer>(
    buf: &mut B,
) -> Result<RunLengthEncodingChunk> {
    let symbol = buf
        .read_u2()
        .context("packet status symbol")?
        .try_into()
        .context("convert u2 to packet status symbol")?;
    let run_length = buf.read_u13::<NetworkOrder>().context("run length")?;

    Ok(RunLengthEncodingChunk { symbol, run_length })
}

enum SomePacketStatusChunk {
    StatusVectorChunk(StatusVectorChunk),
    RunLengthEncodingChunk(RunLengthEncodingChunk),
}

enum SomePacketStatusChunkIterator {
    RunLengthEncodingChunkIterator(RunLengthEncodingIterator),
    StatusVectorChunkIterator(<StatusVectorChunk as IntoIterator>::IntoIter),
}

impl Iterator for SomePacketStatusChunkIterator {
    type Item = PacketStatusSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SomePacketStatusChunkIterator::StatusVectorChunkIterator(i) => i.next(),
            SomePacketStatusChunkIterator::RunLengthEncodingChunkIterator(i) => i.next(),
        }
    }
}

impl SomePacketStatusChunk {
    fn num_symbols(&self) -> u16 {
        match self {
            SomePacketStatusChunk::StatusVectorChunk(svc) => svc.0.len() as u16,
            SomePacketStatusChunk::RunLengthEncodingChunk(rlec) => rlec.run_length.into(),
        }
    }
}

impl IntoIterator for SomePacketStatusChunk {
    type Item = PacketStatusSymbol;

    type IntoIter = SomePacketStatusChunkIterator;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SomePacketStatusChunk::StatusVectorChunk(svc) => {
                SomePacketStatusChunkIterator::StatusVectorChunkIterator(svc.into_iter())
            }
            SomePacketStatusChunk::RunLengthEncodingChunk(rlec) => {
                SomePacketStatusChunkIterator::RunLengthEncodingChunkIterator(rlec.into_iter())
            }
        }
    }
}

fn read_some_packet_status_chunk<B: PacketBuffer>(
    buf: &mut B,
    max_symbol_count: usize,
) -> Result<SomePacketStatusChunk> {
    let chunk_type = buf.read_u1().context("chunk type")?;
    match chunk_type {
        U1_ZERO => read_run_length_encoding_chunk(buf)
            .map(SomePacketStatusChunk::RunLengthEncodingChunk)
            .context("run length encoding chunk"),
        U1_ONE => read_status_vector_chunk(buf, max_symbol_count)
            .map(SomePacketStatusChunk::StatusVectorChunk)
            .context("status vector chunk"),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use bitcursor::bit_cursor::BitCursor;
    use bitvec::{bits, order::Msb0};

    use crate::rtcp::rtcp_fb_tcc::PacketStatusSymbol;

    use super::read_status_vector_chunk;

    #[test]
    fn test_sv_chunk_1_bit_symbols() {
        let chunk = bits!(u8, Msb0; 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1);
        let mut cursor = BitCursor::new(chunk);

        let sv_chunk = read_status_vector_chunk(&mut cursor, 14).unwrap();
        assert_eq!(sv_chunk.0.len(), 14);
        assert!(cursor.remaining_slice().is_empty());
        assert_eq!(
            sv_chunk.0,
            vec![
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedSmallDelta,
            ]
        );
    }

    #[test]
    fn test_sv_chunk_1_bit_symbols_with_limit() {
        let chunk = bits!(u8, Msb0; 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1);
        let mut cursor = BitCursor::new(chunk);

        let sv_chunk = read_status_vector_chunk(&mut cursor, 3).unwrap();
        assert_eq!(sv_chunk.0.len(), 3);
        assert!(cursor.remaining_slice().is_empty());
        assert_eq!(
            sv_chunk.0,
            vec![
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::NotReceived,
            ]
        );
    }

    #[test]
    fn test_sv_chunk_2_bit_symbols() {
        let chunk = bits!(u8, Msb0; 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0);
        let mut cursor = BitCursor::new(chunk);

        let sv_chunk = read_status_vector_chunk(&mut cursor, 14).unwrap();
        assert_eq!(sv_chunk.0.len(), 7);
        assert!(cursor.remaining_slice().is_empty());
        assert_eq!(
            sv_chunk.0,
            vec![
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedLargeOrNegativeDelta,
                PacketStatusSymbol::NotReceived,
                PacketStatusSymbol::ReceivedSmallDelta,
                PacketStatusSymbol::ReceivedLargeOrNegativeDelta,
                PacketStatusSymbol::NotReceived,
            ]
        );
    }
}

// TODO: look at packet 96 in wireshark trace and use that for a test case
