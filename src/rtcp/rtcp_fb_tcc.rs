use parsely_rs::*;

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

    pub fn payload_length_bytes(&self) -> usize {
        todo!()
    }
}

impl<B: BitBuf> ParselyRead<B> for RtcpFbTccPacket {
    type Ctx = (RtcpHeader, RtcpFbHeader);

    fn read<T: ByteOrder>(buf: &mut B, (header, fb_header): Self::Ctx) -> ParselyResult<Self> {
        let base_seq_num = buf.get_u16::<T>().context("Reading field 'base_seq_num'")?;
        let packet_status_count = buf
            .get_u16::<T>()
            .context("Reading field 'packet_status_count'")?;
        let reference_time = buf
            .get_u24::<T>()
            .context("Reading field 'reference_time'")?;
        let feedback_packet_count = buf
            .get_u8()
            .context("Reading field 'feedback_packet_count'")?;

        let mut num_status_remaining = packet_status_count;
        let mut chunks: Vec<SomePacketStatusChunk> = vec![];
        while num_status_remaining > 0 {
            let chunk = SomePacketStatusChunk::read::<T>(buf, (num_status_remaining as usize,))
                .context("packet status chunk")?;
            num_status_remaining -= chunk.num_symbols();
            chunks.push(chunk);
        }
        let mut packet_reports: Vec<PacketReport> = Vec::new();
        let mut curr_seq_num = base_seq_num;
        for chunk in &chunks {
            for status_symbol in chunk.iter() {
                match status_symbol.delta_size_bytes() {
                    0 => packet_reports.push(PacketReport::UnreceivedPacket {
                        seq_num: curr_seq_num,
                    }),
                    1 => {
                        let delta_ticks = buf
                            .get_u8()
                            .with_context(|| format!("delta ticks for packet {curr_seq_num}"))?;
                        packet_reports.push(PacketReport::ReceivedPacketSmallDelta {
                            seq_num: curr_seq_num,
                            delta_ticks,
                        })
                    }
                    2 => {
                        let delta_ticks = buf
                            .get_u16::<T>()
                            .with_context(|| format!("delta ticks for packet {curr_seq_num}"))?
                            as i16;
                        packet_reports.push(PacketReport::ReceivedPacketLargeOrNegativeDelta {
                            seq_num: curr_seq_num,
                            delta_ticks,
                        })
                    }
                    delta_size_bytes => bail!("Invalid delta size: {delta_size_bytes} bytes"),
                }
                curr_seq_num = curr_seq_num.wrapping_add(1);
            }
        }
        Ok(RtcpFbTccPacket {
            header,
            fb_header,
            packet_reports,
            reference_time,
            feedback_packet_count,
        })
    }
}

impl<B: BitBufMut> ParselyWrite<B> for RtcpFbTccPacket {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        self.header.write::<T>(buf, ()).context("header")?;
        self.fb_header.write::<T>(buf, ()).context("fb header")?;

        if self.packet_reports.is_empty() {
            return Ok(());
        }
        let base_seq_num = self.packet_reports[0].seq_num();
        let packet_status_count = self.packet_reports.len() as u16;
        buf.put_u16::<T>(base_seq_num).context("base_seq_num")?;
        buf.put_u16::<T>(packet_status_count)
            .context("packet_status_count")?;
        buf.put_u24::<T>(self.reference_time)
            .context("reference_time")?;
        buf.put_u8(self.feedback_packet_count)
            .context("feedback_packet_count")?;
        todo!()
    }
}

impl StateSync for RtcpFbTccPacket {
    type SyncCtx = ();

    fn sync(&mut self, _sync_ctx: Self::SyncCtx) -> ParselyResult<()> {
        self.header
            .sync((self.payload_length_bytes() as u16, Self::FMT))?;

        self.packet_reports.sort_by_key(|pr| pr.seq_num());

        Ok(())
    }
}

// #[derive(Debug)]
// enum SomeRecvDelta {
//     Small(u8),
//     LargeOrNegative(i16),
// }

// fn write_some_recv_delta<B: BitBufMut>(buf: &mut B, delta: SomeRecvDelta) -> Result<()> {
//     match delta {
//         SomeRecvDelta::Small(d) => Ok(buf.write_u8(d)?),
//         // TODO: need support for writing a signed int here
//         SomeRecvDelta::LargeOrNegative(d) => Ok(buf.write_u16::<NetworkOrder>(d as u16)?),
//     }
// }
//
// fn write_rtcp_fb_tcc<B: BitBufMut>(buf: &mut B, fb_tcc: &RtcpFbTccPacket) -> Result<()> {
//     write_rtcp_header(buf, &fb_tcc.header).context("rtcp header")?;
//     write_rtcp_fb_header(buf, &fb_tcc.fb_header).context("fb header")?;
//
//     write_rtcp_fb_tcc_data(buf, &fb_tcc.packet_reports, fb_tcc.reference_time)
//         .context("fb tcc data")?;
//
//     Ok(())
// }
//
// /// Write the FB TCC packet data.  Note that `packet_reports` should be a _continuous_ set of
// /// reports: all NotReceived values should have already been inserted.
// fn write_rtcp_fb_tcc_data<B: BitBufMut>(
//     buf: &mut B,
//     packet_reports: &[PacketReport],
//     reference_time: u24,
// ) -> Result<()> {
//     let base_seq_num = packet_reports[0].seq_num();
//     buf.write_u16::<NetworkOrder>(base_seq_num)
//         .context("base seq num")?;
//     buf.write_u16::<NetworkOrder>(packet_reports.len() as u16)
//         .context("packet status count")?;
//     buf.write_u24::<NetworkOrder>(reference_time)
//         .context("reference time")?;
//
//     let (feedback_packet_count, chunks, deltas) = prepare_packet_reports(&packet_reports);
//     buf.write_u8(feedback_packet_count)
//         .context("feedback packet count")?;
//
//     for chunk in chunks {
//         write_some_packet_status_chunk(chunk, buf).context("packet status chunk")?;
//     }
//
//     for delta in deltas {
//         write_some_recv_delta(buf, delta).context("delta")?;
//     }
//
//     Ok(())
// }
//
// fn prepare_packet_reports(
//     packet_reports: &[PacketReport],
// ) -> (u8, Vec<SomePacketStatusChunk>, Vec<SomeRecvDelta>) {
//     let mut expected_seq_num = packet_reports[0].seq_num();
//     let mut chunks: Vec<SomePacketStatusChunk> = vec![];
//     let mut deltas: Vec<SomeRecvDelta> = vec![];
//     let mut curr_chunk = Chunk::default();
//     let mut seq_num_count = 0u8;
//     for packet_report in packet_reports {
//         while expected_seq_num != packet_report.seq_num() {
//             if !curr_chunk.can_add(PacketStatusSymbol::NotReceived) {
//                 chunks.push(curr_chunk.emit());
//             }
//             curr_chunk.add(PacketStatusSymbol::NotReceived);
//             expected_seq_num = expected_seq_num.wrapping_add(1);
//             seq_num_count = seq_num_count.wrapping_add(1);
//         }
//
//         if !curr_chunk.can_add(packet_report.symbol()) {
//             chunks.push(curr_chunk.emit());
//         }
//         match packet_report {
//             PacketReport::UnreceivedPacket { .. } => (),
//             PacketReport::ReceivedPacketSmallDelta { delta_ticks, .. } => {
//                 deltas.push(SomeRecvDelta::Small(*delta_ticks))
//             }
//             PacketReport::ReceivedPacketLargeOrNegativeDelta { delta_ticks, .. } => {
//                 deltas.push(SomeRecvDelta::LargeOrNegative(*delta_ticks))
//             }
//         }
//
//         expected_seq_num = expected_seq_num.wrapping_add(1);
//         seq_num_count = seq_num_count.wrapping_add(1);
//     }
//     chunks.push(curr_chunk.emit());
//
//     (seq_num_count, chunks, deltas)
// }

#[derive(Debug, PartialEq)]
pub enum PacketReport {
    UnreceivedPacket { seq_num: u16 },
    ReceivedPacketSmallDelta { seq_num: u16, delta_ticks: u8 },
    ReceivedPacketLargeOrNegativeDelta { seq_num: u16, delta_ticks: i16 },
}

impl PacketReport {
    pub fn seq_num(&self) -> u16 {
        match self {
            Self::UnreceivedPacket { seq_num } => *seq_num,
            Self::ReceivedPacketSmallDelta { seq_num, .. } => *seq_num,
            Self::ReceivedPacketLargeOrNegativeDelta { seq_num, .. } => *seq_num,
        }
    }

    pub fn symbol(&self) -> PacketStatusSymbol {
        match self {
            PacketReport::UnreceivedPacket { .. } => PacketStatusSymbol::NotReceived,
            PacketReport::ReceivedPacketSmallDelta { .. } => PacketStatusSymbol::ReceivedSmallDelta,
            PacketReport::ReceivedPacketLargeOrNegativeDelta { .. } => {
                PacketStatusSymbol::ReceivedLargeOrNegativeDelta
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PacketStatusSymbol {
    NotReceived = 0,
    ReceivedSmallDelta = 1,
    ReceivedLargeOrNegativeDelta = 2,
}

impl PacketStatusSymbol {
    // pub(crate) fn from_delta_size(delta_size: u8) -> Self {
    //     match delta_size {
    //         0 => PacketStatusSymbol::NotReceived,
    //         1 => PacketStatusSymbol::ReceivedSmallDelta,
    //         2 => PacketStatusSymbol::ReceivedLargeOrNegativeDelta,
    //         _ => todo!("invalid"),
    //     }
    // }

    pub(crate) fn delta_size_bytes(&self) -> u8 {
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

impl TryInto<u1> for &PacketStatusSymbol {
    type Error = anyhow::Error;

    fn try_into(self) -> std::prelude::v1::Result<u1, Self::Error> {
        match self {
            PacketStatusSymbol::NotReceived => Ok(U1_ZERO),
            PacketStatusSymbol::ReceivedSmallDelta => Ok(U1_ONE),
            PacketStatusSymbol::ReceivedLargeOrNegativeDelta => Err(anyhow!(
                "PacketStatusSymbol::ReceivedLargeOrNegativeDelta can't be encoded into a u1"
            )),
        }
    }
}

impl TryInto<u1> for PacketStatusSymbol {
    type Error = anyhow::Error;

    fn try_into(self) -> std::prelude::v1::Result<u1, Self::Error> {
        (&self).try_into()
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

impl From<&PacketStatusSymbol> for u2 {
    fn from(val: &PacketStatusSymbol) -> Self {
        match val {
            PacketStatusSymbol::NotReceived => u2::new(0),
            PacketStatusSymbol::ReceivedSmallDelta => u2::new(1),
            PacketStatusSymbol::ReceivedLargeOrNegativeDelta => u2::new(2),
        }
    }
}

impl From<PacketStatusSymbol> for u2 {
    fn from(val: PacketStatusSymbol) -> Self {
        (&val).into()
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
pub struct StatusVectorChunk(pub(crate) Vec<PacketStatusSymbol>);

impl StatusVectorChunk {
    fn has_two_bit_symbols(&self) -> bool {
        self.0
            .iter()
            .any(|ss| matches!(ss, PacketStatusSymbol::ReceivedLargeOrNegativeDelta))
    }

    fn iter(&self) -> std::slice::Iter<'_, PacketStatusSymbol> {
        self.0.iter()
    }
}

/// This method assumes buf's position is at the symbol-size bit.
impl<B: BitBuf> ParselyRead<B> for StatusVectorChunk {
    type Ctx = (usize,);

    fn read<T: ByteOrder>(buf: &mut B, (max_symbol_count,): Self::Ctx) -> ParselyResult<Self> {
        let symbol_size = buf.get_u1().context("symbol size")?;
        let mut packet_status_symbols = match symbol_size {
            s if s == 0 => {
                // 1 bit symbols
                (0..14)
                    .map(|i| {
                        buf.get_u1()
                            .with_context(|| format!("packet status symbol {i}"))
                            .map(|v| v.into())
                    })
                    .collect::<ParselyResult<Vec<PacketStatusSymbol>>>()
                    .context("1 bit packet status symbols")
            }
            s if s == 1 => {
                // 2 bit symbols
                (0..7)
                    .map(|i| {
                        buf.get_u2()
                            .with_context(|| format!("packet status symbol {i}"))?
                            .try_into()
                            .context("converting u2 to packet status symbol")
                    })
                    .collect::<ParselyResult<Vec<PacketStatusSymbol>>>()
                    .context("2 bit packet status symbols")
            }
            _ => unreachable!("u1 can only be 1 or 0"),
        }
        .context("Packet status symbols")?;

        packet_status_symbols.truncate(max_symbol_count);

        Ok(StatusVectorChunk(packet_status_symbols))
    }
}

impl<B: BitBufMut> ParselyWrite<B> for StatusVectorChunk {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        buf.put_u1(u1::new(1)).context("SV chunk type")?;
        if self.has_two_bit_symbols() {
            buf.put_u1(u1::new(1)).context("SV chunk symbol size")?;
            for (i, symbol) in self.iter().enumerate() {
                buf.put_u2(symbol.into())
                    .with_context(|| format!("2 bit sv chunk symbol {i}"))?;
            }
        } else {
            buf.put_u1(u1::new(0)).context("SV chunk symbol size")?;
            for (i, symbol) in self.iter().enumerate() {
                buf.put_u1(
                    symbol
                        .try_into()
                        .context("Trying to convert status symbol to u1")?,
                )
                .with_context(|| format!("2 bit sv chunk symbol {i}"))?;
            }
        }
        Ok(())
    }
}

impl_stateless_sync!(StatusVectorChunk);

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

/// Assumes the buf's position is at the packet status symbol bit
impl<B: BitBuf> ParselyRead<B> for RunLengthEncodingChunk {
    type Ctx = ();

    fn read<T: ByteOrder>(buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<Self> {
        let symbol = buf
            .get_u2()
            .context("Reading run length encoding symbol")?
            .try_into()
            .context("Converting u2 to packet status symbol")?;

        let run_length = buf.get_u13::<T>().context("Reading run length")?;

        Ok(RunLengthEncodingChunk { symbol, run_length })
    }
}

impl<B: BitBufMut> ParselyWrite<B> for RunLengthEncodingChunk {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        buf.put_u1(u1::new(0)).context("rle chunk type")?;
        buf.put_u2(self.symbol.into()).context("rle chunk symbol")?;
        buf.put_u13::<T>(self.run_length)
            .context("rle chunk run length")?;

        Ok(())
    }
}

impl_stateless_sync!(RunLengthEncodingChunk);

#[derive(Debug, Clone)]
pub(crate) enum SomePacketStatusChunk {
    StatusVectorChunk(StatusVectorChunk),
    RunLengthEncodingChunk(RunLengthEncodingChunk),
}

pub(crate) enum SomePacketStatusChunkIterator<'a> {
    StatusVector(std::slice::Iter<'a, PacketStatusSymbol>),
    RunLength(std::iter::Repeat<PacketStatusSymbol>, usize), // (iter, remaining count)
}

impl Iterator for SomePacketStatusChunkIterator<'_> {
    type Item = PacketStatusSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SomePacketStatusChunkIterator::StatusVector(iter) => iter.next().copied(),
            SomePacketStatusChunkIterator::RunLength(iter, remaining) => {
                if *remaining == 0 {
                    None
                } else {
                    *remaining -= 1;
                    iter.next()
                }
            }
        }
    }
}

impl SomePacketStatusChunk {
    pub(crate) fn num_symbols(&self) -> u16 {
        match self {
            SomePacketStatusChunk::StatusVectorChunk(svc) => svc.0.len() as u16,
            SomePacketStatusChunk::RunLengthEncodingChunk(rlec) => rlec.run_length.into(),
        }
    }

    pub fn iter(&self) -> SomePacketStatusChunkIterator<'_> {
        match self {
            SomePacketStatusChunk::StatusVectorChunk(StatusVectorChunk(vec)) => {
                SomePacketStatusChunkIterator::StatusVector(vec.iter())
            }
            SomePacketStatusChunk::RunLengthEncodingChunk(chunk) => {
                SomePacketStatusChunkIterator::RunLength(
                    std::iter::repeat(chunk.symbol),
                    chunk.run_length.into(),
                )
            }
        }
    }
}

impl<B: BitBuf> ParselyRead<B> for SomePacketStatusChunk {
    type Ctx = (usize,);

    fn read<T: ByteOrder>(buf: &mut B, (max_symbol_count,): Self::Ctx) -> ParselyResult<Self> {
        let chunk_type = buf.get_u1().context("chunk type")?;
        match chunk_type {
            ct if ct == 0 => RunLengthEncodingChunk::read::<T>(buf, ())
                .map(SomePacketStatusChunk::RunLengthEncodingChunk)
                .context("run length encoding chunk"),
            ct if ct == 1 => StatusVectorChunk::read::<T>(buf, (max_symbol_count,))
                .map(SomePacketStatusChunk::StatusVectorChunk)
                .context("status vector chunk"),
            _ => unreachable!(),
        }
    }
}

impl<B: BitBufMut> ParselyWrite<B> for SomePacketStatusChunk {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        match self {
            SomePacketStatusChunk::RunLengthEncodingChunk(rle_chunk) => {
                rle_chunk.write::<T>(buf, ())?
            }
            SomePacketStatusChunk::StatusVectorChunk(sv_chunk) => sv_chunk.write::<T>(buf, ())?,
        }
        Ok(())
    }
}

impl_stateless_sync!(SomePacketStatusChunk);

#[cfg(test)]
mod test {
    use super::*;
    use bits_io::prelude::*;

    #[test]
    fn test_sv_chunk_1_bit_symbols() {
        let chunk_data = bits!(1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1);
        let mut bits = Bits::copy_from_bit_slice(chunk_data);
        // Advance past the chunk type bit since we're calling StatusVectorChunk::read directly and
        // it assumes that bit has already been read
        bits.advance_bits(1);

        let sv_chunk = StatusVectorChunk::read::<NetworkOrder>(&mut bits, (14,)).unwrap();

        assert_eq!(sv_chunk.0.len(), 14);
        assert!(bits.is_empty());
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

        let mut bits_mut = BitsMut::new();
        sv_chunk.write::<NetworkOrder>(&mut bits_mut, ()).unwrap();
        assert_eq!(chunk_data, bits_mut.as_ref());
    }

    #[test]
    fn test_sv_chunk_1_bit_symbols_with_limit() {
        let mut chunk_data = bits!(0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1);

        let sv_chunk = StatusVectorChunk::read::<NetworkOrder>(&mut chunk_data, (3,)).unwrap();
        assert_eq!(sv_chunk.0.len(), 3);
        assert!(chunk_data.is_empty());
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
        let chunk_data = bits!(1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0);
        let mut bits = Bits::copy_from_bit_slice(chunk_data);
        bits.advance_bits(1);

        let sv_chunk = StatusVectorChunk::read::<NetworkOrder>(&mut bits, (15,)).unwrap();
        assert_eq!(sv_chunk.0.len(), 7);
        assert!(bits.is_empty());
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

        let mut bits_mut = BitsMut::new();
        sv_chunk.write::<NetworkOrder>(&mut bits_mut, ()).unwrap();
        assert_eq!(chunk_data, bits_mut.as_ref());
    }

    #[test]
    fn test_rle_chunk() {
        let chunk_data = bits!(0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1);
        let mut bits = Bits::copy_from_bit_slice(chunk_data);
        bits.advance_bits(1);

        let rle_chunk = RunLengthEncodingChunk::read::<NetworkOrder>(&mut bits, ()).unwrap();
        assert!(bits.is_empty());
        assert_eq!(rle_chunk.symbol, PacketStatusSymbol::ReceivedSmallDelta);
        assert_eq!(rle_chunk.run_length, 0b0000000010101);

        let mut bits_mut = BitsMut::new();
        rle_chunk.write::<NetworkOrder>(&mut bits_mut, ()).unwrap();
        assert_eq!(chunk_data, bits_mut.as_ref());
    }

    #[test]
    fn test_rtcp_fb_tcc_packet() {
        #[rustfmt::skip]
        let data_buf = [
            0x01, 0x81, 0x00, 0x08, 0x19, 0xae, 0xe8, 0x45,
            0xd9, 0x55, 0x20, 0x01, 0xa8, 0xff, 0xfc, 0x04,
            0x00, 0x50, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        let mut bits = Bits::copy_from_bytes(&data_buf[..]);
        let tcc_packet = RtcpFbTccPacket::read::<NetworkOrder>(
            &mut bits,
            (RtcpHeader::default(), RtcpFbHeader::default()),
        )
        .unwrap();
        assert_eq!(tcc_packet.reference_time, u24::new(1683176));
        assert_eq!(tcc_packet.feedback_packet_count, 69);
        assert_eq!(
            tcc_packet.packet_reports,
            [
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 385,
                    delta_ticks: 168,
                },
                PacketReport::ReceivedPacketLargeOrNegativeDelta {
                    seq_num: 386,
                    delta_ticks: -4,
                },
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 387,
                    delta_ticks: 4,
                },
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 388,
                    delta_ticks: 0,
                },
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 389,
                    delta_ticks: 80,
                },
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 390,
                    delta_ticks: 4,
                },
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 391,
                    delta_ticks: 0,
                },
                PacketReport::ReceivedPacketSmallDelta {
                    seq_num: 392,
                    delta_ticks: 0,
                },
            ]
        );
    }

    //
    // #[test]
    // fn test_read_tcc_fb_data() {
    //     #[rustfmt::skip]
    //     let data_buf = [
    //         0x01, 0x81, 0x00, 0x08, 0x19, 0xae, 0xe8, 0x45,
    //         0xd9, 0x55, 0x20, 0x01, 0xa8, 0xff, 0xfc, 0x04,
    //         0x00, 0x50, 0x04, 0x00, 0x00, 0x00, 0x00, 00
    //     ];
    //     let mut cursor = BitCursor::new(BitVec::<u8, Msb0>::from_slice(&data_buf));
    //     let (packet_reports, reference_time, feedback_packet_count) =
    //         read_rtcp_fb_tcc_data(&mut cursor).unwrap();
    //
    //     assert_eq!(reference_time, u24::new(1683176));
    //     assert_eq!(feedback_packet_count, 69);
    //     assert_eq!(
    //         packet_reports,
    //         [
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 385,
    //                 delta_ticks: 168,
    //             },
    //             PacketReport::ReceivedPacketLargeOrNegativeDelta {
    //                 seq_num: 386,
    //                 delta_ticks: -4,
    //             },
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 387,
    //                 delta_ticks: 4,
    //             },
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 388,
    //                 delta_ticks: 0,
    //             },
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 389,
    //                 delta_ticks: 80,
    //             },
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 390,
    //                 delta_ticks: 4,
    //             },
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 391,
    //                 delta_ticks: 0,
    //             },
    //             PacketReport::ReceivedPacketSmallDelta {
    //                 seq_num: 392,
    //                 delta_ticks: 0,
    //             },
    //         ]
    //     );
    //     dbg!(packet_reports);
    // }
}
