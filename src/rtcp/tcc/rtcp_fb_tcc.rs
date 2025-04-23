use anyhow::{Context, Result};
use bit_cursor::{
    bit_read_exts::BitReadExts, bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
    nsw_types::*,
};

use crate::{
    rtcp::{
        rtcp_fb_header::RtcpFbHeader, rtcp_fb_tcc::SomePacketStatusChunk, rtcp_header::RtcpHeader,
    },
    BitBuf, BitBufMut,
};

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
pub struct RtcpFbTccPacket2 {
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
    pub chunks: Vec<SomePacketStatusChunk>,
    pub deltas: Vec<SomeRecvDelta>,
    pub reference_time: u24,
    pub feedback_packet_count: u8,
}

impl RtcpFbTccPacket2 {
    pub const FMT: u5 = u5::new(15);
}

pub fn read_rtcp_fb_tcc2<B: BitBuf>(
    buf: &mut B,
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
) -> Result<RtcpFbTccPacket2> {
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

    todo!()
}

#[derive(Debug)]
enum SomeRecvDelta {
    Small(u8),
    LargeOrNegative(i16),
}

fn write_some_recv_delta<B: BitBufMut>(buf: &mut B, delta: SomeRecvDelta) -> Result<()> {
    match delta {
        SomeRecvDelta::Small(d) => {
            let write_u8 = buf.write_u8(d);
            Ok(write_u8?)
        }
        // TODO: need support for writing a signed int here
        SomeRecvDelta::LargeOrNegative(d) => Ok(buf.write_u16::<NetworkOrder>(d as u16)?),
    }
}
