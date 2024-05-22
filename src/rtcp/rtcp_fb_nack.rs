use std::collections::BTreeSet;

use crate::{
    rtcp::{rtcp_fb_header::write_rtcp_fb_header, rtcp_header::write_rtcp_header},
    PacketBuffer, PacketBufferMut,
};
use anyhow::{anyhow, bail, Context, Result};
use bitcursor::{
    bit_read_exts::BitReadExts, bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
};

use super::{rtcp_fb_header::RtcpFbHeader, rtcp_header::RtcpHeader};

/// https://datatracker.ietf.org/doc/html/rfc4585#section-6.2.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            PID                |             BLP               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtcpFbNackPacket {
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
    pub missing_seq_nums: BTreeSet<u16>,
}

// TODO: somewhere in here we need to enforce some kind of maximum number of sequence numbers that
// can be included in a nack packet (or, a way for a nack to fail to serialize due to having more
// sequence numbers that couldn't be added to the buffer)

impl RtcpFbNackPacket {
    pub const FMT: u8 = 1;
}

pub fn read_rtcp_fb_nack<B: PacketBuffer>(
    buf: &mut B,
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
) -> Result<RtcpFbNackPacket> {
    let mut missing_seq_nums = BTreeSet::new();
    let mut nack_block_num = 1;
    while buf.bytes_remaining() >= NackBlock::SIZE_BYTES {
        let mut nack_block =
            read_nack_block(buf).with_context(|| format!("nack block {nack_block_num}"))?;
        missing_seq_nums.append(&mut nack_block.missing_seq_nums);
        nack_block_num += 1;
    }

    Ok(RtcpFbNackPacket {
        header,
        fb_header,
        missing_seq_nums,
    })
}

pub fn write_rtcp_fb_nack<B: PacketBufferMut>(
    buf: &mut B,
    fb_nack: &RtcpFbNackPacket,
) -> Result<()> {
    write_rtcp_header(buf, &fb_nack.header).context("rtcp header")?;
    write_rtcp_fb_header(buf, &fb_nack.fb_header).context("fb header")?;

    for (i, missing_packet_chunk) in fb_nack
        .missing_seq_nums
        .chunk_by_max_difference(16)
        .into_iter()
        .enumerate()
    {
        let nack_block = NackBlock {
            missing_seq_nums: missing_packet_chunk,
        };
        if buf.bytes_remaining() < NackBlock::SIZE_BYTES {
            bail!("Not enough room in buffer for nack block {i}");
        }
        write_nack_block(buf, &nack_block).with_context(|| format!("nack block {i}"))?;
    }

    Ok(())
}

pub struct NackBlock {
    // We don't use the BTreeSet here because when this type is used we're either parsing from a
    // packet, where know the order will be right (since we parse it that way), or about to
    // serialize, where we also know the order is already correct.
    missing_seq_nums: BTreeSet<u16>,
}

impl NackBlock {
    pub const SIZE_BYTES: usize = 4;
}

pub fn read_nack_block<B: PacketBuffer>(buf: &mut B) -> Result<NackBlock> {
    let packet_id = buf.read_u16::<NetworkOrder>().context("packet id")?;
    let blp = buf.read_u16::<NetworkOrder>().context("blp")?;

    let mut missing_seq_nums = BTreeSet::new();
    missing_seq_nums.insert(packet_id);
    for shift_amount in 0..16 {
        if (blp >> shift_amount) & 0x1 == 1 {
            missing_seq_nums.insert(packet_id + shift_amount + 1);
        }
    }

    Ok(NackBlock { missing_seq_nums })
}

pub fn write_nack_block<B: PacketBufferMut>(buf: &mut B, nack_block: &NackBlock) -> Result<()> {
    let packet_id = nack_block.missing_seq_nums.first().ok_or(anyhow!(
        "NackBlock must contain at least one sequence number"
    ))?;
    buf.write_u16::<NetworkOrder>(*packet_id)
        .context("packet id")?;
    let mut blp = 0u16;
    // Skip past the first one, since that was used for the packet id
    for missing_seq_num in nack_block.missing_seq_nums.iter().skip(1) {
        let delta = missing_seq_num - packet_id;
        if delta > 16 {
            bail!("NACK missing sequence numbers can not span more than 16 sequence numbers");
        }
        let mask = 1u16 << (delta - 1);
        blp |= mask;
    }
    buf.write_u16::<NetworkOrder>(blp).context("blp")?;

    Ok(())
}

trait ChunkByMaxDifference<T> {
    fn chunk_by_max_difference(&self, max_diff: T) -> Vec<BTreeSet<T>>;
}

impl ChunkByMaxDifference<u16> for BTreeSet<u16> {
    fn chunk_by_max_difference(&self, max_diff: u16) -> Vec<BTreeSet<u16>> {
        let mut all_chunks: Vec<BTreeSet<u16>> = Vec::new();
        let Some(first) = self.first() else {
            return all_chunks;
        };
        let mut curr_chunk: BTreeSet<u16> = BTreeSet::from([*first]);
        for value in self.iter().skip(1) {
            if value - curr_chunk.first().unwrap() > max_diff {
                all_chunks.push(curr_chunk);
                curr_chunk = BTreeSet::from([*value]);
            } else {
                curr_chunk.insert(*value);
            }
        }

        all_chunks
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use bitcursor::bit_cursor::BitCursor;
    use bitvec::{order::Msb0, vec::BitVec};

    use super::{read_nack_block, write_nack_block};

    #[test]
    fn test_read_nack_block() {
        // Missing seq nums 10, 11, 16, 18, 22, 24, 26
        let data_buf: [u8; 4] = [0x00, 0x0A, 0xA8, 0xA1];
        let mut cursor = BitCursor::new(BitVec::<u8, Msb0>::from_slice(&data_buf));
        let nack_block = read_nack_block(&mut cursor).unwrap();
        assert_eq!(
            nack_block.missing_seq_nums,
            BTreeSet::from([10, 11, 16, 18, 22, 24, 26]),
        );
    }

    #[test]
    fn test_write_nack_block() {
        // Missing seq nums 10, 11, 16, 18, 22, 24, 26
        let data_buf: [u8; 4] = [0x00, 0x0A, 0xA8, 0xA1];
        let mut cursor = BitCursor::new(BitVec::<u8, Msb0>::from_slice(&data_buf));
        let nack_block = read_nack_block(&mut cursor).unwrap();

        let write_data_buf = [0u8; 4];
        let mut write_cursor = BitCursor::new(BitVec::<u8, Msb0>::from_slice(&write_data_buf));
        write_nack_block(&mut write_cursor, &nack_block).unwrap();
        let write_data = write_cursor.into_inner().into_vec();
        assert_eq!(&data_buf, &write_data[..]);
    }
}
