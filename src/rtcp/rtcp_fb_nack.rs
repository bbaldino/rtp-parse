use parsely_rs::*;
use std::collections::BTreeSet;

use super::{
    rtcp_fb_header::RtcpFbHeader, rtcp_fb_packet::RtcpFbTlPacket, rtcp_header::RtcpHeader,
};

/// https://datatracker.ietf.org/doc/html/rfc4585#section-6.2.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            PID                |             BLP               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq)]
pub struct RtcpFbNackPacket {
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
    pub missing_seq_nums: BTreeSet<u16>,
}

// TODO: somewhere in here we need to enforce some kind of maximum number of sequence numbers that
// can be included in a nack packet (or, a way for a nack to fail to serialize due to having more
// sequence numbers that couldn't be added to the buffer)

impl RtcpFbNackPacket {
    pub const FMT: u5 = u5::new(1);

    pub fn add_missing_seq_num(&mut self, missing_seq_num: u16) {
        self.missing_seq_nums.insert(missing_seq_num);
    }

    pub fn payload_length_bytes(&self) -> u16 {
        // TODO: not ideal to have to do this chunking just to calculate the size, maybe we can at
        // least cache the result and re-use it if no more packets are added?
        let num_chunks = self.missing_seq_nums.chunk_by_max_difference(16).len() as u16;
        num_chunks * 4
    }
}

impl Default for RtcpFbNackPacket {
    fn default() -> Self {
        Self {
            header: RtcpHeader::default()
                .packet_type(RtcpFbTlPacket::PT)
                .report_count(RtcpFbNackPacket::FMT),
            fb_header: Default::default(),
            missing_seq_nums: Default::default(),
        }
    }
}

impl StateSync<()> for RtcpFbNackPacket {
    fn sync(&mut self, _sync_ctx: ()) -> ParselyResult<()> {
        // Add 8 for the size of the fb header
        self.header
            .sync((self.payload_length_bytes() + 8, RtcpFbNackPacket::FMT))
    }
}

impl<B: BitBuf> ParselyRead<B, (RtcpHeader, RtcpFbHeader)> for RtcpFbNackPacket {
    fn read<T: ByteOrder>(
        buf: &mut B,
        (header, fb_header): (RtcpHeader, RtcpFbHeader),
    ) -> ParselyResult<Self> {
        let mut missing_seq_nums = BTreeSet::new();
        let mut nack_block_num = 1;
        while buf.remaining_bytes() >= NackBlock::SIZE_BYTES {
            let mut nack_block = NackBlock::read::<T>(buf, ())
                .with_context(|| format!("Nack block {nack_block_num}"))?;
            missing_seq_nums.append(&mut nack_block.missing_seq_nums);
            nack_block_num += 1;
        }
        Ok(RtcpFbNackPacket {
            header,
            fb_header,
            missing_seq_nums,
        })
    }
}

impl<B: BitBufMut> ParselyWrite<B, ()> for RtcpFbNackPacket {
    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: ()) -> ParselyResult<()> {
        self.header.write::<T>(buf, ()).context("header")?;
        self.fb_header.write::<T>(buf, ()).context("fb header")?;
        for (i, chunk) in self
            .missing_seq_nums
            .chunk_by_max_difference(16)
            .into_iter()
            .enumerate()
        {
            if buf.remaining_mut_bytes() < NackBlock::SIZE_BYTES {
                bail!("Not enough room to write nack block {i}");
            }
            let nack_block = NackBlock {
                missing_seq_nums: chunk,
            };
            nack_block
                .write::<T>(buf, ())
                .with_context(|| format!("Writing nack block {i}"))?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct NackBlock {
    missing_seq_nums: BTreeSet<u16>,
}

impl NackBlock {
    pub const SIZE_BYTES: usize = 4;

    pub fn add_missing_seq_num(&mut self, missing_seq_num: u16) {
        self.missing_seq_nums.insert(missing_seq_num);
    }
}

impl<B: BitBuf> ParselyRead<B, ()> for NackBlock {
    fn read<T: ByteOrder>(buf: &mut B, _ctx: ()) -> ParselyResult<Self> {
        let packet_id = buf.get_u16::<NetworkOrder>().context("packet id")?;
        let blp = buf.get_u16::<NetworkOrder>().context("blp")?;

        let mut missing_seq_nums = BTreeSet::new();
        missing_seq_nums.insert(packet_id);
        for shift_amount in 0..16 {
            if (blp >> shift_amount) & 0x1 == 1 {
                missing_seq_nums.insert(packet_id + shift_amount + 1);
            }
        }
        Ok(NackBlock { missing_seq_nums })
    }
}

impl<B: BitBufMut> ParselyWrite<B, ()> for NackBlock {
    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: ()) -> ParselyResult<()> {
        let packet_id = self.missing_seq_nums.first().ok_or(anyhow!(
            "NackBlock must contain at least one sequence number"
        ))?;
        buf.put_u16::<T>(*packet_id).context("packet it")?;
        let mut blp = 0u16;
        // Skip past the first one since it was used for the packet id
        for missing_seq_num in self.missing_seq_nums.iter().skip(1) {
            let delta = missing_seq_num - packet_id;
            if delta > 16 {
                bail!("NACK cannot contain sequence number spread larger than 16");
            }
            let mask = 1u16 << (delta - 1);
            blp |= mask;
        }
        buf.put_u16::<T>(blp).context("blp")?;
        Ok(())
    }
}

trait ChunkByMaxDifference<T> {
    fn chunk_by_max_difference(&self, max_diff: T) -> Vec<BTreeSet<T>>;
}

impl ChunkByMaxDifference<u16> for BTreeSet<u16> {
    /// Return a Vec of BTreeSets where the values included in each one do not differ by more than
    /// the given `max_diff`.`
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
        all_chunks.push(curr_chunk);

        all_chunks
    }
}

#[cfg(test)]
mod test {
    use crate::rtcp::rtcp_fb_packet::RtcpFbTlPacket;

    use super::*;

    #[test]
    fn test_read_nack_block() {
        // Missing seq nums 10, 11, 16, 18, 22, 24, 26
        let mut bits = Bits::from_static_bytes(&[0x00, 0x0A, 0xA8, 0xA1]);
        let nack_block = NackBlock::read::<NetworkOrder>(&mut bits, ()).unwrap();
        assert_eq!(
            nack_block.missing_seq_nums,
            BTreeSet::from([10, 11, 16, 18, 22, 24, 26]),
        );
    }

    #[test]
    fn test_put_nack_block() {
        // Missing seq nums 10, 11, 16, 18, 22, 24, 26
        let mut nack_block = NackBlock::default();
        nack_block.add_missing_seq_num(10);
        nack_block.add_missing_seq_num(11);
        nack_block.add_missing_seq_num(16);
        nack_block.add_missing_seq_num(18);
        nack_block.add_missing_seq_num(22);
        nack_block.add_missing_seq_num(24);
        nack_block.add_missing_seq_num(26);

        let mut bits_mut = BitsMut::new();
        nack_block.write::<NetworkOrder>(&mut bits_mut, ()).unwrap();

        let mut bits = bits_mut.freeze();
        let read_nack_block = NackBlock::read::<NetworkOrder>(&mut bits, ()).unwrap();
        assert_eq!(read_nack_block, nack_block);
    }

    #[test]
    fn test_read_nack_packet() {
        let rtcp_header = RtcpHeader {
            report_count: RtcpFbNackPacket::FMT,
            packet_type: RtcpFbTlPacket::PT,
            length_field: 3,
            ..Default::default()
        };
        let rtcp_fb_header = RtcpFbHeader::default()
            .media_source_ssrc(42)
            .sender_ssrc(24);
        #[rustfmt::skip]
        let nack_payload = vec![
            // packet id 10
            0x00, 0x0A,
            // Missing seq nums 10, 11, 16, 18, 22, 24, 26
            0xA8, 0xA1,
            // packet id 40
            0x00, 0x28,
            // Missing seq nums 40, 42, 48, 51, 54
            0x24, 0x82
        ];
        let mut bits = Bits::from_owner_bytes(nack_payload);
        let nack_packet =
            RtcpFbNackPacket::read::<NetworkOrder>(&mut bits, (rtcp_header, rtcp_fb_header))
                .unwrap();
        assert_eq!(
            nack_packet.missing_seq_nums,
            BTreeSet::from_iter([10, 11, 16, 18, 22, 24, 26, 40, 42, 48, 51, 54])
        );
    }

    #[test]
    fn test_default() {
        let rtcp_fb_nack = RtcpFbNackPacket::default();
        assert_eq!(rtcp_fb_nack.header.packet_type, RtcpFbTlPacket::PT);
        assert_eq!(rtcp_fb_nack.header.report_count, RtcpFbNackPacket::FMT);
        assert_eq!(rtcp_fb_nack.header.length_field, 0);
    }

    #[test]
    fn test_sync() {
        let mut rtcp_fb_nack = RtcpFbNackPacket::default();
        rtcp_fb_nack.add_missing_seq_num(10);
        rtcp_fb_nack.add_missing_seq_num(12);
        rtcp_fb_nack.add_missing_seq_num(13);
        rtcp_fb_nack.add_missing_seq_num(17);
        rtcp_fb_nack.add_missing_seq_num(21);
        rtcp_fb_nack.add_missing_seq_num(23);
        rtcp_fb_nack.sync(()).unwrap();
        // Above missing packets should fit in a single block
        assert_eq!(rtcp_fb_nack.header.length_field, 3);
    }

    #[test]
    fn test_sync_multiple_blocks() {
        let mut rtcp_fb_nack = RtcpFbNackPacket::default();
        rtcp_fb_nack.add_missing_seq_num(10);
        rtcp_fb_nack.add_missing_seq_num(12);
        rtcp_fb_nack.add_missing_seq_num(13);
        rtcp_fb_nack.add_missing_seq_num(17);
        rtcp_fb_nack.add_missing_seq_num(21);
        rtcp_fb_nack.add_missing_seq_num(23);
        rtcp_fb_nack.add_missing_seq_num(44);
        rtcp_fb_nack.sync(()).unwrap();
        assert_eq!(rtcp_fb_nack.header.length_field, 4);
    }

    #[test]
    fn test_put_rtcp_fb_nack() {
        let mut rtcp_fb_nack = RtcpFbNackPacket::default();
        rtcp_fb_nack.add_missing_seq_num(10);
        rtcp_fb_nack.add_missing_seq_num(12);
        rtcp_fb_nack.add_missing_seq_num(13);
        rtcp_fb_nack.add_missing_seq_num(17);
        rtcp_fb_nack.add_missing_seq_num(21);
        rtcp_fb_nack.add_missing_seq_num(23);
        rtcp_fb_nack.add_missing_seq_num(44);
        rtcp_fb_nack.sync(()).unwrap();

        let mut bits_mut = BitsMut::new();

        rtcp_fb_nack
            .write::<NetworkOrder>(&mut bits_mut, ())
            .unwrap();
        let mut bits = bits_mut.freeze();
        let header = RtcpHeader::read::<NetworkOrder>(&mut bits, ()).unwrap();
        let fb_header = RtcpFbHeader::read::<NetworkOrder>(&mut bits, ()).unwrap();
        let read_rtcp_fb_nack =
            RtcpFbNackPacket::read::<NetworkOrder>(&mut bits, (header, fb_header)).unwrap();
        assert_eq!(read_rtcp_fb_nack, rtcp_fb_nack);
    }
}
