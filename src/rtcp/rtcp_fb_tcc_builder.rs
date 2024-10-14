use std::time::Instant;

use bit_cursor::nsw_types::u13;
use bytes::Buf;

use super::rtcp_fb_tcc::{
    PacketStatusSymbol, RunLengthEncodingChunk, SomePacketStatusChunk, StatusVectorChunk,
};

const MAX_ONE_BIT_CAPACITY: usize = 14;
const MAX_TWO_BIT_CAPACITY: usize = 7;
const MAX_VECTOR_CAPACITY: usize = MAX_ONE_BIT_CAPACITY;
const MAX_RUN_LENGTH_CAPACITY: usize = 0x1FFF;

struct Chunk {
    all_same: bool,
    has_large_delta: bool,
    num_deltas: usize,
    delta_sizes: [u8; MAX_VECTOR_CAPACITY],
}

impl Default for Chunk {
    fn default() -> Self {
        Self {
            all_same: true,
            has_large_delta: false,
            num_deltas: 0,
            delta_sizes: Default::default(),
        }
    }
}

impl Chunk {
    fn empty(&self) -> bool {
        self.num_deltas == 0
    }

    fn clear(&mut self) {
        self.num_deltas = 0;
        self.all_same = true;
        self.has_large_delta = false;
    }

    // TODO: change this api to take in a PacketStatusSymbol instead?
    /// Return true if the given delta size can be encoded into this chunk
    fn can_add(&self, delta_size: u8) -> bool {
        if self.num_deltas < MAX_TWO_BIT_CAPACITY {
            return true;
        }
        if self.num_deltas < MAX_ONE_BIT_CAPACITY && !self.has_large_delta && delta_size != 2 {
            return true;
        }
        if self.num_deltas < MAX_RUN_LENGTH_CAPACITY
            && self.all_same
            && self.delta_sizes[0] == delta_size
        {
            return true;
        }
        false
    }

    /// Add `delta_size` to this chunk.  Assumes can_add(delta_size) returned true
    fn add(&mut self, delta_size: u8) {
        if self.num_deltas < MAX_VECTOR_CAPACITY {
            self.delta_sizes[self.num_deltas] = delta_size;
        }
        self.num_deltas += 1;
        self.all_same = self.all_same && self.delta_sizes[0] == delta_size;
        self.has_large_delta = self.has_large_delta || delta_size == 2;
    }

    /// Equivalent to add(0) `num_missing` times.  Assumes empty returned true
    fn add_missing_packets(&mut self, num_missing: usize) {
        for i in 0..num_missing {
            self.delta_sizes[i] = 0;
        }
        self.num_deltas = num_missing;
    }

    fn emit(&mut self) -> SomePacketStatusChunk {
        if self.all_same {
            let chunk = SomePacketStatusChunk::RunLengthEncodingChunk(self.encode_run_length());
            self.clear();
            return chunk;
        }
        if self.num_deltas == MAX_ONE_BIT_CAPACITY {
            let chunk = SomePacketStatusChunk::StatusVectorChunk(self.encode_one_bit());
            self.clear();
            return chunk;
        }
        let chunk =
            SomePacketStatusChunk::StatusVectorChunk(self.encode_two_bit(MAX_TWO_BIT_CAPACITY));
        // Remove MAX_TWO_BIT_CAPACITY encoded delta sizes
        // Shift remaining delta sizes and recalculate all_same and has_large_delta
        self.num_deltas -= MAX_TWO_BIT_CAPACITY;
        self.all_same = true;
        self.has_large_delta = false;
        for i in 0..self.num_deltas {
            let delta_size = self.delta_sizes[i + MAX_TWO_BIT_CAPACITY];
            self.delta_sizes[i] = delta_size;
            self.all_same = self.all_same && delta_size == self.delta_sizes[0];
            self.has_large_delta = self.has_large_delta || delta_size == 2;
        }
        chunk
    }

    fn encode_run_length(&self) -> RunLengthEncodingChunk {
        RunLengthEncodingChunk {
            symbol: PacketStatusSymbol::from_delta_size(self.delta_sizes[0]),
            run_length: u13::new(self.num_deltas as u16),
        }
    }

    fn encode_one_bit(&self) -> StatusVectorChunk {
        let symbols = self
            .delta_sizes
            .iter()
            .take(self.num_deltas)
            .map(|delta_size| PacketStatusSymbol::from_delta_size(*delta_size))
            .collect::<_>();
        StatusVectorChunk(symbols)
    }

    fn encode_two_bit(&self, size: usize) -> StatusVectorChunk {
        let symbols = self
            .delta_sizes
            .iter()
            .take(size)
            .map(|delta_size| PacketStatusSymbol::from_delta_size(*delta_size))
            .collect::<_>();
        StatusVectorChunk(symbols)
    }
}

pub struct RtcpFbTccBuilder {
    base_seq_num: Option<u16>,
    last_timestamp: Option<Instant>,
    chunk: Chunk,
}

impl RtcpFbTccBuilder {
    pub fn add_received_packet(&mut self, tcc_seq_num: u16, receive_timestamp: Instant) -> bool {
        if self.base_seq_num.is_none() {
            self.base_seq_num = Some(tcc_seq_num);
            self.last_timestamp = Some(receive_timestamp);
        }
        let delta = receive_timestamp.duration_since(self.last_timestamp.unwrap());
        let delta_ticks = delta.as_micros() / 250;
        if delta_ticks > u16::MAX as u128 {
            // Delta is too large to be represented in this packet
            return false;
        }

        true
    }
}

#[cfg(test)]
mod test {
    use crate::rtcp::{
        rtcp_fb_tcc::{PacketStatusSymbol, SomePacketStatusChunk},
        rtcp_fb_tcc_builder::MAX_ONE_BIT_CAPACITY,
    };

    use super::{Chunk, MAX_RUN_LENGTH_CAPACITY};

    #[test]
    fn test_chunk_default() {
        let chunk = Chunk::default();
        assert!(chunk.empty());
    }

    #[test]
    fn test_chunk_one_bit() {
        let mut chunk = Chunk::default();
        // Add 14 one-bit deltas but not all the same, so run-length can't be used
        assert!(chunk.can_add(PacketStatusSymbol::NotReceived.delta_size_bytes()));
        chunk.add(PacketStatusSymbol::NotReceived.delta_size_bytes());
        for _ in 1..14 {
            assert!(chunk.can_add(PacketStatusSymbol::ReceivedSmallDelta.delta_size_bytes()));
            chunk.add(PacketStatusSymbol::ReceivedSmallDelta.delta_size_bytes());
        }
        // Shouldn't be any room left
        assert!(!chunk.can_add(PacketStatusSymbol::NotReceived.delta_size_bytes()));
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), 14);
        let SomePacketStatusChunk::StatusVectorChunk(sv_chunk) = encoded else {
            panic!("Expected status vector chunk");
        };
        assert_eq!(sv_chunk.0[0], PacketStatusSymbol::NotReceived);
        for i in 1..14 {
            assert_eq!(sv_chunk.0[i], PacketStatusSymbol::ReceivedSmallDelta);
        }
    }

    #[test]
    fn test_chunk_two_bit() {
        let mut chunk = Chunk::default();
        assert!(chunk.can_add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta.delta_size_bytes()));
        chunk.add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta.delta_size_bytes());
        // Now add 6 more symbols
        for _ in 0..6 {
            assert!(chunk.can_add(PacketStatusSymbol::ReceivedSmallDelta.delta_size_bytes()));
            chunk.add(PacketStatusSymbol::ReceivedSmallDelta.delta_size_bytes());
        }
        // Next one should fail
        assert!(!chunk.can_add(PacketStatusSymbol::ReceivedSmallDelta.delta_size_bytes()));
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), 7);
        let SomePacketStatusChunk::StatusVectorChunk(sv_chunk) = encoded else {
            panic!("Expected status vector chunk");
        };
        assert_eq!(
            sv_chunk.0[0],
            PacketStatusSymbol::ReceivedLargeOrNegativeDelta
        );
        for i in 1..7 {
            assert_eq!(sv_chunk.0[i], PacketStatusSymbol::ReceivedSmallDelta);
        }
    }

    #[test]
    fn test_chunk_run_length() {
        let mut chunk = Chunk::default();

        for i in 0..MAX_RUN_LENGTH_CAPACITY {
            assert!(
                chunk.can_add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta.delta_size_bytes())
            );
            // If we're beyond MAX_ONE_BIT_CAPACITY, we shouldn't be able to add another symbol
            // type
            if i > MAX_ONE_BIT_CAPACITY {
                assert!(!chunk.can_add(PacketStatusSymbol::NotReceived.delta_size_bytes()));
            }
            chunk.add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta.delta_size_bytes());
        }
        // Shouldn't be able to add any more
        assert!(!chunk.can_add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta.delta_size_bytes()));
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), MAX_RUN_LENGTH_CAPACITY as u16);
    }
}
