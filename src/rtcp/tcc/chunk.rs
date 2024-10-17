use std::cmp::min;

use bit_cursor::nsw_types::*;

use crate::rtcp::rtcp_fb_tcc::{
    PacketStatusSymbol, RunLengthEncodingChunk, SomePacketStatusChunk, StatusVectorChunk,
};

const MAX_ONE_BIT_CAPACITY: usize = 14;
const MAX_TWO_BIT_CAPACITY: usize = 7;
// const MAX_VECTOR_CAPACITY: usize = MAX_ONE_BIT_CAPACITY;
const MAX_RUN_LENGTH_CAPACITY: usize = 0x1FFF;

pub(crate) struct Chunk {
    all_same: bool,
    has_large_delta: bool,
    symbols: Vec<PacketStatusSymbol>,
}

impl Default for Chunk {
    fn default() -> Self {
        Self {
            all_same: true,
            has_large_delta: false,
            symbols: Default::default(),
        }
    }
}

impl Chunk {
    pub(crate) fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.all_same = true;
        self.has_large_delta = false;
        self.symbols = Default::default();
    }

    // TODO: change this api to take in a PacketStatusSymbol instead?
    /// Return true if the given delta size can be encoded into this chunk
    pub(crate) fn can_add(&self, symbol: PacketStatusSymbol) -> bool {
        if self.symbols.len() < MAX_TWO_BIT_CAPACITY {
            return true;
        }
        if self.symbols.len() < MAX_ONE_BIT_CAPACITY
            && !self.has_large_delta
            && symbol != PacketStatusSymbol::ReceivedLargeOrNegativeDelta
        {
            return true;
        }
        if self.symbols.len() < MAX_RUN_LENGTH_CAPACITY
            && self.all_same
            && self.symbols[0] == symbol
        {
            return true;
        }
        false
    }

    /// Add `delta_size` to this chunk.  Assumes can_add(delta_size) returned true
    pub(crate) fn add(&mut self, symbol: PacketStatusSymbol) {
        // if self.symbols.len() < MAX_VECTOR_CAPACITY {
        //     self.symbols.push(symbol);
        // }
        // TODO: if we separately kept state for how many symbols were present, then in the
        // run-length case we wouldn't have to store every symbol in self.symbols and instead could
        // just increment the num_symbols state.  For now let's just put every symbol here, which
        // is a bit wasteful in the RLE case, but can see how it goes.
        self.symbols.push(symbol);
        self.all_same = self.all_same && self.symbols[0] == symbol;
        self.has_large_delta =
            self.has_large_delta || symbol == PacketStatusSymbol::ReceivedLargeOrNegativeDelta;
    }

    /// Equivalent to add(0) `num_missing` times.  Assumes empty returned true
    pub(crate) fn add_missing_packets(&mut self, num_missing: usize) {
        for i in 0..num_missing {
            self.symbols.push(PacketStatusSymbol::NotReceived);
        }
    }

    /// Encode the current status of this [`Chunk`] into [`SomePacketStatusChunk`].  The most
    /// space-efficient chunk type will be used.
    pub(crate) fn emit(&mut self) -> SomePacketStatusChunk {
        if self.all_same {
            let chunk = SomePacketStatusChunk::RunLengthEncodingChunk(self.encode_run_length());
            self.clear();
            return chunk;
        }
        if self.symbols.len() == MAX_ONE_BIT_CAPACITY {
            let chunk = SomePacketStatusChunk::StatusVectorChunk(self.encode_one_bit());
            self.clear();
            return chunk;
        }
        let chunk =
            SomePacketStatusChunk::StatusVectorChunk(self.encode_two_bit(MAX_TWO_BIT_CAPACITY));
        // Remove MAX_TWO_BIT_CAPACITY encoded delta sizes
        self.symbols
            .drain(0..(min(MAX_TWO_BIT_CAPACITY, self.symbols.len())));
        self.all_same = self.symbols.iter().all(|s| s == &self.symbols[0]);
        self.has_large_delta = self
            .symbols
            .iter()
            .any(|s| s == &PacketStatusSymbol::ReceivedLargeOrNegativeDelta);
        // Shift remaining delta sizes and recalculate all_same and has_large_delta
        // self.num_deltas -= MAX_TWO_BIT_CAPACITY;
        // self.all_same = true;
        // self.has_large_delta = false;
        // for i in 0..self.num_deltas {
        //     let delta_size = self.delta_sizes[i + MAX_TWO_BIT_CAPACITY];
        //     self.delta_sizes[i] = delta_size;
        //     self.all_same = self.all_same && delta_size == self.delta_sizes[0];
        //     self.has_large_delta = self.has_large_delta || delta_size == 2;
        // }
        chunk
    }

    fn encode_run_length(&self) -> RunLengthEncodingChunk {
        RunLengthEncodingChunk {
            symbol: self.symbols[0],
            run_length: u13::new(self.symbols.len() as u16),
        }
    }

    fn encode_one_bit(&self) -> StatusVectorChunk {
        StatusVectorChunk(self.symbols.clone())
    }

    fn encode_two_bit(&self, size: usize) -> StatusVectorChunk {
        // let symbols = self.symbols.drain(0..size).collect();
        let symbols = self.symbols.iter().cloned().take(size).collect();
        StatusVectorChunk(symbols)
    }
}

#[cfg(test)]
mod test {
    use crate::rtcp::{
        rtcp_fb_tcc::{PacketStatusSymbol, SomePacketStatusChunk},
        tcc::chunk::MAX_ONE_BIT_CAPACITY,
    };

    use super::{Chunk, MAX_RUN_LENGTH_CAPACITY};

    #[test]
    fn test_chunk_default() {
        let chunk = Chunk::default();
        assert!(chunk.is_empty());
    }

    #[test]
    fn test_chunk_one_bit() {
        let mut chunk = Chunk::default();
        // Add 14 one-bit deltas but not all the same, so run-length can't be used
        assert!(chunk.can_add(PacketStatusSymbol::NotReceived));
        chunk.add(PacketStatusSymbol::NotReceived);
        for _ in 1..14 {
            assert!(chunk.can_add(PacketStatusSymbol::ReceivedSmallDelta));
            chunk.add(PacketStatusSymbol::ReceivedSmallDelta);
        }
        // Shouldn't be any room left
        assert!(!chunk.can_add(PacketStatusSymbol::NotReceived));
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
        assert!(chunk.can_add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta));
        chunk.add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta);
        // Now add 6 more symbols
        for _ in 0..6 {
            assert!(chunk.can_add(PacketStatusSymbol::ReceivedSmallDelta));
            chunk.add(PacketStatusSymbol::ReceivedSmallDelta);
        }
        // Next one should fail
        assert!(!chunk.can_add(PacketStatusSymbol::ReceivedSmallDelta));
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
    fn test_chunk_partial() {
        // Emit a chunk with different symbols before it was full
        let mut chunk = Chunk::default();
        chunk.add(PacketStatusSymbol::NotReceived);
        for _ in 1..5 {
            chunk.add(PacketStatusSymbol::ReceivedSmallDelta);
        }
        // Should still be room left
        assert!(chunk.can_add(PacketStatusSymbol::NotReceived));
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), 5);
        let SomePacketStatusChunk::StatusVectorChunk(sv_chunk) = encoded else {
            panic!("Expected status vector chunk");
        };
        assert_eq!(sv_chunk.0[0], PacketStatusSymbol::NotReceived);
        for i in 1..5 {
            assert_eq!(sv_chunk.0[i], PacketStatusSymbol::ReceivedSmallDelta);
        }
    }

    #[test]
    fn test_chunk_leftover() {
        // Emit a chunk where all the current symbols don't fit so there are some left over
        let mut chunk = Chunk::default();
        chunk.add(PacketStatusSymbol::NotReceived);
        for _ in 1..9 {
            chunk.add(PacketStatusSymbol::ReceivedSmallDelta);
        }
        chunk.add(PacketStatusSymbol::NotReceived);
        // Should still be room left
        assert!(chunk.can_add(PacketStatusSymbol::NotReceived));
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), 7);
        let SomePacketStatusChunk::StatusVectorChunk(sv_chunk) = encoded else {
            panic!("Expected status vector chunk");
        };
        assert_eq!(sv_chunk.0[0], PacketStatusSymbol::NotReceived);
        for i in 1..7 {
            assert_eq!(sv_chunk.0[i], PacketStatusSymbol::ReceivedSmallDelta);
        }
        // There should still be symbols left over
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), 3);
        // Should be a SV chunk because remaining symbols weren't all the same
        let SomePacketStatusChunk::StatusVectorChunk(sv_chunk) = encoded else {
            panic!("Expected status vector chunk");
        };
        assert_eq!(sv_chunk.0[0], PacketStatusSymbol::ReceivedSmallDelta);
        assert_eq!(sv_chunk.0[1], PacketStatusSymbol::ReceivedSmallDelta);
        assert_eq!(sv_chunk.0[2], PacketStatusSymbol::NotReceived);
    }

    #[test]
    fn test_chunk_run_length() {
        let mut chunk = Chunk::default();

        for i in 0..MAX_RUN_LENGTH_CAPACITY {
            assert!(chunk.can_add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta));
            // If we're beyond MAX_ONE_BIT_CAPACITY, we shouldn't be able to add another symbol
            // type
            if i > MAX_ONE_BIT_CAPACITY {
                assert!(!chunk.can_add(PacketStatusSymbol::NotReceived));
            }
            chunk.add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta);
        }
        // Shouldn't be able to add any more
        assert!(!chunk.can_add(PacketStatusSymbol::ReceivedLargeOrNegativeDelta));
        let encoded = chunk.emit();
        assert_eq!(encoded.num_symbols(), MAX_RUN_LENGTH_CAPACITY as u16);
    }
}
