use std::time::Instant;

use anyhow::Result;

use crate::rtcp::rtcp_fb_tcc::{PacketStatusSymbol, RtcpFbTccPacket, SomePacketStatusChunk};

use super::chunk::Chunk;

pub struct RtcpFbTccBuilder {
    base_seq_num: u16,
    reference_timestamp: Instant,
    expected_next_seq_num: u16,
    last_timestamp: Instant,
    chunks: Vec<SomePacketStatusChunk>,
    last_chunk: Chunk,
}

impl RtcpFbTccBuilder {
    pub fn new(base_seq_num: u16, reference_timestamp: Instant) -> Self {
        Self {
            base_seq_num,
            reference_timestamp,
            expected_next_seq_num: base_seq_num,
            last_timestamp: reference_timestamp,
            chunks: Default::default(),
            last_chunk: Chunk::default(),
        }
    }

    // Note that packets here should have sequence numbers passed _in order_ (i.e. packets received
    // but received out-of-order should have already been sorted into place)
    pub fn add_received_packet(&mut self, tcc_seq_num: u16, receive_timestamp: Instant) -> bool {
        let delta = receive_timestamp.duration_since(self.last_timestamp);
        let delta_ticks = delta.as_micros() / 250;
        if delta_ticks > u16::MAX as u128 {
            // Delta is too large to be represented in this packet
            return false;
        }

        // Add 'NotReceived' for any missing sequence numbers
        while self.expected_next_seq_num != tcc_seq_num {
            if !self.last_chunk.can_add(PacketStatusSymbol::NotReceived) {
                self.chunks.push(self.last_chunk.emit());
            }
            self.last_chunk.add(PacketStatusSymbol::NotReceived);
            self.expected_next_seq_num = self.expected_next_seq_num.wrapping_add(1);
        }
        if (0..=0xFF).contains(&delta_ticks) {
        } else {
        }

        true
    }

    pub fn build(self) -> Result<RtcpFbTccPacket> {
        // TODO: It doesn't seem right to just generate PacketReports here...we have to do the
        // chunks above to see what can 'fit' and what can't...so I think we should change the
        // RtcpFbTccPacket to hold the chunks and deltas and then add a helper to convert that to
        // PacketReports
        Ok(RtcpFbTccPacket {
            header: todo!(),
            fb_header: todo!(),
            packet_reports: todo!(),
            reference_time: todo!(),
            feedback_packet_count: todo!(),
        })
    }
}
