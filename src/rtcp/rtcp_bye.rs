use std::{io::Read, str::from_utf8};

use anyhow::{Context, Result};
use bitcursor::{bit_read::BitRead, bit_read_exts::BitReadExts, byte_order::NetworkOrder};

use super::rtcp_header::RtcpHeader;

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.6
///        0                   1                   2                   3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |V=2|P|    SC   |   PT=BYE=203  |             length            |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                           SSRC/CSRC                           |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       :                              ...                              :
///       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// (opt) |     length    |               reason for leaving            ...
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct RtcpByePacket {
    pub header: RtcpHeader,
    pub ssrcs: Vec<u32>,
    pub reason: Option<String>,
}

impl RtcpByePacket {
    pub const PT: u8 = 203;
}

pub fn parse_rtcp_bye<R: BitRead + Read>(buf: &mut R, header: RtcpHeader) -> Result<RtcpByePacket> {
    let ssrcs = (0u32..header.report_count.into())
        .map(|i| {
            buf.read_u32::<NetworkOrder>()
                .with_context(|| format!("ssrc-{i}"))
        })
        .collect::<Result<Vec<u32>>>()?;

    // Try to read a BYE reason length
    let reason = {
        if let Ok(reason_length) = buf.read_u8() {
            let mut reason_bytes = vec![0; reason_length.into()];
            std::io::Read::read(buf, &mut reason_bytes).context("bye reason bytes")?;
            Some(
                from_utf8(&reason_bytes)
                    .context("convert bye reason from urf8")
                    .map(|str| str.to_owned())?,
            )
        } else {
            // Reason is optional, so if there was no data there just mark it as None.
            // TODO: technically I think we should only do this in the 'failed to fill buffer'
            // error case? Otherwise it could be a real error of some kind.
            None
        }
    };
    Ok(RtcpByePacket {
        header,
        ssrcs,
        reason,
    })
}
