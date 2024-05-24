use crate::{PacketBuffer, PacketBufferMut};
use anyhow::{bail, Context, Result};
use bitcursor::{
    bit_read_exts::BitReadExts,
    bit_write_exts::BitWriteExts,
    byte_order::NetworkOrder,
    ux::{u24, u5},
};

use super::{
    rtcp_fb_header::{write_rtcp_fb_header, RtcpFbHeader},
    rtcp_header::{write_rtcp_header, RtcpHeader},
};

/// FIR FCI:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              SSRC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Seq nr.       |    Reserved                                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// From https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.1.2:
/// Within the common packet header for feedback messages (as defined in
/// section 6.1 of [RFC4585]), the "SSRC of packet sender" field
/// indicates the source of the request, and the "SSRC of media source"
/// is not used and SHALL be set to 0.  The SSRCs of the media senders to
/// which the FIR command applies are in the corresponding FCI entries.
/// A FIR message MAY contain requests to multiple media senders, using
/// one FCI entry per target media sender.
#[derive(Debug)]
pub struct RtcpFbFirPacket {
    pub header: RtcpHeader,
    pub fb_header: RtcpFbHeader,
    pub fcis: Vec<RtcpFbFirFci>,
}

impl RtcpFbFirPacket {
    pub const FMT: u5 = u5::new(4);
}

pub fn read_rtcp_fb_fir<B: PacketBuffer>(
    buf: &mut B,
    header: RtcpHeader,
    fb_header: RtcpFbHeader,
) -> Result<RtcpFbFirPacket> {
    // TODO: there can be multiple FCI chunks here, we need to keep reading until reaching the end
    // of the packet.  That means the buf we're given needs to be a slice based on the length in
    // the header so this can read until the end
    if fb_header.media_source_ssrc != 0 {
        bail!("SSRC of media source must be set to 0");
    }
    let mut num_fci = 1;
    let mut fcis = Vec::new();
    while buf.bytes_remaining() >= RtcpFbFirFci::SIZE_BYTES {
        let fci = read_rtcp_fb_fir_fci(buf).with_context(|| format!("fci {num_fci}"))?;
        fcis.push(fci);
        num_fci += 1;
    }
    Ok(RtcpFbFirPacket {
        header,
        fb_header,
        fcis,
    })
}

pub fn write_rtcp_fb_fir<B: PacketBufferMut>(buf: &mut B, fb_fir: &RtcpFbFirPacket) -> Result<()> {
    write_rtcp_header(buf, &fb_fir.header).context("header")?;
    write_rtcp_fb_header(buf, &fb_fir.fb_header).context("fb header")?;
    for (i, fci) in fb_fir.fcis.iter().enumerate() {
        write_rtcp_fb_fir_fci(buf, fci).with_context(|| format!("fci {i}"))?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct RtcpFbFirFci {
    ssrc: u32,
    seq_num: u8,
}

impl RtcpFbFirFci {
    pub const SIZE_BYTES: usize = 8;
}

pub fn read_rtcp_fb_fir_fci<B: PacketBuffer>(buf: &mut B) -> Result<RtcpFbFirFci> {
    let ssrc = buf.read_u32::<NetworkOrder>().context("source")?;
    let seq_num = buf.read_u8().context("seq num")?;
    // Consume the reserved chunk
    let _ = buf.read_u24::<NetworkOrder>().context("reserved")?;

    Ok(RtcpFbFirFci { ssrc, seq_num })
}

pub fn write_rtcp_fb_fir_fci<B: PacketBufferMut>(
    buf: &mut B,
    fb_fir_fci: &RtcpFbFirFci,
) -> Result<()> {
    buf.write_u32::<NetworkOrder>(fb_fir_fci.ssrc)
        .context("source")?;
    buf.write_u8(fb_fir_fci.seq_num).context("seq num")?;
    buf.write_u24::<NetworkOrder>(u24::new(0))
        .context("reserved")?;

    Ok(())
}
