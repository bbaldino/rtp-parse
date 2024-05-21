use anyhow::{Context, Result};
use bitcursor::{
    bit_read::BitRead, bit_read_exts::BitReadExts, bit_write::BitWrite,
    bit_write_exts::BitWriteExts, byte_order::NetworkOrder,
};

/// https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.1
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// sender |              NTP timestamp, most significant word             |
/// info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |             NTP timestamp, least significant word             |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                         RTP timestamp                         |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                     sender's packet count                     |
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |                      sender's octet count                     |
///        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#[derive(Debug)]
pub struct RtcpSenderInfo {
    pub ntp_timestamp_msw: u32,
    pub ntp_timestamp_lsw: u32,
    pub rtp_timestamp: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
}

pub fn read_rtcp_sender_info<R: BitRead>(buf: &mut R) -> Result<RtcpSenderInfo> {
    Ok(RtcpSenderInfo {
        ntp_timestamp_msw: buf
            .read_u32::<NetworkOrder>()
            .context("ntp_timestamp_msw")?,
        ntp_timestamp_lsw: buf
            .read_u32::<NetworkOrder>()
            .context("ntp_timestamp_lsw")?,
        rtp_timestamp: buf.read_u32::<NetworkOrder>().context("rtp_timestamp")?,
        sender_packet_count: buf
            .read_u32::<NetworkOrder>()
            .context("sender_packet_count")?,
        sender_octet_count: buf
            .read_u32::<NetworkOrder>()
            .context("sender_octet_count")?,
    })
}

pub fn write_rtcp_sender_info<W: BitWrite>(
    buf: &mut W,
    rtcp_sender_info: &RtcpSenderInfo,
) -> Result<()> {
    buf.write_u32::<NetworkOrder>(rtcp_sender_info.ntp_timestamp_msw)
        .context("ntp_timestamp_msw")?;
    buf.write_u32::<NetworkOrder>(rtcp_sender_info.ntp_timestamp_lsw)
        .context("ntp_timestamp_lsw")?;
    buf.write_u32::<NetworkOrder>(rtcp_sender_info.rtp_timestamp)
        .context("rtp_timestamp")?;
    buf.write_u32::<NetworkOrder>(rtcp_sender_info.sender_packet_count)
        .context("sender_packet_count")?;
    buf.write_u32::<NetworkOrder>(rtcp_sender_info.sender_octet_count)
        .context("sender_octet_count")?;

    Ok(())
}
