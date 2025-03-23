use std::io::SeekFrom;

use anyhow::{anyhow, bail, Context};
use parsely::*;

use crate::{rtcp::rtcp_bye::RtcpByePacket, PacketBuffer};

use super::{
    rtcp_fb_fir::RtcpFbFirPacket,
    rtcp_fb_header::RtcpFbHeader,
    rtcp_fb_packet::{RtcpFbPsPacket, RtcpFbTlPacket},
    rtcp_header::RtcpHeader,
    rtcp_sdes::RtcpSdesPacket,
};

#[derive(Debug)]
pub enum SomeRtcpPacket {
    CompoundRtcpPacket(Vec<SomeRtcpPacket>),
    RtcpByePacket(RtcpByePacket),
    // RtcpSrPacket(RtcpSrPacket),
    // RtcpRrPacket(RtcpRrPacket),
    RtcpSdesPacket(RtcpSdesPacket),
    // RtcpFbNackPacket(RtcpFbNackPacket),
    RtcpFbFirPacket(RtcpFbFirPacket),
    // RtcpFbTccPacket(RtcpFbTccPacket),
    // RtcpFbPliPacket(RtcpFbPliPacket),
    UnknownRtcpPacket {
        header: RtcpHeader,
        payload: Vec<u8>,
    },
}

impl<B: PacketBuffer> ParselyRead<B, ()> for SomeRtcpPacket {
    fn read<T: ByteOrder>(buf: &mut B, _ctx: ()) -> ParselyResult<Self> {
        let mut packets: Vec<SomeRtcpPacket> = Vec::new();

        let mut sub_packet_num = 1;
        // println!("parsing packet, buf: {buf:x}");
        while buf.bytes_remaining() >= RtcpHeader::SIZE_BYTES {
            let packet = read_single_rtcp_packet::<T, B>(buf)
                .with_context(|| format!("sub packet {sub_packet_num}"))?;
            packets.push(packet);
            sub_packet_num += 1;
        }

        match packets.len() {
            0 => Err(anyhow!("No valid packets found")),
            1 => Ok(packets.remove(0)),
            _ => Ok(SomeRtcpPacket::CompoundRtcpPacket(packets)),
        }
    }
}

pub fn read_single_rtcp_packet<T: ByteOrder, B: PacketBuffer>(
    buf: &mut B,
) -> ParselyResult<SomeRtcpPacket> {
    let header = RtcpHeader::read::<T>(buf, ()).context("header")?;
    let payload_length = header
        .payload_length_bytes()
        .context("header length field")? as usize;
    if payload_length > buf.bytes_remaining() {
        bail!("Invalid RTCP packet, length {payload_length} bytes but buf has only {} bytes remaining", buf.bytes_remaining());
    }
    let payload_length_bits = payload_length * 8;
    let mut payload_buffer = buf.sub_buffer(0..payload_length_bits);
    let result: ParselyResult<SomeRtcpPacket> = match header.packet_type {
        RtcpByePacket::PT => Ok(SomeRtcpPacket::RtcpByePacket(
            RtcpByePacket::read::<T>(&mut payload_buffer, (header,)).context("rtcp bye")?,
        )),
        RtcpSdesPacket::PT => Ok(SomeRtcpPacket::RtcpSdesPacket(
            RtcpSdesPacket::read::<T>(&mut payload_buffer, (header,)).context("rtcp sdes")?,
        )),
        RtcpFbPsPacket::PT | RtcpFbTlPacket::PT => {
            let fb_header =
                RtcpFbHeader::read::<T>(&mut payload_buffer, ()).context("rtcp fb header")?;
            match (header.packet_type, header.report_count) {
                (RtcpFbPsPacket::PT, RtcpFbFirPacket::FMT) => Ok(SomeRtcpPacket::RtcpFbFirPacket(
                    RtcpFbFirPacket::read::<T>(&mut payload_buffer, (header, fb_header))
                        .context("rtcp fb fir")?,
                )),
                (pt, fmt) => bail!("Unsuppsorted RTCP FB packet, pt {pt} fmt {fmt}"),
            }
        }
        pt => bail!("Unsupported packet type {pt}"),
    };
    if payload_buffer.bytes_remaining() > 0 {
        // TODO: ideally we'd get more context as to which type went wrong here
        bail!("Did not consume entire buffer when reading rtcp packet");
    }
    drop(payload_buffer);
    if result.is_ok() {
        buf.seek(SeekFrom::Current(payload_length_bits as i64))
            .context("Seeking past read data")?;
    }
    result
}

// pub fn parse_single_rtcp_packet<B: PacketBuffer>(buf: &mut B) -> Result<SomeRtcpPacket> {
//     // println!("Parsing single rtcp packet: {buf:x}");
//     let header = read_rtcp_header(buf).context("rtcp header")?;
//     let payload_length = header
//         .payload_length_bytes()
//         .context("header length field")? as usize;
//     if payload_length > buf.bytes_remaining() {
//         bail!("Invalid RTCP packet, length {payload_length} bytes but buf has only {} bytes remaining", buf.bytes_remaining());
//     }
//     let payload_length_bits = payload_length * 8;
//     let mut payload_buffer = buf.sub_buffer(0..(payload_length * 8));
//
//     let result = match header.packet_type {
//         RtcpByePacket::PT => Ok(SomeRtcpPacket::RtcpByePacket(
//             read_rtcp_bye(&mut payload_buffer, header).context("rtcp bye")?,
//         )),
//         RtcpSrPacket::PT => Ok(SomeRtcpPacket::RtcpSrPacket(
//             read_rtcp_sr(&mut payload_buffer, header).context("rtcp sr")?,
//         )),
//         RtcpRrPacket::PT => Ok(SomeRtcpPacket::RtcpRrPacket(
//             read_rtcp_rr(&mut payload_buffer, header).context("rtcp sr")?,
//         )),
//         RtcpSdesPacket::PT => Ok(SomeRtcpPacket::RtcpSdesPacket(
//             read_rtcp_sdes(&mut payload_buffer, header).context("rtcp sdes")?,
//         )),
//         RtcpFbPsPacket::PT | RtcpFbTlPacket::PT => {
//             let fb_header = read_rtcp_fb_header(&mut payload_buffer).context("fb header")?;
//             match (header.packet_type, header.report_count) {
//                 (RtcpFbPsPacket::PT, RtcpFbFirPacket::FMT) => Ok(SomeRtcpPacket::RtcpFbFirPacket(
//                     read_rtcp_fb_fir(&mut payload_buffer, header, fb_header)
//                         .context("rtcp fb fir")?,
//                 )),
//                 (RtcpFbPsPacket::PT, RtcpFbPliPacket::FMT) => Ok(SomeRtcpPacket::RtcpFbPliPacket(
//                     read_rtcp_fb_pli(&mut payload_buffer, header, fb_header)
//                         .context("rtcp fb pli")?,
//                 )),
//                 (RtcpFbTlPacket::PT, RtcpFbTccPacket::FMT) => Ok(SomeRtcpPacket::RtcpFbTccPacket(
//                     read_rtcp_fb_tcc(&mut payload_buffer, header, fb_header)
//                         .context("rtcp fb tcc")?,
//                 )),
//                 (RtcpFbTlPacket::PT, RtcpFbNackPacket::FMT) => {
//                     Ok(SomeRtcpPacket::RtcpFbNackPacket(
//                         read_rtcp_fb_nack(&mut payload_buffer, header, fb_header)
//                             .context("rtcp fb nack")?,
//                     ))
//                 }
//                 (pt, fmt) => bail!("Unsuppsorted RTCP FB packet, pt {pt} fmt {fmt}"),
//             }
//         }
//         pt => bail!("Unsupported packet type {pt}"),
//     };
//     drop(payload_buffer);
//     if result.is_ok() {
//         buf.seek(std::io::SeekFrom::Current(payload_length_bits as i64))?;
//     }
//     result
// }

#[cfg(test)]
mod tests {
    use std::io::Seek;

    use super::*;

    #[test]
    fn test_read_rtcp() {
        let mut rtcp_bye = RtcpByePacket::default()
            .add_ssrc(42)
            .add_ssrc(43)
            .with_reason("ciao");
        rtcp_bye.sync(()).expect("sync");

        let packet_size = RtcpHeader::SIZE_BYTES + rtcp_bye.payload_length_bytes() as usize;
        let data = vec![0; packet_size];
        let mut cursor = BitCursor::from_vec(data);
        rtcp_bye
            .write::<NetworkOrder>(&mut cursor, ())
            .expect("successful write");
        cursor.rewind().expect("rewind");

        let result =
            SomeRtcpPacket::read::<NetworkOrder>(&mut cursor, ()).expect("successful read");
        dbg!(result);
    }
}
