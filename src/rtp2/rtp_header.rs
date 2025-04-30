use parsely_rs::*;

use super::header_extensions::HeaderExtensions;

/// An RTP header
///
/// https://tools.ietf.org/html/rfc3550#section-5.1
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ...extensions (if present)...                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(ParselyRead, ParselyWrite)]
pub struct RtpHeader {
    pub version: u2,
    pub has_padding: bool,
    pub has_extensions: bool,
    pub csrc_count: u4,
    pub marked: bool,
    pub payload_type: u7,
    pub seq_num: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    #[parsely_read(count = "csrc_count.into()")]
    pub csrcs: Vec<u32>,
    pub extensions: HeaderExtensions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_fixed_header() {
        #[rustfmt::skip]
        let mut data = Bits::from_static_bytes(&[
            // V=2,P=false,X=true,CC=2,M=false,PT=100,SeqNum=16535
            0x92, 0x64, 0x40, 0x97,
            // Timestamp: 3899068446
            0xe8, 0x67, 0x10, 0x1e,
            // SSRC: 2828806853
            0xa8, 0x9c, 0x2a, 0xc5,
            // CSRC 1: 123456
            0x00, 0x01, 0xE2, 0x40,
            // CSRC 2: 45678
            0x00, 0x00, 0xB2, 0x6E,
            // 1 extension
            0xbe, 0xde, 0x00, 0x01,
            0x51, 0x00, 0x02, 0x00
        ]);
        let header = RtpHeader::read::<NetworkOrder>(&mut data, ()).unwrap();
        assert_eq!(header.version, 2);
        assert!(!header.has_padding);
        assert!(header.has_extensions);
        assert_eq!(header.csrc_count, 2);
        assert!(!header.marked);
        assert_eq!(header.payload_type, 100);
        assert_eq!(header.seq_num, 16535);
        assert_eq!(header.timestamp, 3899068446);
        assert_eq!(header.ssrc, 2828806853);
        assert_eq!(header.extensions.len(), 1);
        let ext = header.extensions.get_by_id(5).unwrap();
        assert_eq!(ext.data(), &[0, 2]);
    }
}
