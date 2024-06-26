use super::header_extensions::SomeHeaderExtension;

//
// https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01#section-2.2
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  ID   | L=1   |transport-wide sequence number | zero padding  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

pub fn get_tcc_seq_num(ext: &SomeHeaderExtension) -> u16 {
    let data = ext.data();

    (data[0] as u16) << 8 | data[1] as u16
}
