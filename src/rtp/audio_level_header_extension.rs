//
// https://tools.ietf.org/html/rfc6464#section-3
// TODO: this can be held as either 1 byte or 2 byte. (though webrtc clients appear to all use 1 byte)
//
//  0                   1
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  ID   | len=0 |V| level       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::header_extensions::SomeHeaderExtension;

const AUDIO_LEVEL_MASK: u8 = 0x7F;
const VAD_MASK: u8 = 0x80;

pub fn get_audio_level(ext: &SomeHeaderExtension) -> u8 {
    ext.data()[0] & AUDIO_LEVEL_MASK
}

pub fn is_muted(ext: &SomeHeaderExtension) -> bool {
    get_audio_level(ext) == 127
}

pub fn get_vad(ext: &SomeHeaderExtension) -> bool {
    ext.data()[0] & VAD_MASK != 0
}
