use std::{collections::HashMap, io::Cursor};

use bytes::{Buf, Bytes};

//  https://datatracker.ietf.org/doc/html/rfc3550#section-5.3.1
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      defined by profile       |           length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        header extension                       |
// |                             ....                              |
// The header extension contains a 16-bit length field that
//   counts the number of 32-bit words in the extension, excluding the
//   four-octet extension header (therefore zero is a valid length).

// https://datatracker.ietf.org/doc/html/rfc8285#section-4.2
// One Byte Header
//
// In the one-byte header form of extensions, the 16-bit value required
//    by the RTP specification for a header extension, labeled in the RTP
//    specification as "defined by profile", MUST have the fixed bit
//    pattern 0xBEDE (the pattern was picked for the trivial reason that
//    the first version of this specification was written on May 25th --
//    the feast day of the Venerable Bede).
//
//    Each extension element MUST start with a byte containing an ID and a
//    length:
//
//        0
//        0 1 2 3 4 5 6 7
//       +-+-+-+-+-+-+-+-+
//       |  ID   |  len  |
//       +-+-+-+-+-+-+-+-+
//
//    The 4-bit ID is the local identifier of this element in the range
//    1-14 inclusive.  In the signaling section, this is referred to as the
//    valid range.
//
//    The local identifier value 15 is reserved for a future extension and
//    MUST NOT be used as an identifier.  If the ID value 15 is
//    encountered, its length field MUST be ignored, processing of the
//    entire extension MUST terminate at that point, and only the extension
//    elements present prior to the element with ID 15 SHOULD be
//    considered.
//
//    The 4-bit length is the number, minus one, of data bytes of this
//    header extension element following the one-byte header.  Therefore,
//    the value zero (0) in this field indicates that one byte of data
//    follows, and a value of 15 (the maximum) indicates element data of
//    16 bytes.  (This permits carriage of 16-byte values, which is a
//    common length of labels and identifiers, while losing the possibility
//    of zero-length values, which would often be padded anyway.)
#[derive(Debug)]
pub struct OneByteHeaderExtension(Bytes);

impl OneByteHeaderExtension {
    pub const TYPE: u16 = 0xBEDE;

    pub fn type_matches(ext_type: u16) -> bool {
        ext_type == Self::TYPE
    }

    pub fn id(&self) -> u8 {
        (self.0[0] & 0xF0) >> 4
    }

    pub fn data(&self) -> Bytes {
        self.0.slice(1..)
    }
}

pub fn read_one_byte_header_extension(buf: &mut Bytes) -> OneByteHeaderExtension {
    let id = (buf[0] & 0xF0) >> 4;

    let length_bytes = match id {
        // A 0 id means we've hit the end of the actual extensions, so consume the rest of the
        // buffer
        0 => buf.len() - 1,
        _ => ((buf[0] & 0xF) + 1) as usize,
    };

    // TODO: here (and two byte) i think we need to validate against buf.len() before splitting
    let he = buf.split_to(1 + length_bytes);

    OneByteHeaderExtension(he)
}

// https://datatracker.ietf.org/doc/html/rfc8285#section-4.3
// Two Byte Header
//
// In the two-byte header form, the 16-bit value defined by the RTP
//    specification for a header extension, labeled in the RTP
//    specification as "defined by profile", is defined as shown below.
//
//        0                   1
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |         0x100         |appbits|
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The appbits field is 4 bits that are application dependent and MAY be
//    defined to be any value or meaning; this topic is outside the scope
//    of this specification.  For the purposes of signaling, this field is
//    treated as a special extension value assigned to the local identifier
//    256.  If no extension has been specified through configuration or
//    signaling for this local identifier value (256), the appbits field
//    SHOULD be set to all 0s (zeros) by the sender and MUST be ignored by
//    the receiver.
//
//    Each extension element starts with a byte containing an ID and a byte
//    containing a length:
//
//        0                   1
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |       ID      |     length    |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The 8-bit ID is the local identifier of this element in the range
//    1-255 inclusive.  In the signaling section, the range 1-256 is
//    referred to as the valid range, with the values 1-255 referring to
//
//    extension elements and the value 256 referring to the 4-bit appbits
//    field (above).  Note that there is one ID space for both the one-byte
//    form and the two-byte form.  This means that the lower values (1-14)
//    can be used in the 4-bit ID field in the one-byte header format with
//    the same meanings.
//
//    The 8-bit length field is the length of extension data in bytes, not
//    including the ID and length fields.  The value zero (0) indicates
//    that there is no subsequent data.
#[derive(Debug)]
pub struct TwoByteHeaderExtension(Bytes);

impl TwoByteHeaderExtension {
    const TYPE_MASK: u16 = 0xFFF0;
    pub const TYPE: u16 = 0x1000;

    pub fn type_matches(ext_type: u16) -> bool {
        (ext_type & Self::TYPE_MASK) == Self::TYPE
    }

    pub fn id(&self) -> u8 {
        self.0[0]
    }

    pub fn data(&self) -> Bytes {
        self.0.slice(2..)
    }
}

/// [`buf`] should start at the beginning of the header extension (the id)
pub fn read_two_byte_header_extension(buf: &mut Bytes) -> TwoByteHeaderExtension {
    let id = buf[0];
    let length_bytes = match id {
        0 => 0,
        _ => buf[1] + 1,
    };
    // The length field is in the second byte, and the '2' is to account for the id and length
    // field bytes before the actul data
    let he = buf.split_to(2 + length_bytes as usize);
    TwoByteHeaderExtension(he)
}

#[derive(Debug)]
pub enum SomeHeaderExtension {
    OneByteHeaderExtension(OneByteHeaderExtension),
    TwoByteHeaderExtension(TwoByteHeaderExtension),
}

impl SomeHeaderExtension {
    pub fn id(&self) -> u8 {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(e) => e.id(),
            SomeHeaderExtension::TwoByteHeaderExtension(e) => e.id(),
        }
    }

    pub fn data(&self) -> Bytes {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(e) => e.data(),
            SomeHeaderExtension::TwoByteHeaderExtension(e) => e.data(),
        }
    }
}

pub fn read_header_extensions(buf: Bytes) -> HashMap<u8, SomeHeaderExtension> {
    // TODO: should be consistent with use of cursor/bitcursor and Vec<u8> and Bytes
    let mut cursor = Cursor::new(buf);

    let ext_type = cursor.get_u16();
    // Length field is length in 4 byte words
    let length_bytes = cursor.get_u16() * 4;
    let buf = cursor.into_inner();

    let mut header_extensions_bytes = buf.slice(4..).slice(..length_bytes as usize);

    let mut header_extensions: HashMap<u8, SomeHeaderExtension> = HashMap::new();
    while !header_extensions_bytes.is_empty() {
        let ext = if TwoByteHeaderExtension::type_matches(ext_type) {
            SomeHeaderExtension::TwoByteHeaderExtension(read_two_byte_header_extension(
                &mut header_extensions_bytes,
            ))
        } else if OneByteHeaderExtension::type_matches(ext_type) {
            SomeHeaderExtension::OneByteHeaderExtension(read_one_byte_header_extension(
                &mut header_extensions_bytes,
            ))
        } else {
            // TODO: change this to result
            panic!("Invalid header extension type: {ext_type:x?}");
        };

        header_extensions.insert(ext.id(), ext);
    }
    header_extensions
}

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use super::read_header_extensions;

    #[test]
    fn test_one_byte_header_extensions() {
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0xBE, 0xDE, 0x00, 0x01,
            0x10, 0xFF, 0x00, 0x00
        ];

        let bytes = Bytes::from(data);
        let he = read_header_extensions(bytes);
        // The padding bytes are parsed as a header extension
        assert_eq!(he.len(), 2);
        let ext_one = he
            .get(&1)
            .expect("should contain a header extension with ID 1");
        assert_eq!(ext_one.data(), Bytes::from_static(&[0xFF]));
    }

    #[test]
    fn test_one_byte_header_extensions_one_byte_padding() {
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0xBE, 0xDE, 0x00, 0x01,
            0x51, 0x00, 0x01, 0x00

        ];
        let bytes = Bytes::from(data);
        let he = read_header_extensions(bytes);
        assert_eq!(he.len(), 2);
        let ext_one = he
            .get(&5)
            .expect("should contain a header extension with ID 1");
        assert_eq!(ext_one.data(), Bytes::from_static(&[0x00, 0x01]));
    }

    #[test]
    fn test_one_byte_header_extensions_two_bytes_padding() {
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0xBE, 0xDE, 0x00, 0x01,
            0x10, 0xFF, 0x00, 0x00

        ];
        let bytes = Bytes::from(data);
        let he = read_header_extensions(bytes);
        assert_eq!(he.len(), 2);
        let ext_one = he
            .get(&1)
            .expect("should contain a header extension with ID 1");
        assert_eq!(ext_one.data(), Bytes::from_static(&[0xFF]));
    }
}
