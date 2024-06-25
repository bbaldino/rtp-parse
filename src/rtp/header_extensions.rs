use std::{collections::HashMap, io::Cursor};

use anyhow::{Context, Result};
use bitcursor::{
    bit_cursor::BitCursor, bit_read::BitRead, bit_read_exts::BitReadExts, byte_order::NetworkOrder,
    ux::*,
};
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
pub struct OneByteHeaderExtension {
    pub id: u4,
    pub data: Vec<u8>,
}

impl OneByteHeaderExtension {
    pub const TYPE: u16 = 0xBEDE;

    pub fn type_matches(ext_type: u16) -> bool {
        ext_type == Self::TYPE
    }
}

pub fn parse_one_byte_header_extensions(
    buf: &mut impl BitRead,
    length_bytes: u16,
) -> Result<Vec<OneByteHeaderExtension>> {
    let mut extensions = Vec::new();
    let mut bytes_read = 0;
    let mut i = 0;

    while bytes_read < length_bytes {
        let id_len = buf.read_u8().with_context(|| format!("id_len-{i}"))?;
        let id = (id_len & 0xF0) >> 4;
        // If the id is 0, then the length field is ignored completely; otherwise the
        // length field represents the number of bytes of the extension data - 1.
        let ext_data_byte_len = match id {
            0 => 0,
            id => {
                let ext_data_length = (id_len & 0xF) + 1;
                let mut data = vec![0u8; ext_data_length as usize];
                buf.read_exact(&mut data)
                    .with_context(|| format!("data-{i}"))?;
                extensions.push(OneByteHeaderExtension {
                    id: u4::new(id),
                    data,
                });
                ext_data_length
            }
        };
        // 1 for the header, then the length
        bytes_read += 1 + ext_data_byte_len as u16;
        i += 1;
    }

    Ok(extensions)
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
pub struct TwoByteHeaderExtension {
    pub id: u8,
    pub data: Vec<u8>,
}

impl TwoByteHeaderExtension {
    const TYPE_MASK: u16 = 0xFFF0;
    pub const TYPE: u16 = 0x1000;

    pub fn type_matches(ext_type: u16) -> bool {
        (ext_type & Self::TYPE_MASK) == Self::TYPE
    }
}

pub fn parse_two_byte_header_extensions(
    buf: &mut impl BitRead,
    length: u16,
) -> Result<Vec<TwoByteHeaderExtension>> {
    let mut extensions = Vec::new();
    let mut bytes_read = 0;
    let mut i = 0;
    while bytes_read < length {
        let id = buf.read_u8().with_context(|| format!("id-{i}"))?;
        let length = buf.read_u8().with_context(|| format!("length-{i}"))?;
        let mut data = vec![0u8; length as usize];
        if id != 0 {
            buf.read_exact(&mut data)
                .with_context(|| format!("data-{i}"))?;
            extensions.push(TwoByteHeaderExtension { id, data });
        }
        bytes_read += 1 + 1 + length as u16;
        i += 1;
    }
    Ok(extensions)
}

#[derive(Debug)]
pub enum SomeHeaderExtension {
    OneByteHeaderExtension(OneByteHeaderExtension),
    TwoByteHeaderExtension(TwoByteHeaderExtension),
}

impl SomeHeaderExtension {
    pub fn has_id(&self, id: u8) -> bool {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(ob) => u8::from(ob.id) == id,
            SomeHeaderExtension::TwoByteHeaderExtension(tb) => tb.id == id,
        }
    }

    pub fn get_id(&self) -> u8 {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(ob) => ob.id.into(),
            SomeHeaderExtension::TwoByteHeaderExtension(tb) => tb.id,
        }
    }

    pub fn get_data(&self) -> &[u8] {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(ob) => &ob.data,
            SomeHeaderExtension::TwoByteHeaderExtension(tb) => &tb.data,
        }
    }
}

pub fn parse_header_extensions(buf: &mut impl BitRead) -> Result<Vec<SomeHeaderExtension>> {
    let ext_type = buf.read_u16::<NetworkOrder>().context("extensions type")?;
    let length_bytes = buf
        .read_u16::<NetworkOrder>()
        .context("extensions length")?
        * 4; // the field is the count of 32 bit words, so multiply by 4 to get the length in bytes

    if TwoByteHeaderExtension::type_matches(ext_type) {
        Ok(parse_two_byte_header_extensions(buf, length_bytes)
            .context("two byte header extensions")?
            .into_iter()
            .map(SomeHeaderExtension::TwoByteHeaderExtension)
            .collect())
    } else if OneByteHeaderExtension::type_matches(ext_type) {
        Ok(parse_one_byte_header_extensions(buf, length_bytes)
            .context("one byte header extensions")?
            .into_iter()
            .map(SomeHeaderExtension::OneByteHeaderExtension)
            .collect())
    } else {
        panic!("invalid header extension type {ext_type:x}");
    }
}

#[derive(Debug)]
pub struct TwoByteHeaderExtension2(Bytes);

impl TwoByteHeaderExtension2 {
    pub fn id(&self) -> u8 {
        self.0[0]
    }

    pub fn data(&self) -> Bytes {
        self.0.slice(2..)
    }
}

/// [`buf`] should start at the beginning of the header extension (the id)
pub fn read_two_byte_header_extension(buf: &mut Bytes) -> TwoByteHeaderExtension2 {
    let length_bytes = buf[1] + 1;
    // The length field is in the second byte, and the '2' is to account for the id and length
    // field bytes before the actul data
    let he = buf.split_to(2 + length_bytes as usize);
    TwoByteHeaderExtension2(he)
}

#[derive(Debug)]
pub struct OneByteHeaderExtension2(Bytes);

impl OneByteHeaderExtension2 {
    pub fn id(&self) -> u8 {
        (self.0[0] & 0xF0) >> 4
    }

    pub fn data(&self) -> Bytes {
        self.0.slice(1..)
    }
}

pub fn read_one_byte_header_extension(buf: &mut Bytes) -> OneByteHeaderExtension2 {
    let length_bytes = (buf[0] & 0xF) + 1;
    // TODO: here (and above) i think we need to validate against buf.len() before splitting
    let he = buf.split_to(1 + length_bytes as usize);

    OneByteHeaderExtension2(he)
}

#[derive(Debug)]
pub enum SomeHeaderExtension2 {
    OneByteHeaderExtension(OneByteHeaderExtension2),
    TwoByteHeaderExtension(TwoByteHeaderExtension2),
}

impl SomeHeaderExtension2 {
    pub fn id(&self) -> u8 {
        match self {
            SomeHeaderExtension2::OneByteHeaderExtension(e) => e.id(),
            SomeHeaderExtension2::TwoByteHeaderExtension(e) => e.id(),
        }
    }

    pub fn data(&self) -> Bytes {
        match self {
            SomeHeaderExtension2::OneByteHeaderExtension(e) => e.data(),
            SomeHeaderExtension2::TwoByteHeaderExtension(e) => e.data(),
        }
    }
}

pub fn read_header_extensions(buf: Bytes) -> HashMap<u8, SomeHeaderExtension2> {
    // TODO: should be consistent with use of cursor/bitcursor and Vec<u8> and Bytes
    let mut cursor = Cursor::new(buf);

    let ext_type = cursor.get_u16();
    // Length field is length in 4 byte words
    let length_bytes = cursor.get_u16() * 4;
    let buf = cursor.into_inner();

    let mut header_extensions_bytes = buf.slice(4..).slice(..length_bytes as usize);

    let mut header_extensions: HashMap<u8, SomeHeaderExtension2> = HashMap::new();
    while !header_extensions_bytes.is_empty() {
        let ext = if TwoByteHeaderExtension::type_matches(ext_type) {
            SomeHeaderExtension2::TwoByteHeaderExtension(read_two_byte_header_extension(
                &mut header_extensions_bytes,
            ))
        } else if OneByteHeaderExtension::type_matches(ext_type) {
            SomeHeaderExtension2::OneByteHeaderExtension(read_one_byte_header_extension(
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
}
