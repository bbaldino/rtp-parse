use anyhow::{Context, Result};
use bitcursor::{bit_read::BitRead, bit_read_exts::BitReadExts, byte_order::NetworkOrder, ux::*};

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
