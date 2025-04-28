use std::collections::HashMap;

use parsely_rs::*;

/// https://datatracker.ietf.org/doc/html/rfc8285#section-4.2
/// One Byte Header
///
/// In the one-byte header form of extensions, the 16-bit value required
///    by the RTP specification for a header extension, labeled in the RTP
///    specification as "defined by profile", MUST have the fixed bit
///    pattern 0xBEDE (the pattern was picked for the trivial reason that
///    the first version of this specification was written on May 25th --
///    the feast day of the Venerable Bede).
///
///    Each extension element MUST start with a byte containing an ID and a
///    length:
///
///        0
///        0 1 2 3 4 5 6 7
///       +-+-+-+-+-+-+-+-+
///       |  ID   |  len  |
///       +-+-+-+-+-+-+-+-+
///
///    The 4-bit ID is the local identifier of this element in the range
///    1-14 inclusive.  In the signaling section, this is referred to as the
///    valid range.
///
///    The local identifier value 15 is reserved for a future extension and
///    MUST NOT be used as an identifier.  If the ID value 15 is
///    encountered, its length field MUST be ignored, processing of the
///    entire extension MUST terminate at that point, and only the extension
///    elements present prior to the element with ID 15 SHOULD be
///    considered.
///
///    The 4-bit length is the number, minus one, of data bytes of this
///    header extension element following the one-byte header.  Therefore,
///    the value zero (0) in this field indicates that one byte of data
///    follows, and a value of 15 (the maximum) indicates element data of
///    16 bytes.  (This permits carriage of 16-byte values, which is a
///    common length of labels and identifiers, while losing the possibility
///    of zero-length values, which would often be padded anyway.)
// TODO: I remember how costly parsing header extensions was at volume, so keeping this a
// "lens-style" view of the data rather than parsing the individual field may make sense?
#[derive(Debug)]
pub struct OneByteHeaderExtension(Bits);

impl OneByteHeaderExtension {
    pub const TYPE: u16 = 0xBEDE;

    pub fn type_matches(ext_type: u16) -> bool {
        ext_type == Self::TYPE
    }

    pub fn id(&self) -> u8 {
        // Header extensions have to be byte aligned
        assert!(self.0.byte_aligned());
        // TODO: there's no great way to do this with a good bits API, currently.  `get_u4` will
        // advance the buffer, which we don't want.  If we had a way to create the nsw-types from a
        // `BitSlice` (like how sw-integers can be created "from_be_bytes") then that would be
        // useful here.  We could do something like:
        // u4::from_bitslice(self.0[0..4])
        (self.0.chunk_bytes()[0] & 0xF0) >> 4
    }

    // TODO: i think we just want the raw bytes here, not a Bits instance?
    pub fn data(&self) -> &[u8] {
        &self.0.chunk_bytes()[1..]
    }
}

pub fn read_one_byte_header_extension(buf: &mut Bits) -> ParselyResult<OneByteHeaderExtension> {
    let id = (buf.chunk_bytes()[0] & 0xF0) >> 4;

    // Get the length of the entire extension (including the id/len byte)
    let length_bytes = match id {
        // A 0 id means we've hit the end of the extensions
        0 => 1,
        // We add '2' here to get the length of the entire extension (id/len byte + data):
        // 1 is for the id/len byte which we only 'peeked' at above
        // 1 is for the fact that, in one-byte extensions, the length field is the number of bytes
        //   minus 1
        _ => ((buf.chunk_bytes()[0] & 0xF) + 2) as usize,
    };

    if buf.remaining_bytes() < length_bytes {
        bail!(
            "Header extension length was {length_bytes} but buffer only has {} bytes remaining",
            buf.remaining_bytes()
        );
    }
    println!("length bytes = {length_bytes}");
    println!("buf = {buf:?}");
    let he_buffer = buf.split_to_bytes(length_bytes);
    println!("he buff: {he_buffer:?}");
    println!("he remaining: {}", he_buffer.remaining_bytes());
    Ok(OneByteHeaderExtension(he_buffer))
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
pub struct TwoByteHeaderExtension(Bits);

impl TwoByteHeaderExtension {
    const TYPE_MASK: u16 = 0xFFF0;
    pub const TYPE: u16 = 0x1000;

    pub fn type_matches(ext_type: u16) -> bool {
        (ext_type & Self::TYPE_MASK) == Self::TYPE
    }

    pub fn id(&self) -> u8 {
        self.0.chunk_bytes()[0]
    }

    pub fn data(&self) -> &[u8] {
        &self.0.chunk_bytes()[2..]
    }
}

/// [`buf`] should start at the beginning of the header extension (the id)
pub fn read_two_byte_header_extension(buf: &mut Bits) -> ParselyResult<TwoByteHeaderExtension> {
    let id = buf.chunk_bytes()[0];
    let data_length_bytes = match id {
        0 => 0,
        // Add 2 to include the id and length fields
        _ => buf.chunk_bytes()[1],
    } as usize;
    if buf.remaining_bytes() < data_length_bytes + 1 {
        bail!(
            "Header extension length was {data_length_bytes} but buffer only has {} bytes remaining",
            buf.remaining_bytes()
        );
    }
    // The length field is in the second byte, and the '2' is to account for the id and length
    // field bytes before the actul data
    let he = buf.split_to_bytes(2 + data_length_bytes);
    Ok(TwoByteHeaderExtension(he))
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

    pub fn data(&self) -> &[u8] {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(e) => e.data(),
            SomeHeaderExtension::TwoByteHeaderExtension(e) => e.data(),
        }
    }
}

pub struct HeaderExtensions(HashMap<u8, SomeHeaderExtension>);

impl HeaderExtensions {
    /// Returns the number of header extensions
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if there are no extensions present
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if any one-byte header extensions are present
    pub fn has_one_byte(&self) -> bool {
        self.0
            .iter()
            .any(|(_, he)| matches!(he, SomeHeaderExtension::OneByteHeaderExtension(_)))
    }

    /// Returns true if any two-byte header extensions are present
    pub fn has_two_byte(&self) -> bool {
        self.0
            .iter()
            .any(|(_, he)| matches!(he, SomeHeaderExtension::TwoByteHeaderExtension(_)))
    }

    /// Add a new header extension.  Returns the prior extension with the same ID, if there was one
    pub fn add_extension(&mut self, ext: SomeHeaderExtension) -> Option<SomeHeaderExtension> {
        self.0.insert(ext.id(), ext)
    }

    /// Remove the header extension with the given `id`, if it existed.  Returns the remobed
    /// extension, if there was one.
    pub fn remove_extension_by_id(&mut self, id: u8) -> Option<SomeHeaderExtension> {
        self.0.remove(&id)
    }

    pub fn get_by_id(&self, id: u8) -> Option<&SomeHeaderExtension> {
        self.0.get(&id)
    }
}

impl<'a> IntoIterator for &'a HeaderExtensions {
    type Item = (&'a u8, &'a SomeHeaderExtension);

    type IntoIter = std::collections::hash_map::Iter<'a, u8, SomeHeaderExtension>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Reader header extensions from the given buf until it's empty.  The given buffer should start at
/// the beginning of the header extensions block. `extmap_allow_mixed` denotes whether or not
/// mixing one- and two-byte header extensions should be allowed.
// TODO: I wanted to avoid having to pass 'extmap-allow-mixed' here, but an ID of 15 with it
// disabled means parsing should stop immediately, so maybe we do need to pass it.
pub fn read_header_extensions(buf: &mut Bits) -> ParselyResult<HeaderExtensions> {
    let mut header_extensions = HashMap::new();

    let ext_type = buf
        .get_u16::<NetworkOrder>()
        .context("Reading header extensions profile")?;
    let ext_length = buf
        .get_u16::<NetworkOrder>()
        .context("Reading header extensions length")?;

    // 'ext_length' describes the length in 4-byte words
    let ext_length_bytes = (ext_length * 4) as usize;
    let current_bytes_remaining = buf.remaining_bytes();

    // Using `buf.take_bytes(ext_length_bytes)` would be a lot cleaner here, but then we lose the
    // `Bits` instance and downstream functions would have to operate on `BitBuf` instead of `Bits`
    // directly.  We want those downstream types to be able to save off the data without copying,
    // so do this to keep things using `Bits` directly.
    // TODO: one downside though is that this check won't prevent an individual extension parsing
    // from going 'past' the limit as long as it starts before.
    while buf.remaining_bytes() > current_bytes_remaining - ext_length_bytes {
        println!("Length of extensions: {ext_length_bytes} bytes.  Starting bytes remaining: {current_bytes_remaining}, current bytes remaining: {}", buf.remaining_bytes());
        let extension = if OneByteHeaderExtension::type_matches(ext_type) {
            // Both one- and two-byte extensions may be present
            // TODO: would be nice to clean this up.  If we had as_uXX methods for BitSlice that'd
            // probably feel better
            let id = &buf.chunk_bytes()[0] & 0xF0;
            if id == 0xF0 {
                // This was a 'fake' ID header to indicate that this is a 2-byte extension mixed in
                // with one-byte extensions.  Swallow the first byte to get to the real 2-byte
                // extension ID.
                let _ = buf.get_u8();
                let he = read_two_byte_header_extension(buf)?;
                SomeHeaderExtension::TwoByteHeaderExtension(he)
            } else {
                let he = read_one_byte_header_extension(buf)?;
                SomeHeaderExtension::OneByteHeaderExtension(he)
            }
        } else if TwoByteHeaderExtension::type_matches(ext_type) {
            let he = read_two_byte_header_extension(buf)?;
            SomeHeaderExtension::TwoByteHeaderExtension(he)
        } else {
            bail!("Encountered invalid header extension block type: {ext_type:x}");
        };
        if extension.id() != 0 {
            header_extensions.insert(extension.id(), extension);
        }
    }

    Ok(HeaderExtensions(header_extensions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_byte_header_extension_parse() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0x10, 0xFF, 0x00, 0x00
        ]);

        let he = read_one_byte_header_extension(&mut bits).unwrap();
        assert_eq!(he.id(), 1);
        assert_eq!(he.data(), &[0xFF]);
    }

    #[test]
    fn test_two_byte_header_extension_parse() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0x01, 0x01, 0xFF, 0x00, 0x00
        ]);
        let he = read_two_byte_header_extension(&mut bits).unwrap();
        assert_eq!(he.id(), 1);
        assert_eq!(he.data(), &[0xFF]);
    }

    #[test]
    fn test_header_extensions_parse_all_one_byte() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0xBE, 0xDE, 0x00, 0x02,
            0x10, 0xFF, 0x00, 0x00,
            0x21, 0xDE, 0xAD, 0x00
        ]);

        let exts = read_header_extensions(&mut bits).unwrap();
        assert_eq!(exts.len(), 2);
        let ext1 = exts.get_by_id(1).unwrap();
        assert_eq!(ext1.data(), &[0xFF]);

        let ext2 = exts.get_by_id(2).unwrap();
        assert_eq!(ext2.data(), &[0xDE, 0xAD]);
    }

    #[test]
    fn test_header_extensions_parse_all_two_byte() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0x10, 0x00, 0x00, 0x03,
            0x07, 0x04, 0xDE, 0xAD,
            0xBE, 0xEF, 0x04, 0x01,
            0x42, 0x00, 0x00, 0x00,
        ]);
        let exts = read_header_extensions(&mut bits).unwrap();
        assert_eq!(exts.len(), 2);
        let ext7 = exts.get_by_id(7).unwrap();
        assert_eq!(ext7.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let ext4 = exts.get_by_id(4).unwrap();
        assert_eq!(ext4.data(), &[0x42]);
    }

    #[test]
    fn test_header_extensions_parse_mixed() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0xBE, 0xDE, 0x00, 0x04,
            // One-byte extension
            0x10, 0xFF, 0x00, 0x00,
            // Two-byte extension
            0xF0, 0x07, 0x04, 0xDE, 
            // Two-byte extension
            0xAD, 0xBE, 0xEF, 0xF0,
            0x04, 0x01, 0x42, 0x00, 
        ]);
        let exts = read_header_extensions(&mut bits).unwrap();
        assert_eq!(exts.len(), 3);
        let ext = exts.get_by_id(1).unwrap();
        assert_eq!(ext.data(), &[0xFF]);
        let ext = exts.get_by_id(7).unwrap();
        assert_eq!(ext.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let ext = exts.get_by_id(4).unwrap();
        assert_eq!(ext.data(), &[0x42]);
    }
}
