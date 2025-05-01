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
///    ```text
///        0
///        0 1 2 3 4 5 6 7
///       +-+-+-+-+-+-+-+-+
///       |  ID   |  len  |
///       +-+-+-+-+-+-+-+-+
///    ```
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
#[derive(Debug, PartialEq)]
pub struct OneByteHeaderExtension {
    id: u4,
    data: Bits,
}

impl OneByteHeaderExtension {
    pub const TYPE: u16 = 0xBEDE;

    pub fn type_matches(ext_type: u16) -> bool {
        ext_type == Self::TYPE
    }

    pub fn new(id: u4, data: Bits) -> Self {
        Self { id, data }
    }

    pub fn id(&self) -> u4 {
        self.id
    }

    pub fn data(&self) -> &[u8] {
        self.data.chunk_bytes()
    }
}

impl From<OneByteHeaderExtension> for SomeHeaderExtension {
    fn from(value: OneByteHeaderExtension) -> Self {
        SomeHeaderExtension::OneByteHeaderExtension(value)
    }
}

impl<B: BitBuf> ParselyRead<B> for OneByteHeaderExtension {
    type Ctx = ();

    fn read<T: ByteOrder>(buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<Self> {
        let id = buf.get_u4().context("id")?;

        // Get the length of the entire extension (including the id/len byte)
        let data_length_bytes = match id {
            // A 0 id means we've hit the end of the extensions
            i if i == 0 => {
                // Consume the rest of this byte
                let _ = buf.get_u4();
                0
            }
            // 1 is for the fact that, in one-byte extensions, the length field is the number of
            // bytes minus 1
            _ => {
                let length: usize = buf.get_u4().context("length")?.into();
                // In one-byte header extensions, the length field value is the length in bytes
                // minus one, so add one here to get the actual data length in bytes
                length + 1
            }
        };

        if buf.remaining_bytes() < data_length_bytes {
            bail!(
                "Header extension length was {data_length_bytes} but buffer only has {} bytes remaining",
                buf.remaining_bytes()
            );
        }
        let data = Bits::copy_from_bytes(&buf.chunk_bytes()[..data_length_bytes]);
        buf.advance_bytes(data_length_bytes);
        Ok(OneByteHeaderExtension { id, data })
    }
}

impl<B: BitBufMut> ParselyWrite<B> for OneByteHeaderExtension {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        buf.put_u4(self.id).context("Writing field 'id'")?;
        let data_length_bytes = self.data.len_bytes();
        let length_field = u4::try_from(data_length_bytes - 1).context("fitting length in u4")?;
        buf.put_u4(length_field).context("Writing field 'length'")?;
        buf.try_put_slice_bytes(self.data())
            .context("Writing field 'data'")?;

        Ok(())
    }
}

impl_stateless_sync!(OneByteHeaderExtension);

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
#[derive(Debug, PartialEq)]
pub struct TwoByteHeaderExtension {
    id: u8,
    data: Bits,
}

impl TwoByteHeaderExtension {
    const TYPE_MASK: u16 = 0xFFF0;
    pub const TYPE: u16 = 0x1000;

    pub fn type_matches(ext_type: u16) -> bool {
        (ext_type & Self::TYPE_MASK) == Self::TYPE
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn data(&self) -> &[u8] {
        self.data.chunk_bytes()
    }
}

impl From<TwoByteHeaderExtension> for SomeHeaderExtension {
    fn from(value: TwoByteHeaderExtension) -> Self {
        SomeHeaderExtension::TwoByteHeaderExtension(value)
    }
}

impl<B: BitBuf> ParselyRead<B> for TwoByteHeaderExtension {
    type Ctx = ();

    /// [`buf`] should start at the beginning of the header extension (the id)
    fn read<T: ByteOrder>(buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<Self> {
        let id = buf.get_u8().context("id")?;
        let data_length_bytes = match id {
            0 => 0,
            _ => buf.get_u8().context("length")?,
        } as usize;
        if buf.remaining_bytes() < data_length_bytes {
            bail!(
                "Header extension length was {data_length_bytes} but buffer only has {} bytes remaining",
                buf.remaining_bytes()
            );
        }
        let data = Bits::copy_from_bytes(&buf.chunk_bytes()[..data_length_bytes]);
        buf.advance_bytes(data_length_bytes);
        Ok(TwoByteHeaderExtension { id, data })
    }
}

impl<B: BitBufMut> ParselyWrite<B> for TwoByteHeaderExtension {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        buf.put_u8(self.id()).context("Writing field 'id'")?;
        let data_length_bytes = self.data().len();
        buf.put_u8(data_length_bytes as u8)
            .context("Writing field 'length'")?;
        buf.try_put_slice_bytes(self.data())
            .context("Writing field 'data'")?;

        Ok(())
    }
}

impl_stateless_sync!(TwoByteHeaderExtension);

#[derive(Debug, PartialEq)]
pub enum SomeHeaderExtension {
    OneByteHeaderExtension(OneByteHeaderExtension),
    TwoByteHeaderExtension(TwoByteHeaderExtension),
}

impl SomeHeaderExtension {
    pub fn id(&self) -> u8 {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(e) => e.id().into(),
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

impl<B: BitBufMut> ParselyWrite<B> for SomeHeaderExtension {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        match self {
            SomeHeaderExtension::OneByteHeaderExtension(he) => he.write::<T>(buf, ()),
            SomeHeaderExtension::TwoByteHeaderExtension(he) => he.write::<T>(buf, ()),
        }
    }
}

impl_stateless_sync!(SomeHeaderExtension);

#[derive(Debug, Default, PartialEq)]
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
    pub fn add_extension<T: Into<SomeHeaderExtension>>(
        &mut self,
        ext: T,
    ) -> Option<SomeHeaderExtension> {
        let ext: SomeHeaderExtension = ext.into();
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
// disabled means parsing should stop immediately, so maybe we do need to pass it.  We could pass
// it as context?
impl<B: BitBuf> ParselyRead<B> for HeaderExtensions {
    type Ctx = ();

    fn read<T: ByteOrder>(buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<Self> {
        let mut header_extensions = HashMap::new();

        let ext_type = buf
            .get_u16::<NetworkOrder>()
            .context("Reading header extensions profile")?;
        let ext_length = buf
            .get_u16::<NetworkOrder>()
            .context("Reading header extensions length")?;

        // 'ext_length' describes the length in 4-byte words
        let ext_length_bytes = (ext_length * 4) as usize;
        let mut extensions_buf = buf.take_bytes(ext_length_bytes);

        while extensions_buf.has_remaining_bytes() {
            let extension = if OneByteHeaderExtension::type_matches(ext_type) {
                // Peek at the id so we can tell if this is a two-byte extension nested amongst
                // one-byte extensions or not
                let id = (&extensions_buf.chunk_bits()[..4]).as_u4();
                if id == 0xF {
                    // This was a 'fake' ID header to indicate that this is a 2-byte extension mixed
                    // in with one-byte extensions.  Swallow the first byte to
                    // get to the real 2-byte extension ID.
                    let _ = extensions_buf.get_u8();
                    let he = TwoByteHeaderExtension::read::<T>(&mut extensions_buf, ())
                        .context("One-byte header extension")?;
                    SomeHeaderExtension::TwoByteHeaderExtension(he)
                } else {
                    let he = OneByteHeaderExtension::read::<T>(&mut extensions_buf, ())
                        .context("One-byte header extension")?;
                    SomeHeaderExtension::OneByteHeaderExtension(he)
                }
            } else if TwoByteHeaderExtension::type_matches(ext_type) {
                let he = TwoByteHeaderExtension::read::<T>(&mut extensions_buf, ())
                    .context("One-byte header extension")?;
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
}

impl<B: BitBufMut> ParselyWrite<B> for HeaderExtensions {
    type Ctx = ();

    fn write<T: ByteOrder>(&self, buf: &mut B, _ctx: Self::Ctx) -> ParselyResult<()> {
        let len_start = buf.remaining_mut_bytes();
        self.0
            .values()
            .map(|he| he.write::<T>(buf, ()))
            .collect::<ParselyResult<Vec<_>>>()
            .context("Writing header extensions")?;

        while (len_start - buf.remaining_mut_bytes()) % 4 != 0 {
            buf.put_u8(0).context("Padding")?;
        }

        Ok(())
    }
}

impl_stateless_sync!(HeaderExtensions);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_byte_header_extension_parse() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0x10, 0xFF, 0x00, 0x00
        ]);

        let he = OneByteHeaderExtension::read::<NetworkOrder>(&mut bits, ()).unwrap();
        assert_eq!(he.id(), 1);
        assert_eq!(he.data(), &[0xFF]);
    }

    #[test]
    fn test_two_byte_header_extension_parse() {
        #[rustfmt::skip]
        let mut bits = Bits::from_static_bytes(&[
            0x01, 0x01, 0xFF, 0x00, 0x00
        ]);
        let he = TwoByteHeaderExtension::read::<NetworkOrder>(&mut bits, ()).unwrap();
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

        let exts = HeaderExtensions::read::<NetworkOrder>(&mut bits, ()).unwrap();
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
        let exts = HeaderExtensions::read::<NetworkOrder>(&mut bits, ()).unwrap();
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
        let exts = HeaderExtensions::read::<NetworkOrder>(&mut bits, ()).unwrap();
        assert_eq!(exts.len(), 3);
        let ext = exts.get_by_id(1).unwrap();
        assert_eq!(ext.data(), &[0xFF]);
        let ext = exts.get_by_id(7).unwrap();
        assert_eq!(ext.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let ext = exts.get_by_id(4).unwrap();
        assert_eq!(ext.data(), &[0x42]);
    }
}
