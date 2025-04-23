### Buffer types

I think we need to keep PacketBuffer around and maybe can find some way to make
the ParselyRead/ParselyWrite traits generic around the buffer trait so that we
could use a more capable buffer trait (PacketBuffer) for the rtp code? Using
what BitRead/BitWrite has alone makes things like consuming/adding padding
really tough (BitRead/BitWrite has no concept of position and can't 'peek' or
seek backwards)

--> Ended up adding a custom buffer_type hook in parsely to support this

### Builders vs Default/manual builder APIs

I want to make the creation of packets both a) easy and b) ergonomic in the
sense that fields that _must_ be set to a certain value are done automatically
(e.g. the packet type field should be set correctly in the header when creating
an instance of a certain packet).

I started out doing this manually with a combination of Default and manually
adding APIs.  At some point I started to think that maybe using typed-builder
would be better for this, but after giving that a try I'm not sure it works
out.  For example, when you want to create some rtcp packet, you want to set
the packet type in the header correctly, but using typed-builder it means you
need to set this default in an attribute, which gets a bit verbose:

```rust
#[derive(TypedBuilder, ...)]
struct MyRtcpPacket {
  #[builder(default = RtcpHeader::builder().packet_type(MyRtcpPacket::PT).builder())]
  header: RtcpHeader,
  ...
}
```

vs using a manual Default impl which isn't shorter, but feels cleaner since
it's in actual rust code:

```rust
impl Default for MyRtcpPacket {
  fn default() -> Self {
    Self {
      header: RtcpHeader::default().packet_type(MyRtcpPacket::PT),
      ...
    }
  }
}
```

so at this point I think I'm going to go back to Default impls and manual APIs
and get rid of typed-builder

### Sync arguments

Going back and forth a bit on what should be treated as a "sync argument" (passed to the sync method) and what shouldn't.  I think my first thought was:

- "dynamic" values which are based on the payload should/need to be passed to
sync (payload length, report count)
- "static" values can just be set upon creation (i.e. in Default impl)

There are a couple weird examples of this: FB packets use the report count
field to denote the FMT so in those cases the field is "static" and would be
set in the Default impl but then would also need to be passed to sync, which is
a bit annoying but not a huge deal.  But that made me wonder if packet type
should also be passed to sync?  I think as long as nothing uses that
"dynamically" we can leave it out.

### RTP packets

Two approaches I'm considering when dealing with RTP packets:

- Parse things completely (i.e. read/copy header fields into a header struct)
- Keep a contiguous buffer (perhaps split views via Bytes) and for things like
the header use a "lens" approach (where reads/writes index into the buffer
directly)

The first approach simplifies things quite a bit, I think, but the performance
implications are unclear.  So I think some amount of investigation into both
styles and some comparisons are needed.

### Sub-buffers

One goal I was really interested in was the concept of a "sub-buffer" where an exact-sized-slice of some kind could be taken and passed to a parsing method.  This could help ensure both that the parsing method didn't read too much data and also that it did consume all the data it was supposed to.  Unfortunately this concept doesn't work
NOTE: The "Take" approach might work here if it's "taking" the reference and it's still available.  webrtc-rs seems to use it this way, need to verify

### Padding

webrtc-rs deals with padding by assuming the start of the buffer some parsing
code is given is aligned and then tracking how much data has been read so it
can then calculate specifically how many bytes need to be consumed.  need to
check if we can do something like that at the parsely layer.

I think what we can do:

When reading, we can save the number of remaining bytes at the start and then
subtract the number of remaining bytes at the end to know how many bytes we
consumed.  we can consume more until that number is word aligned.

when writing, we can save the length of the buffer at the start and then check
it at the end to figure out how much we've written, then add padding until it's
world aligned.
