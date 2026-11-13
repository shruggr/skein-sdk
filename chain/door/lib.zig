//! chaindoor: the chain app's checks before the entry (skein next, SPEC.md section 6), moved out of
//! the skein kernel: `check` (the BEEF check, `chain.beef`) and the BEEF decoder/encoder it builds
//! the pointer record and the envelope with (`beef`). Over the SDK's codecs (cbor, cid, mst) and
//! the chain module (its BEEF parser and SPV verifier).
pub const check = @import("check.zig");
pub const beef = check.beef;

test {
    _ = check;
}
