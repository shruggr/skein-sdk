//! The chain library (shruggr/skein#78): what verifying a transaction
//! against the chain takes, and the chain state the chain module
//! (shruggr/skein-chain) keeps — headers and our chain tracker, merkle
//! paths as IPLD nodes, BEEF, SPV, the record store and its index maps, and
//! `state`: the chain app's records (transactions, proofs, spends,
//! settlement, registered broadcasts), which every reader of the chain
//! state reads by CID. Over bsvz. The wallet library (`wallet`) builds on
//! this module and re-exports it under the names it always had.
pub const cbor = @import("cbor.zig");
pub const header = @import("header.zig");
pub const beef = @import("beef.zig");
pub const chain = @import("chain.zig");
pub const spv = @import("spv.zig");
pub const merkle = @import("merkle.zig");
pub const store = @import("store.zig");
pub const state = @import("state.zig");
/// The header chain an image tree carries (shruggr/skein#132): its layout, `load` into an empty state, `write`.
pub const image = @import("image.zig");
/// The BEEF pointer record (shruggr/skein#121) and `beefOf`, its encoder.
pub const record = @import("record.zig");
/// bsvz itself, for programs built on this library.
pub const bsvz = @import("bsvz");

test {
    @import("std").testing.refAllDecls(@This());
}
