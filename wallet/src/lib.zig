//! wallet-zig: the wallet's state inside the skein VM (issue #29). Keys and
//! signing stay outside (the oracle); here are the records, the index maps
//! over them, SPV, and BRC-29 payee internalization. The chain parts —
//! headers and our chain tracker, merkle paths, BEEF, SPV, the record store —
//! are the `chain` module (shruggr/skein#78), re-exported here under the
//! names they always had.
const c = @import("chain");
pub const cbor = c.cbor;
pub const header = c.header;
pub const beef = c.beef;
pub const chain = c.chain;
pub const spv = c.spv;
pub const store = c.store;
pub const merkle = c.merkle;
/// The chain module's own state (the chain app's records), for a reader of the chain head.
pub const chainstate = c.state;
pub const brc29 = @import("brc29.zig");
pub const wire = @import("wire.zig");
pub const builder = @import("builder.zig");
pub const wallet = @import("wallet.zig");
pub const overlay = @import("overlay.zig");
/// bsvz itself, for programs built on this library (programs/overlay).
pub const bsvz = @import("bsvz");

test {
    @import("std").testing.refAllDecls(@This());
}
