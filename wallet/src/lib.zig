//! wallet-zig (skein next): what programs signing through the signer take from the wallet
//! library — the BRC-100 wire frames (`wire`) and BRC-29 (`brc29`). The combined wallet record,
//! the overlay-in-wallet and the transaction builder are gone (no caller). The chain parts —
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
/// bsvz itself, for programs built on this library.
pub const bsvz = @import("bsvz");

test {
    @import("std").testing.refAllDecls(@This());
}
