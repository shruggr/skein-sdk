//! wallet-zig: the wallet's state inside the skein VM (issue #29). Keys and
//! signing stay outside (the oracle); here are the records, the index maps
//! over them, our own chain tracker, SPV, and BRC-29 payee internalization.
pub const cbor = @import("cbor.zig");
pub const header = @import("header.zig");
pub const beef = @import("beef.zig");
pub const chain = @import("chain.zig");
pub const spv = @import("spv.zig");
pub const brc29 = @import("brc29.zig");
pub const wire = @import("wire.zig");
pub const store = @import("store.zig");
pub const wallet = @import("wallet.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
