//! The host chain (shruggr/skein#156, #133): the header chain a host keeps
//! once for all its instances, in the host's `host/chain` set, written only by
//! the kernel's tracker (skein kernel-zig/src/host_chain.zig) and read by
//! every instance through the chain exception. Its record:
//!
//!   {kind: "host-chain", network: "main" | "test" | "regtest",
//!    maps: {headers: <MST root>, heights: <MST root>},
//!    tip: {height, hash: <display hex>}}
//!
//! `headers` (height → header) and `heights` (block hash → height) are the
//! chain tracker's two maps (chain.zig), the same layout an instance's chain
//! state names: an instance's `chain/state` points at them
//! (`State.pointAt`), never copies them. Old roots stay readable (blocks are
//! never deleted), so an event naming an older record resolves on replay.
const std = @import("std");
const cbor = @import("cbor.zig");
const hdr = @import("header.zig");
const chain_mod = @import("chain.zig");
const store_mod = @import("store.zig");
const image = @import("image.zig");

const Store = store_mod.Store;
const Map = store_mod.Map;
const Value = cbor.Value;
pub const Network = chain_mod.Network;

pub const kind = "host-chain";

pub const Tip = struct { height: u32, hash: [32]u8 };

/// A host chain record, read.
pub const Record = struct {
    network: Network,
    headers: ?[]const u8,
    heights: ?[]const u8,
    tip: ?Tip,
};

/// The host chain record `cid` names.
pub fn read(a: std.mem.Allocator, s: Store, cid: []const u8) !Record {
    const v = try s.getValue(a, cid);
    if (!std.mem.eql(u8, v.getText("kind") orelse "", kind)) return error.BadHostChain;
    const network = Network.parse(v.getText("network") orelse "") orelse return error.BadHostChain;
    const maps = v.get("maps") orelse return error.BadHostChain;
    var tip: ?Tip = null;
    if (v.get("tip")) |t| if (t == .map) {
        const height = t.getUint("height") orelse return error.BadHostChain;
        const hash = hdr.fromHex(t.getText("hash") orelse return error.BadHostChain) catch return error.BadHostChain;
        tip = .{ .height = @intCast(height), .hash = hash };
    };
    return .{ .network = network, .headers = maps.getCid("headers"), .heights = maps.getCid("heights"), .tip = tip };
}

/// The host chain for one write: open at its record (null: a new, empty one), add headers or
/// import an image's, `save` a new record.
pub const Host = struct {
    arena: std.mem.Allocator,
    store: Store,
    network: Network,
    maps: *store_mod.Maps,
    headers: Map,
    heights: Map,

    /// The host chain the record names (null: empty) on `network`; a record of another network is refused.
    pub fn open(arena: std.mem.Allocator, s: Store, record: ?[]const u8, network: Network) !Host {
        const maps = try store_mod.Maps.create(arena, s);
        var h = Host{ .arena = arena, .store = s, .network = network, .maps = maps, .headers = maps.map(null), .heights = maps.map(null) };
        if (record) |c| {
            const r = try read(arena, s, c);
            if (r.network != network) return error.NetworkMismatch;
            h.headers.root = r.headers;
            h.heights.root = r.heights;
        }
        return h;
    }

    pub fn chain(self: *Host) chain_mod.Chain {
        return .{ .arena = self.arena, .store = self.store, .headers = &self.headers, .heights = &self.heights, .network = self.network };
    }

    /// A run of headers, parents first (`Chain.add`: its checks, the heavier branch replacing ours).
    pub fn add(self: *Host, raws: []const []const u8) !chain_mod.Chain.AddResult {
        return self.chain().add(raws);
    }

    /// The header chain the tree `root` carries (an image's `chain/headers`), into this host chain,
    /// which must be empty (`error.NotEmpty`); null when the tree carries none.
    pub fn import(self: *Host, root: []const u8) !?image.Loaded {
        if ((try self.chain().tip()) != null) return error.NotEmpty;
        return image.loadMaps(self.maps, &self.headers, &self.heights, self.network, root);
    }

    /// The tip: its height and hash; null when the chain is empty.
    pub fn tip(self: *Host) !?Tip {
        const t = (try self.chain().tip()) orelse return null;
        const at = (try self.chain().at(t)) orelse return error.BadRecord;
        return .{ .height = t, .hash = at.hash };
    }

    /// Put every new map node and the record naming the maps' roots and the tip; → its CID. Null
    /// when the chain is empty (no record).
    pub fn save(self: *Host) !?[]const u8 {
        const t = (try self.tip()) orelse return null;
        try self.headers.flush();
        try self.heights.flush();
        const a = self.arena;
        return try self.store.putValue(a, .{ .map = try a.dupe(cbor.Entry, &.{
            .{ .key = "kind", .value = .{ .text = kind } },
            .{ .key = "network", .value = .{ .text = @tagName(self.network) } },
            .{ .key = "maps", .value = .{ .map = try a.dupe(cbor.Entry, &.{
                .{ .key = "headers", .value = .{ .cid = self.headers.root.? } },
                .{ .key = "heights", .value = .{ .cid = self.heights.root.? } },
            }) } },
            .{ .key = "tip", .value = .{ .map = try a.dupe(cbor.Entry, &.{
                .{ .key = "height", .value = .{ .uint = t.height } },
                .{ .key = "hash", .value = .{ .text = try a.dupe(u8, &hdr.toHex(t.hash)) } },
            }) } },
        }) });
    }
};
