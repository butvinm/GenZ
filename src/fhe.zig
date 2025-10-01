const std = @import("std");

pub const SimpleSomewhat = struct {
    pub fn enc(pk: u128, m: u1) u4096 {
        const R: u4096 = std.crypto.random.int(u256);
        const r: u4096 = std.crypto.random.int(u32);
        return R * pk + r * 2 + m;
    }

    pub fn dec(pk: u128, ct: u4096) u1 {
        return @intCast(@mod(@mod(ct, pk), 2));
    }
};

test {
    const pk = 123123123123123123;
    const ss = SimpleSomewhat;

    try std.testing.expectEqual(0, ss.dec(pk, ss.enc(pk, 0)));
    try std.testing.expectEqual(1, ss.dec(pk, ss.enc(pk, 1)));

    // additions
    try std.testing.expectEqual(0, ss.dec(pk, ss.enc(pk, 0) + ss.enc(pk, 0)));
    try std.testing.expectEqual(1, ss.dec(pk, ss.enc(pk, 0) + ss.enc(pk, 1)));
    try std.testing.expectEqual(1, ss.dec(pk, ss.enc(pk, 1) + ss.enc(pk, 0)));
    try std.testing.expectEqual(0, ss.dec(pk, ss.enc(pk, 1) + ss.enc(pk, 1)));

    // multiplication
    try std.testing.expectEqual(0, ss.dec(pk, ss.enc(pk, 0) * ss.enc(pk, 0)));
    try std.testing.expectEqual(0, ss.dec(pk, ss.enc(pk, 0) * ss.enc(pk, 1)));
    try std.testing.expectEqual(0, ss.dec(pk, ss.enc(pk, 1) * ss.enc(pk, 0)));
    try std.testing.expectEqual(1, ss.dec(pk, ss.enc(pk, 1) * ss.enc(pk, 1)));
}
