const std = @import("std");
const testing = std.testing;
const ff = std.crypto.ff;

/// The slowest Z_q[X]/(X^d+1) ring ever
pub fn QuotientPoly(d: comptime_int, qbits: comptime_int) type {
    return struct {
        const Self = @This();

        pub const M = ff.Modulus(qbits);

        /// a_0 + a_1*x + a_2*x^2 + ... a_{d-1}*x^{d-1}
        c: [d]M.Fe,

        pub fn add(self: *Self, other: Self, m: M) *Self {
            for (0..d) |i| self.c[i] = m.add(self.c[i], other.c[i]);
            return self;
        }

        pub fn sub(self: *Self, other: Self, m: M) *Self {
            for (0..d) |i| self.c[i] = m.sub(self.c[i], other.c[i]);
            return self;
        }

        pub fn mul(self: *Self, other: Self, m: M) *Self {
            var tmp: [2 * d - 1]M.Fe = .{m.zero} ** (2 * d - 1);
            for (0..d) |i| {
                if (self.c[i].isZero()) continue;
                for (0..d) |j| tmp[i + j] = m.add(tmp[i + j], m.mul(self.c[i], other.c[j]));
            }
            for (0..d - 1) |i| self.c[i] = m.sub(tmp[i], tmp[i + d]);
            self.c[d - 1] = tmp[d - 1];
            return self;
        }
    };
}

test "test add" {
    const q = 7;
    const P = QuotientPoly(4, 4096);
    const m = try P.M.fromPrimitive(u16, q);

    var p1: P = .{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(0, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(1, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(2, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(3, q)),
    } };
    const p2: P = .{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(5, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(6, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(7, q)),
    } };

    _ = p1.add(p2, m);
    try testing.expectEqual(P{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(6, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(8, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(10, q)),
    } }, p1);
}

test "test sub" {
    const q = 7;
    const P = QuotientPoly(4, 4096);
    const m = try P.M.fromPrimitive(u16, q);

    var p1: P = .{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(0, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(1, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(2, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(3, q)),
    } };
    const p2: P = .{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(5, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(6, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(7, q)),
    } };

    _ = p1.sub(p2, m);
    try testing.expectEqual(P{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(-4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(-4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(-4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(-4, q)),
    } }, p1);
}

test "test mul" {
    const q = 7;
    const P = QuotientPoly(4, 4096);
    const m = try P.M.fromPrimitive(u16, q);

    var p1: P = .{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(0, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(1, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(2, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(3, q)),
    } };
    const p2: P = .{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(4, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(5, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(6, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(7, q)),
    } };

    _ = p1.mul(p2, m);
    try testing.expectEqual(P{ .c = .{
        try P.M.Fe.fromPrimitive(u64, m, @mod(-34, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(-28, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(-8, q)),
        try P.M.Fe.fromPrimitive(u64, m, @mod(28, q)),
    } }, p1);
}
