const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

/// The slowest K[X]/(X^d+1) ring ever
pub fn QuotientPolyRing(d: comptime_int, K: type) type {
    return struct {
        const Self = @This();

        /// a_0 + a_1*x + a_2*x^2 + ... a_{d-1}*x^{d-1}
        c: [d]K,

        pub fn add(self: *Self, other: Self) *Self {
            for (0..d) |i| self.c[i] += other.c[i];
            return self;
        }

        pub fn sub(self: *Self, other: Self) *Self {
            for (0..d) |i| self.c[i] -= other.c[i];
            return self;
        }

        pub fn mul(self: *Self, other: Self) *Self {
            var tmp: [2 * d - 1]K = .{0} ** (2 * d - 1);
            for (0..d) |i| {
                if (self.c[i] == 0) continue;
                for (0..d) |j| tmp[i + j] += self.c[i] * other.c[j];
            }
            for (0..d - 1) |i| self.c[i] = tmp[i] - tmp[i + d];
            self.c[d - 1] = tmp[d - 1];
            return self;
        }
    };
}

test "test add" {
    const P = QuotientPolyRing(4, i4096);

    var p1: P = .{ .c = .{ 0, 1, 2, 3 } };
    const p2: P = .{ .c = .{ 4, 5, 6, 7 } };

    _ = p1.add(p2);
    try testing.expectEqual(P{ .c = .{ 4, 6, 8, 10 } }, p1);
}

test "test sub" {
    const P = QuotientPolyRing(4, i4096);

    var p1: P = .{ .c = .{ 0, 1, 2, 3 } };
    const p2: P = .{ .c = .{ 4, 5, 6, 7 } };

    _ = p1.sub(p2);
    try testing.expectEqual(P{ .c = .{ -4, -4, -4, -4 } }, p1);
}

test "test mul" {
    const P = QuotientPolyRing(4, i4096);

    var p1: P = .{ .c = .{ 0, 1, 2, 3 } };
    const p2: P = .{ .c = .{ 4, 5, 6, 7 } };

    _ = p1.mul(p2);
    try testing.expectEqual(P{ .c = .{ -34, -28, -8, 28 } }, p1);
}
