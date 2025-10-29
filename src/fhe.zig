const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

/// The slowest K[X]/(X^d+1) ring ever
pub fn QuotientPolyRing(d: comptime_int, K: type) type {
    return struct {
        const Self = @This();

        /// a_0 + a_1*x + a_2*x^2 + ... a_{d-1}*x^{d-1}
        c: @Vector(d, K),

        pub fn add(self: *Self, other: Self) *Self {
            self.c += other.c;
            return self;
        }

        pub fn sub(self: *Self, other: Self) *Self {
            self.c -= other.c;
            return self;
        }

        pub fn mul(self: *Self, other: Self, tmp: *Self) *Self {
            tmp.c = @splat(0);

            for (0..d) |i| {
                if (self.c[i] == 0) continue;
                for (0..d) |j| {
                    const sum_idx = i + j;
                    if (sum_idx < d) {
                        tmp.c[sum_idx] += self.c[i] * other.c[j];
                    } else {
                        tmp.c[sum_idx - d] -= self.c[i] * other.c[j];
                    }
                }
            }

            self.c = tmp.c;
            return self;
        }
    };
}

test "test add" {
    const R = QuotientPolyRing(4, i4096);

    var p1: R = .{ .c = .{ 0, 1, 2, 3 } };
    const p2: R = .{ .c = .{ 4, 5, 6, 7 } };

    _ = p1.add(p2);
    try testing.expectEqual(R{ .c = .{ 4, 6, 8, 10 } }, p1);

    _ = p1.add(p2);
    try testing.expectEqual(R{ .c = .{ 8, 11, 14, 17 } }, p1);
}

test "test sub" {
    const R = QuotientPolyRing(4, i4096);

    var p1: R = .{ .c = .{ 0, 1, 2, 3 } };
    const p2: R = .{ .c = .{ 4, 5, 6, 7 } };

    _ = p1.sub(p2);
    try testing.expectEqual(R{ .c = .{ -4, -4, -4, -4 } }, p1);

    _ = p1.sub(p2);
    try testing.expectEqual(R{ .c = .{ -8, -9, -10, -11 } }, p1);
}

test "test mul" {
    const R = QuotientPolyRing(4, i4096);

    var p1: R = .{ .c = .{ 0, 1, 2, 3 } };
    const p2: R = .{ .c = .{ 4, 5, 6, 7 } };
    var tmp: R = .{ .c = @splat(0) };

    _ = p1.mul(p2, &tmp);
    try testing.expectEqual(R{ .c = .{ -34, -28, -8, 28 } }, p1);

    _ = p1.mul(p2, &tmp);
    try testing.expectEqual(R{ .c = .{ -32, -394, -572, -334 } }, p1);
}
