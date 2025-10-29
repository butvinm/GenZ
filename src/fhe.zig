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

/// From "Security Guidelines for Implementing Homomorphic Encryption"
/// Assuming secret key from uniform ternary distribution "chi"
const lambda = 128; // Security level (classical) of the parameter set.
const N = 1024; // Dimension of the RLWE instance.
const n = 1; // Dimension of the LWE instance, n = kN when modelling GLWE.
const Q = i26; // Maximal log_2 of the modulus q is 26 hence we use i26 to represent it

/// BGV encryption scheme for RLWE
pub fn BGV() type {
    return struct {
        const Self = @This();

        /// E.Setup(1^λ , 1^µ , b): Use the bit b ∈ {0, 1} to determine whether we are setting parameters for a LWE-based
        /// scheme (where d = 1) or a RLWE-based scheme (where n = 1). Choose a µ-bit modulus q and
        /// choose the other parameters (d = d(λ, µ, b), n = n(λ, µ, b), N = [d(2n + 1) log qe], χ = χ(λ, µ, b))
        /// appropriately to ensure that the scheme is based on a GLWE instance that achieves 2λ security against
        /// known attacks. Let R = Z[x]/(x^d + 1) and let params = (q, d, n, N, χ)
        const R = QuotientPolyRing(N, Q);

        /// E.SecretKeyGen(params): Draw s' ← χn . Set sk = s ← (1, s'[1], . . . , s'[n]) ∈ R_q^{n+1}
        pub fn secretKeyGen() [n + 1]R {
            var one: R = .{ .c = @splat(0) };
            one.c[0] = 1;

            var sPrime: R = .{ .c = @splat(0) };
            for (0..N) |i| sPrime.c[i] = chi();
            return .{ one, sPrime };
        }

        fn chi() i2 {
            return crypto.random.intRangeAtMost(i2, -1, 1);
        }
    };
}

test "test BGV secret key gen" {
    const BGVType = BGV();

    const sk = BGVType.secretKeyGen();

    // Check that we have n+1 = 2 polynomials
    try testing.expectEqual(2, sk.len);

    // First element should be the constant polynomial 1
    const one = sk[0];
    try testing.expectEqual(@as(Q, 1), one.c[0]);
    for (1..N) |i| {
        try testing.expectEqual(@as(Q, 0), one.c[i]);
    }

    // Second element (sPrime) should have coefficients in {-1, 0, 1}
    const sPrime = sk[1];
    for (0..N) |i| {
        const coeff = sPrime.c[i];
        try testing.expect(coeff >= -1 and coeff <= 1);
    }

    // Check that sPrime is not all zeros (with overwhelming probability)
    var hasNonZero = false;
    for (0..N) |i| {
        if (sPrime.c[i] != 0) {
            hasNonZero = true;
            break;
        }
    }
    try testing.expect(hasNonZero);
}
