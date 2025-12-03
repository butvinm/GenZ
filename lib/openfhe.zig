const std = @import("std");

const c = @cImport({
    @cInclude("openfhe_c.h");
});

pub const CryptoContextHandle = c.CryptoContextHandle;
pub const KeyPairHandle = c.KeyPairHandle;
pub const PublicKeyHandle = c.PublicKeyHandle;
pub const PrivateKeyHandle = c.PrivateKeyHandle;
pub const CiphertextHandle = c.CiphertextHandle;
pub const PlaintextHandle = c.PlaintextHandle;

pub const Error = error{
    NullPointer,
    InvalidParam,
    CryptoFailure,
    SerializationError,
    KeyNotFound,
    InternalError,
};

fn mapError(err: c.OpenfheError) Error!void {
    return switch (err) {
        c.OPENFHE_OK => {},
        c.OPENFHE_ERROR_NULL_POINTER => Error.NullPointer,
        c.OPENFHE_ERROR_INVALID_PARAM => Error.InvalidParam,
        c.OPENFHE_ERROR_CRYPTO_FAILURE => Error.CryptoFailure,
        c.OPENFHE_ERROR_SERIALIZATION => Error.SerializationError,
        c.OPENFHE_ERROR_KEY_NOT_FOUND => Error.KeyNotFound,
        else => Error.InternalError,
    };
}

pub fn getLastError() []const u8 {
    const msg = c.openfhe_get_last_error();
    return std.mem.span(msg);
}

pub const SerialFormat = enum(c.SerialFormat) {
    binary = c.SERIAL_BINARY,
    json = c.SERIAL_JSON,
};

pub const BgvParams = struct {
    multiplicative_depth: u32 = 2,
    plaintext_modulus: u64 = 65537,
    security_level: u32 = 128,
    ring_dim: u32 = 0,
    batch_size: u32 = 0,
    max_relin_sk_deg: u32 = 2,
    first_mod_size: u32 = 0,
    scaling_mod_size: u32 = 0,
    num_large_digits: u32 = 0,

    pub fn toC(self: BgvParams) c.BgvParams {
        return .{
            .multiplicative_depth = self.multiplicative_depth,
            .plaintext_modulus = self.plaintext_modulus,
            .security_level = self.security_level,
            .ring_dim = self.ring_dim,
            .batch_size = self.batch_size,
            .max_relin_sk_deg = self.max_relin_sk_deg,
            .first_mod_size = self.first_mod_size,
            .scaling_mod_size = self.scaling_mod_size,
            .num_large_digits = self.num_large_digits,
        };
    }
};

pub const CryptoContext = struct {
    handle: c.CryptoContextHandle,

    pub fn createBgv(params: BgvParams) Error!CryptoContext {
        var c_params = params.toC();
        var handle: c.CryptoContextHandle = null;
        try mapError(c.crypto_context_create_bgv(&c_params, &handle));
        return .{ .handle = handle };
    }

    pub fn enablePke(self: CryptoContext) Error!void {
        try mapError(c.crypto_context_enable_pke(self.handle));
    }

    pub fn enableKeyswitch(self: CryptoContext) Error!void {
        try mapError(c.crypto_context_enable_keyswitch(self.handle));
    }

    pub fn enableLeveledShe(self: CryptoContext) Error!void {
        try mapError(c.crypto_context_enable_leveledshe(self.handle));
    }

    pub fn enableAdvancedShe(self: CryptoContext) Error!void {
        try mapError(c.crypto_context_enable_advancedshe(self.handle));
    }

    pub fn enableFhe(self: CryptoContext) Error!void {
        try mapError(c.crypto_context_enable_fhe(self.handle));
    }

    pub fn getRingDim(self: CryptoContext) u32 {
        return c.crypto_context_get_ring_dim(self.handle);
    }

    pub fn getPlaintextModulus(self: CryptoContext) u64 {
        return c.crypto_context_get_plaintext_modulus(self.handle);
    }

    pub fn getCyclotomicOrder(self: CryptoContext) u32 {
        return c.crypto_context_get_cyclotomic_order(self.handle);
    }

    pub fn keyGen(self: CryptoContext) Error!KeyPair {
        var handle: c.KeyPairHandle = null;
        try mapError(c.keygen(self.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalMultKeysGen(self: CryptoContext, sk: PrivateKey) Error!void {
        try mapError(c.eval_mult_keys_gen(self.handle, sk.handle));
    }

    pub fn evalRotateKeysGen(self: CryptoContext, sk: PrivateKey, indices: []const i32) Error!void {
        try mapError(c.eval_rotate_keys_gen(
            self.handle,
            sk.handle,
            indices.ptr,
            indices.len,
        ));
    }

    pub fn evalSumKeysGen(self: CryptoContext, sk: PrivateKey) Error!void {
        try mapError(c.eval_sum_keys_gen(self.handle, sk.handle));
    }

    pub fn makePackedPlaintext(self: CryptoContext, values: []const i64) Error!Plaintext {
        var handle: c.PlaintextHandle = null;
        try mapError(c.make_packed_plaintext(self.handle, values.ptr, values.len, &handle));
        return .{ .handle = handle };
    }

    pub fn makeCoefPackedPlaintext(self: CryptoContext, values: []const i64) Error!Plaintext {
        var handle: c.PlaintextHandle = null;
        try mapError(c.make_coef_packed_plaintext(self.handle, values.ptr, values.len, &handle));
        return .{ .handle = handle };
    }

    pub fn encrypt(self: CryptoContext, pk: PublicKey, pt: Plaintext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.encrypt(self.handle, pk.handle, pt.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn encryptPrivate(self: CryptoContext, sk: PrivateKey, pt: Plaintext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.encrypt_private(self.handle, sk.handle, pt.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn decrypt(self: CryptoContext, sk: PrivateKey, ct: Ciphertext) Error!Plaintext {
        var handle: c.PlaintextHandle = null;
        try mapError(c.decrypt(self.handle, sk.handle, ct.handle, &handle));
        return .{ .handle = handle };
    }

    // Homomorphic operations
    pub fn evalAdd(self: CryptoContext, ct1: Ciphertext, ct2: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_add(self.handle, ct1.handle, ct2.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalAddInplace(self: CryptoContext, ct1: *Ciphertext, ct2: Ciphertext) Error!void {
        try mapError(c.eval_add_inplace(self.handle, ct1.handle, ct2.handle));
    }

    pub fn evalAddPlaintext(self: CryptoContext, ct: Ciphertext, pt: Plaintext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_add_plaintext(self.handle, ct.handle, pt.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalSub(self: CryptoContext, ct1: Ciphertext, ct2: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_sub(self.handle, ct1.handle, ct2.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalSubInplace(self: CryptoContext, ct1: *Ciphertext, ct2: Ciphertext) Error!void {
        try mapError(c.eval_sub_inplace(self.handle, ct1.handle, ct2.handle));
    }

    pub fn evalMult(self: CryptoContext, ct1: Ciphertext, ct2: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_mult(self.handle, ct1.handle, ct2.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalMultInplace(self: CryptoContext, ct1: *Ciphertext, ct2: Ciphertext) Error!void {
        try mapError(c.eval_mult_inplace(self.handle, ct1.handle, ct2.handle));
    }

    pub fn evalMultNoRelin(self: CryptoContext, ct1: Ciphertext, ct2: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_mult_no_relin(self.handle, ct1.handle, ct2.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalMultPlaintext(self: CryptoContext, ct: Ciphertext, pt: Plaintext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_mult_plaintext(self.handle, ct.handle, pt.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalMultMany(self: CryptoContext, cts: []Ciphertext) Error!Ciphertext {
        var handles = std.ArrayList(c.CiphertextHandle).init(std.heap.page_allocator);
        defer handles.deinit();
        for (cts) |ct| {
            handles.append(ct.handle) catch return Error.InternalError;
        }
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_mult_many(self.handle, handles.items.ptr, handles.items.len, &handle));
        return .{ .handle = handle };
    }

    pub fn relinearize(self: CryptoContext, ct: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_relinearize(self.handle, ct.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalNegate(self: CryptoContext, ct: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_negate(self.handle, ct.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn evalNegateInplace(self: CryptoContext, ct: *Ciphertext) Error!void {
        try mapError(c.eval_negate_inplace(self.handle, ct.handle));
    }

    // Rotation operations
    pub fn evalRotate(self: CryptoContext, ct: Ciphertext, index: i32) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_rotate(self.handle, ct.handle, index, &handle));
        return .{ .handle = handle };
    }

    pub fn evalRotateInplace(self: CryptoContext, ct: *Ciphertext, index: i32) Error!void {
        try mapError(c.eval_rotate_inplace(self.handle, ct.handle, index));
    }

    pub fn evalSum(self: CryptoContext, ct: Ciphertext, batch_size: u32) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_sum(self.handle, ct.handle, batch_size, &handle));
        return .{ .handle = handle };
    }

    pub fn evalInnerProduct(self: CryptoContext, ct1: Ciphertext, ct2: Ciphertext, batch_size: u32) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_inner_product(self.handle, ct1.handle, ct2.handle, batch_size, &handle));
        return .{ .handle = handle };
    }

    // Level operations
    pub fn modReduce(self: CryptoContext, ct: Ciphertext) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.mod_reduce(self.handle, ct.handle, &handle));
        return .{ .handle = handle };
    }

    pub fn modReduceInplace(self: CryptoContext, ct: *Ciphertext) Error!void {
        try mapError(c.mod_reduce_inplace(self.handle, ct.handle));
    }

    // Bootstrapping
    pub fn evalBootstrapSetup(
        self: CryptoContext,
        level_budget: [2]u32,
        dim1: ?[2]u32,
        slots: u32,
        correction_factor: u32,
    ) Error!void {
        const dim1_ptr: ?*const u32 = if (dim1) |d| &d[0] else null;
        try mapError(c.eval_bootstrap_setup(self.handle, &level_budget[0], dim1_ptr, slots, correction_factor));
    }

    pub fn evalBootstrapKeyGen(self: CryptoContext, sk: PrivateKey, slots: u32) Error!void {
        try mapError(c.eval_bootstrap_keygen(self.handle, sk.handle, slots));
    }

    pub fn evalBootstrap(self: CryptoContext, ct: Ciphertext, num_iterations: u32, precision: u32) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.eval_bootstrap(self.handle, ct.handle, num_iterations, precision, &handle));
        return .{ .handle = handle };
    }

    // Serialization
    pub fn serialize(self: CryptoContext, format: SerialFormat, allocator: std.mem.Allocator) Error![]u8 {
        var data: [*]u8 = undefined;
        var size: usize = 0;
        try mapError(c.crypto_context_serialize(self.handle, @intFromEnum(format), @ptrCast(&data), &size));

        const result = allocator.alloc(u8, size) catch return Error.InternalError;
        @memcpy(result, data[0..size]);
        c.serialized_data_free(data);
        return result;
    }

    pub fn deserialize(data: []const u8, format: SerialFormat) Error!CryptoContext {
        var handle: c.CryptoContextHandle = null;
        try mapError(c.crypto_context_deserialize(data.ptr, data.len, @intFromEnum(format), &handle));
        return .{ .handle = handle };
    }

    pub fn serializeEvalMultKeys(self: CryptoContext, format: SerialFormat, allocator: std.mem.Allocator) Error![]u8 {
        var data: [*]u8 = undefined;
        var size: usize = 0;
        try mapError(c.eval_mult_keys_serialize(self.handle, @intFromEnum(format), @ptrCast(&data), &size));

        const result = allocator.alloc(u8, size) catch return Error.InternalError;
        @memcpy(result, data[0..size]);
        c.serialized_data_free(data);
        return result;
    }

    pub fn deserializeEvalMultKeys(self: CryptoContext, data: []const u8, format: SerialFormat) Error!void {
        try mapError(c.eval_mult_keys_deserialize(self.handle, data.ptr, data.len, @intFromEnum(format)));
    }

    pub fn serializeEvalAutomorphismKeys(self: CryptoContext, format: SerialFormat, allocator: std.mem.Allocator) Error![]u8 {
        var data: [*]u8 = undefined;
        var size: usize = 0;
        try mapError(c.eval_automorphism_keys_serialize(self.handle, @intFromEnum(format), @ptrCast(&data), &size));

        const result = allocator.alloc(u8, size) catch return Error.InternalError;
        @memcpy(result, data[0..size]);
        c.serialized_data_free(data);
        return result;
    }

    pub fn deserializeEvalAutomorphismKeys(self: CryptoContext, data: []const u8, format: SerialFormat) Error!void {
        try mapError(c.eval_automorphism_keys_deserialize(self.handle, data.ptr, data.len, @intFromEnum(format)));
    }

    pub fn deinit(self: *CryptoContext) void {
        c.crypto_context_destroy(self.handle);
        self.handle = null;
    }
};

pub const KeyPair = struct {
    handle: c.KeyPairHandle,

    pub fn getPublicKey(self: KeyPair) PublicKey {
        return .{ .handle = c.keypair_get_public_key(self.handle) };
    }

    pub fn getPrivateKey(self: KeyPair) PrivateKey {
        return .{ .handle = c.keypair_get_private_key(self.handle) };
    }

    pub fn deinit(self: *KeyPair) void {
        c.keypair_destroy(self.handle);
        self.handle = null;
    }
};

pub const PublicKey = struct {
    handle: c.PublicKeyHandle,

    pub fn serialize(self: PublicKey, format: SerialFormat, allocator: std.mem.Allocator) Error![]u8 {
        var data: [*]u8 = undefined;
        var size: usize = 0;
        try mapError(c.public_key_serialize(self.handle, @intFromEnum(format), @ptrCast(&data), &size));

        const result = allocator.alloc(u8, size) catch return Error.InternalError;
        @memcpy(result, data[0..size]);
        c.serialized_data_free(data);
        return result;
    }

    pub fn deserialize(data: []const u8, format: SerialFormat) Error!PublicKey {
        var handle: c.PublicKeyHandle = null;
        try mapError(c.public_key_deserialize(data.ptr, data.len, @intFromEnum(format), &handle));
        return .{ .handle = handle };
    }

    pub fn deinit(self: *PublicKey) void {
        c.public_key_destroy(self.handle);
        self.handle = null;
    }
};

pub const PrivateKey = struct {
    handle: c.PrivateKeyHandle,

    pub fn serialize(self: PrivateKey, format: SerialFormat, allocator: std.mem.Allocator) Error![]u8 {
        var data: [*]u8 = undefined;
        var size: usize = 0;
        try mapError(c.private_key_serialize(self.handle, @intFromEnum(format), @ptrCast(&data), &size));

        const result = allocator.alloc(u8, size) catch return Error.InternalError;
        @memcpy(result, data[0..size]);
        c.serialized_data_free(data);
        return result;
    }

    pub fn deserialize(data: []const u8, format: SerialFormat) Error!PrivateKey {
        var handle: c.PrivateKeyHandle = null;
        try mapError(c.private_key_deserialize(data.ptr, data.len, @intFromEnum(format), &handle));
        return .{ .handle = handle };
    }

    pub fn deinit(self: *PrivateKey) void {
        c.private_key_destroy(self.handle);
        self.handle = null;
    }
};

pub const Plaintext = struct {
    handle: c.PlaintextHandle,

    pub fn getValues(self: Plaintext, buffer: []i64) Error![]i64 {
        var length: usize = 0;
        try mapError(c.plaintext_get_values(self.handle, buffer.ptr, &length, buffer.len));
        return buffer[0..length];
    }

    pub fn setLength(self: Plaintext, length: usize) void {
        c.plaintext_set_length(self.handle, length);
    }

    pub fn getLength(self: Plaintext) usize {
        return c.plaintext_get_length(self.handle);
    }

    pub fn deinit(self: *Plaintext) void {
        c.plaintext_destroy(self.handle);
        self.handle = null;
    }
};

pub const Ciphertext = struct {
    handle: c.CiphertextHandle,

    pub fn clone(self: Ciphertext) Ciphertext {
        return .{ .handle = c.ciphertext_clone(self.handle) };
    }

    pub fn getLevel(self: Ciphertext) u32 {
        return c.ciphertext_get_level(self.handle);
    }

    pub fn serialize(self: Ciphertext, format: SerialFormat, allocator: std.mem.Allocator) Error![]u8 {
        var data: [*]u8 = undefined;
        var size: usize = 0;
        try mapError(c.ciphertext_serialize(self.handle, @intFromEnum(format), @ptrCast(&data), &size));

        const result = allocator.alloc(u8, size) catch return Error.InternalError;
        @memcpy(result, data[0..size]);
        c.serialized_data_free(data);
        return result;
    }

    pub fn deserialize(ctx: CryptoContext, data: []const u8, format: SerialFormat) Error!Ciphertext {
        var handle: c.CiphertextHandle = null;
        try mapError(c.ciphertext_deserialize(ctx.handle, data.ptr, data.len, @intFromEnum(format), &handle));
        return .{ .handle = handle };
    }

    pub fn deinit(self: *Ciphertext) void {
        c.ciphertext_destroy(self.handle);
        self.handle = null;
    }
};

// Tests
test "BGV basic operations" {
    // Create context
    var ctx = try CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    });
    defer ctx.deinit();

    // Enable features
    try ctx.enablePke();
    try ctx.enableKeyswitch();
    try ctx.enableLeveledShe();

    // Generate keys
    var kp = try ctx.keyGen();
    defer kp.deinit();

    var pk = kp.getPublicKey();
    defer pk.deinit();

    var sk = kp.getPrivateKey();
    defer sk.deinit();

    // Generate evaluation keys for multiplication
    try ctx.evalMultKeysGen(sk);

    // Create plaintext
    const values = [_]i64{ 1, 2, 3, 4 };
    var pt = try ctx.makePackedPlaintext(&values);
    defer pt.deinit();

    // Encrypt
    var ct = try ctx.encrypt(pk, pt);
    defer ct.deinit();

    // Decrypt and verify
    var result = try ctx.decrypt(sk, ct);
    defer result.deinit();

    var buffer: [16]i64 = undefined;
    const decrypted = try result.getValues(&buffer);

    try std.testing.expectEqual(@as(i64, 1), decrypted[0]);
    try std.testing.expectEqual(@as(i64, 2), decrypted[1]);
    try std.testing.expectEqual(@as(i64, 3), decrypted[2]);
    try std.testing.expectEqual(@as(i64, 4), decrypted[3]);
}

test "BGV homomorphic addition" {
    var ctx = try CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    });
    defer ctx.deinit();

    try ctx.enablePke();
    try ctx.enableKeyswitch();
    try ctx.enableLeveledShe();

    var kp = try ctx.keyGen();
    defer kp.deinit();

    var pk = kp.getPublicKey();
    defer pk.deinit();

    var sk = kp.getPrivateKey();
    defer sk.deinit();

    const values1 = [_]i64{ 1, 2, 3, 4 };
    const values2 = [_]i64{ 10, 20, 30, 40 };

    var pt1 = try ctx.makePackedPlaintext(&values1);
    defer pt1.deinit();

    var pt2 = try ctx.makePackedPlaintext(&values2);
    defer pt2.deinit();

    var ct1 = try ctx.encrypt(pk, pt1);
    defer ct1.deinit();

    var ct2 = try ctx.encrypt(pk, pt2);
    defer ct2.deinit();

    // Add ciphertexts
    var ct_sum = try ctx.evalAdd(ct1, ct2);
    defer ct_sum.deinit();

    var result = try ctx.decrypt(sk, ct_sum);
    defer result.deinit();

    var buffer: [16]i64 = undefined;
    const decrypted = try result.getValues(&buffer);

    try std.testing.expectEqual(@as(i64, 11), decrypted[0]);
    try std.testing.expectEqual(@as(i64, 22), decrypted[1]);
    try std.testing.expectEqual(@as(i64, 33), decrypted[2]);
    try std.testing.expectEqual(@as(i64, 44), decrypted[3]);
}

test "BGV homomorphic multiplication" {
    var ctx = try CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    });
    defer ctx.deinit();

    try ctx.enablePke();
    try ctx.enableKeyswitch();
    try ctx.enableLeveledShe();

    var kp = try ctx.keyGen();
    defer kp.deinit();

    var pk = kp.getPublicKey();
    defer pk.deinit();

    var sk = kp.getPrivateKey();
    defer sk.deinit();

    try ctx.evalMultKeysGen(sk);

    const values1 = [_]i64{ 1, 2, 3, 4 };
    const values2 = [_]i64{ 2, 3, 4, 5 };

    var pt1 = try ctx.makePackedPlaintext(&values1);
    defer pt1.deinit();

    var pt2 = try ctx.makePackedPlaintext(&values2);
    defer pt2.deinit();

    var ct1 = try ctx.encrypt(pk, pt1);
    defer ct1.deinit();

    var ct2 = try ctx.encrypt(pk, pt2);
    defer ct2.deinit();

    // Multiply ciphertexts
    var ct_prod = try ctx.evalMult(ct1, ct2);
    defer ct_prod.deinit();

    var result = try ctx.decrypt(sk, ct_prod);
    defer result.deinit();

    var buffer: [16]i64 = undefined;
    const decrypted = try result.getValues(&buffer);

    try std.testing.expectEqual(@as(i64, 2), decrypted[0]); // 1*2
    try std.testing.expectEqual(@as(i64, 6), decrypted[1]); // 2*3
    try std.testing.expectEqual(@as(i64, 12), decrypted[2]); // 3*4
    try std.testing.expectEqual(@as(i64, 20), decrypted[3]); // 4*5
}

test "BGV rotation" {
    var ctx = try CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    });
    defer ctx.deinit();

    try ctx.enablePke();
    try ctx.enableKeyswitch();
    try ctx.enableLeveledShe();

    var kp = try ctx.keyGen();
    defer kp.deinit();

    var pk = kp.getPublicKey();
    defer pk.deinit();

    var sk = kp.getPrivateKey();
    defer sk.deinit();

    // Generate rotation keys for indices 1 and -1
    const rotation_indices = [_]i32{ 1, -1, 2 };
    try ctx.evalRotateKeysGen(sk, &rotation_indices);

    // Create plaintext [1, 2, 3, 4, 0, 0, ...]
    const values = [_]i64{ 1, 2, 3, 4 };
    var pt = try ctx.makePackedPlaintext(&values);
    defer pt.deinit();

    var ct = try ctx.encrypt(pk, pt);
    defer ct.deinit();

    // Rotate left by 1: [2, 3, 4, 0, ...] (slots shift left)
    var ct_rotated = try ctx.evalRotate(ct, 1);
    defer ct_rotated.deinit();

    var result = try ctx.decrypt(sk, ct_rotated);
    defer result.deinit();

    var buffer: [16]i64 = undefined;
    const decrypted = try result.getValues(&buffer);

    try std.testing.expectEqual(@as(i64, 2), decrypted[0]);
    try std.testing.expectEqual(@as(i64, 3), decrypted[1]);
    try std.testing.expectEqual(@as(i64, 4), decrypted[2]);
}

test "BGV ciphertext serialization" {
    const allocator = std.testing.allocator;

    var ctx = try CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    });
    defer ctx.deinit();

    try ctx.enablePke();
    try ctx.enableKeyswitch();
    try ctx.enableLeveledShe();

    var kp = try ctx.keyGen();
    defer kp.deinit();

    var pk = kp.getPublicKey();
    defer pk.deinit();

    var sk = kp.getPrivateKey();
    defer sk.deinit();

    // Create and encrypt
    const values = [_]i64{ 100, 200, 300, 400 };
    var pt = try ctx.makePackedPlaintext(&values);
    defer pt.deinit();

    var ct = try ctx.encrypt(pk, pt);
    defer ct.deinit();

    // Serialize ciphertext to binary
    const serialized = try ct.serialize(.binary, allocator);
    defer allocator.free(serialized);

    std.log.info("Serialized ciphertext size: {} bytes", .{serialized.len});

    // Deserialize ciphertext
    var ct_restored = try Ciphertext.deserialize(ctx, serialized, .binary);
    defer ct_restored.deinit();

    // Decrypt restored ciphertext and verify
    var result = try ctx.decrypt(sk, ct_restored);
    defer result.deinit();

    var buffer: [16]i64 = undefined;
    const decrypted = try result.getValues(&buffer);

    try std.testing.expectEqual(@as(i64, 100), decrypted[0]);
    try std.testing.expectEqual(@as(i64, 200), decrypted[1]);
    try std.testing.expectEqual(@as(i64, 300), decrypted[2]);
    try std.testing.expectEqual(@as(i64, 400), decrypted[3]);
}

test "BGV public key serialization" {
    const allocator = std.testing.allocator;

    var ctx = try CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    });
    defer ctx.deinit();

    try ctx.enablePke();
    try ctx.enableKeyswitch();
    try ctx.enableLeveledShe();

    var kp = try ctx.keyGen();
    defer kp.deinit();

    var pk = kp.getPublicKey();
    defer pk.deinit();

    var sk = kp.getPrivateKey();
    defer sk.deinit();

    // Serialize public key
    const pk_serialized = try pk.serialize(.binary, allocator);
    defer allocator.free(pk_serialized);

    std.log.info("Serialized public key size: {} bytes", .{pk_serialized.len});

    // Deserialize public key
    var pk_restored = try PublicKey.deserialize(pk_serialized, .binary);
    defer pk_restored.deinit();

    // Use restored public key to encrypt
    const values = [_]i64{ 42, 43, 44, 45 };
    var pt = try ctx.makePackedPlaintext(&values);
    defer pt.deinit();

    var ct = try ctx.encrypt(pk_restored, pt);
    defer ct.deinit();

    // Decrypt with original secret key
    var result = try ctx.decrypt(sk, ct);
    defer result.deinit();

    var buffer: [16]i64 = undefined;
    const decrypted = try result.getValues(&buffer);

    try std.testing.expectEqual(@as(i64, 42), decrypted[0]);
    try std.testing.expectEqual(@as(i64, 43), decrypted[1]);
    try std.testing.expectEqual(@as(i64, 44), decrypted[2]);
    try std.testing.expectEqual(@as(i64, 45), decrypted[3]);
}
