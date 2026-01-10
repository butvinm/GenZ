const std = @import("std");

const openfhe = @import("openfhe");

const api_url = "http://localhost:6969/api";

test "e2e: create session and get crypto context" {
    const alloc = std.testing.allocator;

    var client = std.http.Client{ .allocator = alloc };
    defer client.deinit();

    std.debug.print("[create session]\n", .{});

    var open_session_body: std.Io.Writer.Allocating = .init(alloc);
    defer open_session_body.deinit();

    const open_session_status = try client.fetch(.{
        .location = .{ .url = api_url ++ "/v0.1.0/openSession" },
        .method = .POST,
        .payload = "",
        .response_writer = &open_session_body.writer,
    });
    try std.testing.expectEqual(.ok, open_session_status.status);

    const open_session_response = try std.json.parseFromSlice(
        struct { session_id: []const u8 },
        alloc,
        open_session_body.written(),
        .{},
    );
    defer open_session_response.deinit();
    const session_id = open_session_response.value.session_id;
    std.debug.print("session_id={s}\n", .{session_id});

    std.debug.print("[get crypto context]\n", .{});

    var get_crypto_context_body: std.Io.Writer.Allocating = .init(alloc);
    defer get_crypto_context_body.deinit();

    const get_crypto_context_status = try client.fetch(.{
        .location = .{ .url = api_url ++ "/v0.1.0/getCryptoContext" },
        .method = .POST,
        .payload = "",
        .extra_headers = &.{
            .{ .name = "X-Session-Id", .value = session_id },
        },
        .response_writer = &get_crypto_context_body.writer,
    });
    try std.testing.expectEqual(.ok, get_crypto_context_status.status);

    const get_crypto_context_response = try std.json.parseFromSlice(
        struct { crypto_context: []const u8 },
        alloc,
        get_crypto_context_body.written(),
        .{},
    );
    defer get_crypto_context_response.deinit();
    const crypto_context_encoded = get_crypto_context_response.value.crypto_context;

    // Decode base64
    const cc_decoded_size = try std.base64.standard.Decoder.calcSizeForSlice(crypto_context_encoded);
    const cc_decoded = try alloc.alloc(u8, cc_decoded_size);
    defer alloc.free(cc_decoded);
    try std.base64.standard.Decoder.decode(cc_decoded, crypto_context_encoded);

    try std.testing.expect(cc_decoded.len > 0);

    const cc = try openfhe.CryptoContext.deserialize(cc_decoded, openfhe.SerialFormat.binary);
    std.debug.print("crypto context ring dimension: {}\n", .{cc.getRingDim()});
}
