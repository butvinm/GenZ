const std = @import("std");

const openfhe = @import("openfhe");

const api_url = "http://localhost:6969/api";

test "e2e: create session and get crypto context" {
    const alloc = std.testing.allocator;

    var client = std.http.Client{ .allocator = alloc };
    defer client.deinit();

    std.debug.print("[create session]\n", .{});

    var registerBody: std.Io.Writer.Allocating = .init(alloc);
    defer registerBody.deinit();

    const registerStatus = try client.fetch(.{
        .location = .{ .url = api_url ++ "/v0.1.0/register" },
        .method = .POST,
        .payload = "",
        .response_writer = &registerBody.writer,
    });
    try std.testing.expectEqual(.ok, registerStatus.status);

    const registerResponse = try std.json.parseFromSlice(
        struct { sessionId: []const u8 },
        alloc,
        registerBody.written(),
        .{},
    );
    defer registerResponse.deinit();
    const sessionId = registerResponse.value.sessionId;
    std.debug.print("sessionId={s}\n", .{sessionId});

    std.debug.print("[get crypto context]\n", .{});

    var getCryptoContextBody: std.Io.Writer.Allocating = .init(alloc);
    defer getCryptoContextBody.deinit();

    const getCryptoContextStatus = try client.fetch(.{
        .location = .{ .url = api_url ++ "/v0.1.0/getCryptoContext" },
        .method = .POST,
        .payload = "",
        .extra_headers = &.{
            .{ .name = "X-Session-Id", .value = sessionId },
        },
        .response_writer = &getCryptoContextBody.writer,
    });
    try std.testing.expectEqual(.ok, getCryptoContextStatus.status);

    const getCryptoContextResponse = try std.json.parseFromSlice(
        struct { cryptoContext: []const u8 },
        alloc,
        getCryptoContextBody.written(),
        .{},
    );
    defer getCryptoContextResponse.deinit();
    const cryptoContextEncoded = getCryptoContextResponse.value.cryptoContext;

    // Decode base64
    const ccDecodedSize = try std.base64.standard.Decoder.calcSizeForSlice(cryptoContextEncoded);
    const ccDecoded = try alloc.alloc(u8, ccDecodedSize);
    defer alloc.free(ccDecoded);
    try std.base64.standard.Decoder.decode(ccDecoded, cryptoContextEncoded);

    try std.testing.expect(ccDecoded.len > 0);

    const cc = try openfhe.CryptoContext.deserialize(ccDecoded, openfhe.SerialFormat.binary);
    std.debug.print("crypto context ring dimension: {}\n", .{cc.getRingDim()});
}
