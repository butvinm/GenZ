const std = @import("std");
const httpz = @import("httpz");
const uuid = @import("uuid");
const openfhe = @import("openfhe");

const db = @import("db.zig");

pub const AppConfig = struct {
    appHost: []const u8,
    appPort: u16,
    dbPort: u16,
    dbHost: []const u8,
    dbUser: []const u8,
    dbPassword: []const u8,
    dbDatabase: []const u8,
};

pub const App = struct {
    db: *db.DB,
    config: AppConfig,

    pub fn uncaughtError(_: *App, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
        std.log.info("500 {} {s} {}", .{ req.method, req.url.path, err });
        res.status = 500;
        res.body = "sorry";
    }
};

pub fn initServer(alloc: std.mem.Allocator, app: *App) !httpz.Server(*App) {
    var server = try httpz.Server(*App).init(alloc, .{
        .address = app.config.appHost,
        .port = app.config.appPort,
        .request = .{ .max_body_size = 10485760 },
    }, app);

    var router = try server.router(.{});
    router.get("/health", health, .{});
    router.post("/api/v0.1.0/register", register, .{});
    router.post("/api/v0.1.0/getCryptoContext", getCryptoContext, .{});

    return server;
}

/// Health check endpoint
fn health(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    try res.json(.{ .status = "healthy" }, .{});
}

// const RegisterRequest = struct {
//     publicKey: []u8,

//     pub fn validateRequest(alloc: std.mem.Allocator, req: *httpz.Request) anyerror!RegisterRequest {
//         const request_raw = try req.json(struct { publicKey: []u8 }) orelse return error.ValidationError;
//         const decodedSize = try std.base64.standard.Decoder.calcSizeForSlice(request_raw.publicKey);
//         const request = RegisterRequest{ .publicKey = try alloc.alloc(u8, decodedSize) };
//         try std.base64.standard.Decoder.decode(request.publicKey, request_raw.publicKey);
//         return request;
//     }
// };

/// Open a new session
const RegisterResponse = struct {
    sessionId: uuid.urn.Urn,
};

fn register(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const sessionId = uuid.v4.new();
    const issuedAt = std.time.microTimestamp();

    try app.db.saveSession(sessionId, issuedAt);

    const response = RegisterResponse{ .sessionId = uuid.urn.serialize(sessionId) };
    try res.json(response, .{});
}

/// Create a crypto context
const GetCryptoContextResponse = struct {
    cryptoContext: []const u8,
};

fn getCryptoContext(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const sessionIdHeader = req.headers.get("x-session-id") orelse {
        res.setStatus(std.http.Status.unauthorized);
        return;
    };
    const sessionId = uuid.urn.deserialize(sessionIdHeader) catch {
        res.setStatus(std.http.Status.bad_request);
        return;
    };

    const session = try app.db.getSession(sessionId) orelse {
        res.setStatus(std.http.Status.not_found);
        return;
    };

    const ccSerialized = session.cryptoContext orelse blk: {
        const cc = try openfhe.CryptoContext.createBgv(.{
            .multiplicative_depth = 1,
            .plaintext_modulus = 65537,
        });
        const ccSerialized = try cc.serialize(openfhe.SerialFormat.binary, res.arena);

        try app.db.setCryptoContext(sessionId, ccSerialized);

        break :blk ccSerialized;
    };

    const ccEncodedSize = std.base64.standard.Encoder.calcSize(ccSerialized.len);
    const ccBuf = try res.arena.alloc(u8, ccEncodedSize);
    const ccEncoded = std.base64.standard.Encoder.encode(ccBuf, ccSerialized);

    const response = GetCryptoContextResponse{ .cryptoContext = ccEncoded };
    try res.json(response, .{});
}

// const request = RegisterRequest.validateRequest(res.arena, req) catch |err| {
//     std.log.info("422 {} {s} {}", .{ req.method, req.url.path, err });
//     res.status = 422;
//     res.body = "Unprocessable Content";
//     return;
// };

// const sessionId = uuid.v4.new();
// const issuedAt = std.time.microTimestamp();
// const publicKey = request.publicKey;

// var conn = try app.db.acquire();
// defer conn.release();

// _ = conn.exec(
//     "INSERT INTO keys (session_id, public_key, issued_at) VALUES ($1, $2, $3);",
//     .{ uuid.urn.serialize(sessionId), publicKey, issuedAt },
// ) catch |err| {
//     if (err == error.PG) {
//         if (conn.err) |pge| {
//             std.log.err("PG {s}\n", .{pge.message});
//         }
//     }
//     return err;
// };

// res.status = 200;
// try res.json(.{ .sessionId = uuid.urn.serialize(sessionId) }, .{});

// fn analyze(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
//     res.status = 200;
//     try res.json(.{ .name = "Teg" }, .{});
// }
