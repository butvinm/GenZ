const std = @import("std");
const httpz = @import("httpz");
const uuid = @import("uuid");
const openfhe = @import("openfhe");

const db = @import("db.zig");

pub const AppConfig = struct {
    app_host: []const u8,
    app_port: u16,
    db_port: u16,
    db_host: []const u8,
    db_user: []const u8,
    db_password: []const u8,
    db_database: []const u8,
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
        .address = app.config.app_host,
        .port = app.config.app_port,
        .request = .{ .max_body_size = 10485760 },
    }, app);

    var router = try server.router(.{});
    router.get("/health", health, .{});
    router.post("/api/v0.1.0/openSession", openSession, .{});
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
const OpenSessionResponse = struct {
    session_id: uuid.urn.Urn,
};

fn openSession(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const session_id = uuid.v4.new();
    const issued_at = std.time.microTimestamp();

    try app.db.saveSession(session_id, issued_at);

    const response = OpenSessionResponse{ .session_id = uuid.urn.serialize(session_id) };
    try res.json(response, .{});
}

/// Create a crypto context
const GetCryptoContextResponse = struct {
    crypto_context: []const u8,
};

fn getCryptoContext(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const session_id_header = req.headers.get("x-session-id") orelse {
        res.setStatus(std.http.Status.unauthorized);
        return;
    };
    const session_id = uuid.urn.deserialize(session_id_header) catch {
        res.setStatus(std.http.Status.bad_request);
        return;
    };

    const session = try app.db.getSession(session_id) orelse {
        res.setStatus(std.http.Status.not_found);
        return;
    };

    const cc_serialized = session.crypto_context orelse blk: {
        const cc = try openfhe.CryptoContext.createBgv(.{
            .multiplicative_depth = 1,
            .plaintext_modulus = 65537,
        });
        const cc_serialized = try cc.serialize(openfhe.SerialFormat.binary, res.arena);

        try app.db.setCryptoContext(session_id, cc_serialized);

        break :blk cc_serialized;
    };

    const cc_encoded_size = std.base64.standard.Encoder.calcSize(cc_serialized.len);
    const cc_buf = try res.arena.alloc(u8, cc_encoded_size);
    const cc_encoded = std.base64.standard.Encoder.encode(cc_buf, cc_serialized);

    const response = GetCryptoContextResponse{ .crypto_context = cc_encoded };
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
