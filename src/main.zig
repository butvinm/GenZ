const std = @import("std");
const httpz = @import("httpz");
const uuid = @import("uuid");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const address = "0.0.0.0";
    const port = 5882;

    var app = App{};
    var server = try httpz.Server(*App).init(allocator, .{ .address = address, .port = port }, &app);
    defer {
        server.stop();
        server.deinit();
    }

    var router = try server.router(.{});
    router.post("/api/v0.1.0/register", register, .{});
    // router.post("/api/v0.1.0/analyze", analyze, .{});

    std.log.info("Server is listening on http://{[address]s}:{[port]}", .{ .address = address, .port = port });
    try server.listen();
}

const App = struct {
    pub fn savePublicKey(_: App, publicKey: []u8) !void {
        const file = try std.fs.cwd().createFile("public_key.bin", .{});
        defer file.close();
        try file.writeAll(publicKey);
    }
};

const RegisterRequest = struct {
    public_key: []u8,

    pub fn validateRequest(alloc: std.mem.Allocator, req: *httpz.Request) anyerror!RegisterRequest {
        const request_raw = try req.json(struct { public_key: []u8 }) orelse return error.ValidationError;
        const decodedSize = try std.base64.standard.Decoder.calcSizeForSlice(request_raw.public_key);
        const request = RegisterRequest{ .public_key = try alloc.alloc(u8, decodedSize) };
        try std.base64.standard.Decoder.decode(request.public_key, request_raw.public_key);
        return request;
    }
};

/// Accept public kes from the user and assign user a session ID for later communication
fn register(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const request = RegisterRequest.validateRequest(res.arena, req) catch |err| {
        std.log.info("422 {} {s} {}", .{ req.method, req.url.path, err });
        res.status = 422;
        res.body = "Unprocessable Content";
        return;
    };
    try app.savePublicKey(request.public_key);
    const sessionId = uuid.v4.new();
    res.status = 200;
    try res.json(.{ .sessionId = uuid.urn.serialize(sessionId) }, .{});
}

// fn analyze(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
//     res.status = 200;
//     try res.json(.{ .name = "Teg" }, .{});
// }
