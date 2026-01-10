const std = @import("std");
const httpz = @import("httpz");
const pg = @import("pg");

const db = @import("db.zig");
const server = @import("server.zig");
const openfhe = @import("openfhe");

pub fn main() !void {
    // Test OpenFHE BGV wrapper
    std.log.info("Initializing OpenFHE BGV context...", .{});
    var ctx = openfhe.CryptoContext.createBgv(.{
        .multiplicative_depth = 2,
        .plaintext_modulus = 65537,
    }) catch |err| {
        std.log.err("Failed to create BGV context: {s}", .{openfhe.getLastError()});
        return err;
    };
    defer ctx.deinit();
    std.log.info("OpenFHE BGV context created. Ring dimension: {}", .{ctx.getRingDim()});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var args = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args.deinit();

    const config = switch (parseArgs(allocator, &args)) {
        .ok => |cfg| cfg,
        .err => |msg| {
            std.log.err("{s}", .{msg});
            allocator.free(msg);
            return error.ConfigBadArgs;
        },
    };

    var pool = try pg.Pool.init(allocator, .{
        .connect = .{ .port = config.db_port, .host = config.db_host },
        .auth = .{ .username = config.db_user, .database = config.db_database, .password = config.db_password },
    });
    defer pool.deinit();

    var app_db = db.DB{ .pool = pool };

    var app = server.App{
        .db = &app_db,
        .config = config,
    };

    var app_server = try server.initServer(allocator, &app);
    defer {
        app_server.stop();
        app_server.deinit();
    }

    std.log.info("Running database migration", .{});
    try app_db.migrate();

    std.log.info("Server is listening on http://{s}:{}", .{ config.app_host, config.app_port });
    try app_server.listen();
}

pub const ParseArgsResult = union(enum) {
    ok: server.AppConfig,
    err: []const u8, // allocated, caller must free on error
};

pub fn parseArgs(alloc: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsResult {
    var app_host: ?[]const u8 = null;
    var app_port: ?u16 = null;
    var db_port: ?u16 = null;
    var db_host: ?[]const u8 = null;
    var db_user: ?[]const u8 = null;
    var db_password: ?[]const u8 = null;
    var db_database: ?[]const u8 = null;

    const exec = args.next() orelse "app";
    while (args.next()) |flag| {
        if (std.mem.eql(u8, flag, "--app-host")) {
            app_host = args.next() orelse return expectedArgValueError(alloc, flag, "app host");
        } else if (std.mem.eql(u8, flag, "--app-port")) {
            const app_port_arg = args.next() orelse return expectedArgValueError(alloc, flag, "app port");
            app_port = std.fmt.parseInt(u16, app_port_arg, 10) catch {
                return .{ .err = alloc.dupe(u8, "app port must be a number") catch "app port must be a number" };
            };
        } else if (std.mem.eql(u8, flag, "--db-host")) {
            db_host = args.next() orelse return expectedArgValueError(alloc, flag, "db host");
        } else if (std.mem.eql(u8, flag, "--db-port")) {
            const db_port_arg = args.next() orelse return expectedArgValueError(alloc, flag, "db port");
            db_port = std.fmt.parseInt(u16, db_port_arg, 10) catch {
                return .{ .err = alloc.dupe(u8, "db port must be a number") catch "db port must be a number" };
            };
        } else if (std.mem.eql(u8, flag, "--db-user")) {
            db_user = args.next() orelse return expectedArgValueError(alloc, flag, "db user");
        } else if (std.mem.eql(u8, flag, "--db-password")) {
            db_password = args.next() orelse return expectedArgValueError(alloc, flag, "db password");
        } else if (std.mem.eql(u8, flag, "--db-database")) {
            db_database = args.next() orelse return expectedArgValueError(alloc, flag, "db database");
        }
    }

    if (app_host == null) return missedArgError(alloc, exec, "--app-host");
    if (app_port == null) return missedArgError(alloc, exec, "--app-port");
    if (db_host == null) return missedArgError(alloc, exec, "--db-host");
    if (db_port == null) return missedArgError(alloc, exec, "--db-port");
    if (db_user == null) return missedArgError(alloc, exec, "--db-user");
    if (db_password == null) return missedArgError(alloc, exec, "--db-password");
    if (db_database == null) return missedArgError(alloc, exec, "--db-database");

    return .{ .ok = .{
        .app_host = app_host.?,
        .app_port = app_port.?,
        .db_port = db_port.?,
        .db_host = db_host.?,
        .db_user = db_user.?,
        .db_password = db_password.?,
        .db_database = db_database.?,
    } };
}

fn expectedArgValueError(alloc: std.mem.Allocator, arg_flag: []const u8, arg_name: []const u8) ParseArgsResult {
    const msg = std.fmt.allocPrint(alloc, "{s}: expected {s} value", .{ arg_flag, arg_name }) catch "expected argument value";
    return .{ .err = msg };
}

fn missedArgError(alloc: std.mem.Allocator, exec: []const u8, arg_flag: []const u8) ParseArgsResult {
    const msg = std.fmt.allocPrint(alloc,
        \\{s} missing
        \\usage: {s} [options]
        \\Options:
        \\  --app-host       Host to serve application
        \\  --app-port       Port to serve application
        \\  --db-host        Database host
        \\  --db-port        Database port
        \\  --db-user        Database user
        \\  --db-password    Database password
        \\  --db-database    Database name
    , .{ arg_flag, exec }) catch "error: missing required argument";
    return .{ .err = msg };
}
