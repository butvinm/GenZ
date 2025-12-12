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
        .connect = .{ .port = config.dbPort, .host = config.dbHost },
        .auth = .{ .username = config.dbUser, .database = config.dbDatabase, .password = config.dbPassword },
    });
    defer pool.deinit();

    var appDb = db.DB{ .pool = pool };

    var app = server.App{
        .db = &appDb,
        .config = config,
    };

    var appServer = try server.initServer(allocator, &app);
    defer {
        appServer.stop();
        appServer.deinit();
    }

    std.log.info("Running database migration", .{});
    try appDb.migrate();

    std.log.info("Server is listening on http://{s}:{}", .{ config.appHost, config.appPort });
    try appServer.listen();
}

pub const ParseArgsResult = union(enum) {
    ok: server.AppConfig,
    err: []const u8, // allocated, caller must free on error
};

pub fn parseArgs(alloc: std.mem.Allocator, args: *std.process.ArgIterator) ParseArgsResult {
    var appHost: ?[]const u8 = null;
    var appPort: ?u16 = null;
    var dbPort: ?u16 = null;
    var dbHost: ?[]const u8 = null;
    var dbUser: ?[]const u8 = null;
    var dbPassword: ?[]const u8 = null;
    var dbDatabase: ?[]const u8 = null;

    const exec = args.next() orelse "app";
    while (args.next()) |flag| {
        if (std.mem.eql(u8, flag, "--app-host")) {
            appHost = args.next() orelse return expectedArgValueError(alloc, flag, "app host");
        } else if (std.mem.eql(u8, flag, "--app-port")) {
            const appPortArg = args.next() orelse return expectedArgValueError(alloc, flag, "app port");
            appPort = std.fmt.parseInt(u16, appPortArg, 10) catch {
                return .{ .err = alloc.dupe(u8, "app port must be a number") catch "app port must be a number" };
            };
        } else if (std.mem.eql(u8, flag, "--db-host")) {
            dbHost = args.next() orelse return expectedArgValueError(alloc, flag, "db host");
        } else if (std.mem.eql(u8, flag, "--db-port")) {
            const dbPortArg = args.next() orelse return expectedArgValueError(alloc, flag, "db port");
            dbPort = std.fmt.parseInt(u16, dbPortArg, 10) catch {
                return .{ .err = alloc.dupe(u8, "db port must be a number") catch "db port must be a number" };
            };
        } else if (std.mem.eql(u8, flag, "--db-user")) {
            dbUser = args.next() orelse return expectedArgValueError(alloc, flag, "db user");
        } else if (std.mem.eql(u8, flag, "--db-password")) {
            dbPassword = args.next() orelse return expectedArgValueError(alloc, flag, "db password");
        } else if (std.mem.eql(u8, flag, "--db-database")) {
            dbDatabase = args.next() orelse return expectedArgValueError(alloc, flag, "db database");
        }
    }

    if (appHost == null) return missedArgError(alloc, exec, "--app-host");
    if (appPort == null) return missedArgError(alloc, exec, "--app-port");
    if (dbHost == null) return missedArgError(alloc, exec, "--db-host");
    if (dbPort == null) return missedArgError(alloc, exec, "--db-port");
    if (dbUser == null) return missedArgError(alloc, exec, "--db-user");
    if (dbPassword == null) return missedArgError(alloc, exec, "--db-password");
    if (dbDatabase == null) return missedArgError(alloc, exec, "--db-database");

    return .{ .ok = .{
        .appHost = appHost.?,
        .appPort = appPort.?,
        .dbPort = dbPort.?,
        .dbHost = dbHost.?,
        .dbUser = dbUser.?,
        .dbPassword = dbPassword.?,
        .dbDatabase = dbDatabase.?,
    } };
}

fn expectedArgValueError(alloc: std.mem.Allocator, argFlag: []const u8, argName: []const u8) ParseArgsResult {
    const msg = std.fmt.allocPrint(alloc, "{s}: expected {s} value", .{ argFlag, argName }) catch "expected argument value";
    return .{ .err = msg };
}

fn missedArgError(alloc: std.mem.Allocator, exec: []const u8, argFlag: []const u8) ParseArgsResult {
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
    , .{ argFlag, exec }) catch "error: missing required argument";
    return .{ .err = msg };
}
