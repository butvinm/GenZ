const pg = @import("pg");
const uuid = @import("uuid");
const std = @import("std");

pub const DB = struct {
    pool: *pg.Pool,

    pub fn migrate(self: *DB) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        _ = conn.exec(
            \\CREATE TABLE IF NOT EXISTS sessions (
            \\    session_id UUID PRIMARY KEY,
            \\    public_key bytea NULL,
            \\    crypto_context bytea NULL,
            \\    issued_at timestamp NOT NULL
            \\);
        ,
            .{},
        ) catch |err| return catchPge(err, conn);

        try conn.commit();
    }

    /// Sessions table
    const SessionRow = struct {
        sessionId: uuid.Uuid,
        publicKey: ?[]const u8,
        cryptoContext: ?[]const u8,
        issuedAt: i64,
    };

    /// Save newly created session
    pub fn saveSession(self: *DB, sessionId: uuid.Uuid, issuedAt: i64) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        _ = conn.exec(
            "INSERT INTO sessions (session_id, issued_at) VALUES ($1, $2);",
            .{ uuid.urn.serialize(sessionId), issuedAt },
        ) catch |err| return catchPge(err, conn);
    }

    /// Get session by session id
    pub fn getSession(self: *DB, sessionId: uuid.Uuid) !?SessionRow {
        var conn = try self.pool.acquire();
        defer conn.release();

        var row = (conn.row(
            "SELECT session_id, public_key, crypto_context, issued_at FROM sessions WHERE session_id = $1",
            .{uuid.urn.serialize(sessionId)},
        ) catch |err| return catchPge(err, conn)) orelse return null;
        defer row.deinit() catch {};

        const publicKey = row.get(?[]const u8, 1);
        const cryptoContext = row.get(?[]const u8, 2);
        const issuedAt = row.get(?i64, 3) orelse return error.IssuedAtIsNull;

        return SessionRow{
            .sessionId = sessionId,
            .publicKey = publicKey,
            .cryptoContext = cryptoContext,
            .issuedAt = issuedAt,
        };
    }

    /// Set session crypto context
    pub fn setCryptoContext(self: *DB, sessionId: uuid.Uuid, cryptoContext: []const u8) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        const updated = conn.exec(
            "UPDATE keys SET crypto_context = $2 WHERE session_id = $1",
            .{ uuid.urn.serialize(sessionId), cryptoContext },
        ) catch |err| return catchPge(err, conn);

        if (updated == 0) return error.SessionNotFound;
    }

    fn catchPge(err: anyerror, conn: *pg.Conn) anyerror {
        if (err == error.PG) {
            if (conn.err) |pge| {
                std.log.err("Failed to save session", .{});
                std.log.debug("{s}", .{pge.message});
            }
        }
        return err;
    }
};
