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
        session_id: uuid.Uuid,
        public_key: ?[]const u8,
        crypto_context: ?[]const u8,
        issued_at: i64,
    };

    /// Save newly created session
    pub fn saveSession(self: *DB, session_id: uuid.Uuid, issued_at: i64) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        _ = conn.exec(
            "INSERT INTO sessions (session_id, issued_at) VALUES ($1, $2);",
            .{ uuid.urn.serialize(session_id), issued_at },
        ) catch |err| return catchPge(err, conn);
    }

    /// Get session by session id
    pub fn getSession(self: *DB, session_id: uuid.Uuid) !?SessionRow {
        var conn = try self.pool.acquire();
        defer conn.release();

        var row = (conn.row(
            "SELECT session_id, public_key, crypto_context, issued_at FROM sessions WHERE session_id = $1",
            .{uuid.urn.serialize(session_id)},
        ) catch |err| return catchPge(err, conn)) orelse return null;
        defer row.deinit() catch {};

        const public_key = row.get(?[]const u8, 1);
        const crypto_context = row.get(?[]const u8, 2);
        const issued_at = row.get(?i64, 3) orelse return error.IssuedAtIsNull;

        return SessionRow{
            .session_id = session_id,
            .public_key = public_key,
            .crypto_context = crypto_context,
            .issued_at = issued_at,
        };
    }

    /// Set session crypto context
    pub fn setCryptoContext(self: *DB, session_id: uuid.Uuid, crypto_context: []const u8) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        const updated = conn.exec(
            "UPDATE sessions SET crypto_context = $2 WHERE session_id = $1",
            .{ uuid.urn.serialize(session_id), crypto_context },
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
