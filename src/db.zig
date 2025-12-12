const pg = @import("pg");
const uuid = @import("uuid");
const std = @import("std");

pub const DB = struct {
    pool: *pg.Pool,

    pub fn migrate(self: *DB) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        _ = conn.exec(
            \\CREATE TABLE IF NOT EXISTS keys (
            \\    session_id UUID PRIMARY KEY,
            \\    public_key bytea NULL,
            \\    cripto_context bytea NULL,
            \\    issued_at timestamp NOT NULL
            \\);
        ,
            .{},
        ) catch |err| return catchPge(err, conn);

        try conn.commit();
    }

    /// Save newly created session
    pub fn saveSession(self: *DB, sessionId: uuid.Uuid, issuedAt: i64) !void {
        var conn = try self.pool.acquire();
        defer conn.release();

        _ = conn.exec(
            "INSERT INTO keys (session_id, issued_at) VALUES ($1, $2);",
            .{ uuid.urn.serialize(sessionId), issuedAt },
        ) catch |err| return catchPge(err, conn);
    }

    fn catchPge(err: anyerror, conn: *pg.Conn) !void {
        if (err == error.PG) {
            if (conn.err) |pge| {
                std.log.err("Failed to save session", .{});
                std.log.debug("{s}", .{pge.message});
            }
        }
        return err;
    }
};
