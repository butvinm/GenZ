# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GenZ is a toy DNA processing service with Homomorphic Encryption (FHE), written in Zig. It provides a REST API server with PostgreSQL storage for managing encrypted public keys and sessions.

## Build Commands

Requires Zig 0.15.1 or later.

```bash
# Build the project
zig build

# Run the application
zig build run -- --app-host localhost --app-port 6969 --db-host localhost --db-port 5432 --db-user postgres --db-password postgres --db-database genz_db

# Run all tests
zig build test
```

## Docker

```bash
# Generate SSL certificates (first time or to rotate)
./scripts/generate-certs.sh

# Start services (nginx + app + postgres)
docker-compose up

# Build only
docker-compose build
```

Environment variables are configured in `.env`.

### SSL/HTTPS

The service uses Nginx as a reverse proxy with self-signed SSL certificates:
- `scripts/generate-certs.sh` - Generates certificates to `certs/` directory
- `nginx/nginx.conf` - Nginx configuration with SSL termination
- Certificates are mounted as volumes (not baked into images)

API is available at `https://localhost:443` (use `-k` with curl for self-signed certs).

## Architecture

- **src/main.zig** - Application entry point, CLI argument parsing, database pool initialization
- **src/server.zig** - HTTP server setup using httpz, route definitions, request handlers, database schema initialization
- **src/fhe.zig** - SimpleSomewhat homomorphic encryption implementation (encrypt/decrypt single bits)
- **src/root.zig** - Library module entry point (currently empty)

## Dependencies

- **httpz** - HTTP server framework
- **pg** - PostgreSQL client
- **uuid** - UUID generation (v4)

## CLI Arguments

All arguments are required:
- `--app-host` / `--app-port` - Server binding
- `--db-host` / `--db-port` / `--db-user` / `--db-password` / `--db-database` - PostgreSQL connection

## API Endpoints

- `POST /api/v0.1.0/register` - Register a public key, returns a session UUID

## Zig reference

- https://www.openmymind.net/learning_zig/
- https://ziglang.org/documentation/0.15.2/
- https://ziglang.org/documentation/0.15.2/std/
