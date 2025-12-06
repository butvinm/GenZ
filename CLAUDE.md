# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GenZ is a toy DNA processing service with Homomorphic Encryption (FHE), written in Zig. It provides a REST API server with PostgreSQL storage for managing encrypted public keys and sessions.

## Build Commands

Requires Zig 0.15.1 or later.

```bash
# Build the project (includes OpenFHE via CMake)
zig build

# Run the application (requires LD_LIBRARY_PATH for OpenFHE libs)
LD_LIBRARY_PATH=zig-out/lib:third-party/openfhe/build/lib zig build run -- --app-host localhost --app-port 6969 --db-host localhost --db-port 5432 --db-user postgres --db-password postgres --db-database genz_db

# Run all tests
zig build test

# Force clean rebuild (delete cache)
rm -rf .zig-cache && zig build
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

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on pushes to master and all PRs:

- **build** - Builds Docker image
- **gitleaks** - Scans git history and source code for leaked secrets
- **checkov** - IaC scanner for Dockerfile and GitHub Actions misconfigurations
- **trivy-config** - Scans Dockerfile, docker-compose.yml, nginx config for misconfigurations
- **trivy-images** - Scans Docker images (genz, nginx:alpine, postgres:18) for vulnerabilities

Results are uploaded to GitHub Security tab (Code scanning alerts).

## Architecture

### Source Files (src/)
- **src/main.zig** - Application entry point, CLI argument parsing, OpenFHE initialization, database pool initialization
- **src/server.zig** - HTTP server setup using httpz, route definitions, request handlers, database schema initialization
- **src/root.zig** - Library module entry point, uses `std.testing.refAllDecls(@This())` for test discovery
- **src/fhe.zig** - SimpleSomewhat homomorphic encryption implementation (toy, encrypt/decrypt single bits)

### OpenFHE Library (lib/)
- **lib/openfhe.zig** - Zig bindings for OpenFHE BGV scheme (production FHE), exposed as named module "openfhe"
- **lib/openfhe_c.h** - C header for OpenFHE wrapper (opaque pointer types, extern "C" functions)
- **lib/openfhe_c.cpp** - C++ implementation wrapping OpenFHE library

## OpenFHE Integration

OpenFHE is included as a git submodule at `third-party/openfhe`. The build system:
1. Builds OpenFHE using CMake (first run takes several minutes)
2. Compiles the C++ wrapper (`lib/openfhe_c.cpp`) as a shared library via `b.addLibrary()` (cached by Zig)
3. Creates the "openfhe" Zig module linked to the C++ wrapper via `Module.linkLibrary()`
4. Dependencies propagate automatically - no manual step ordering needed

### BGV Scheme API

The wrapper exposes OpenFHE's BGV scheme for integer homomorphic encryption:

```zig
const openfhe = @import("openfhe");  // Named module, not file path

// Create context
var ctx = try openfhe.CryptoContext.createBgv(.{
    .multiplicative_depth = 2,
    .plaintext_modulus = 65537,
});
defer ctx.deinit();

try ctx.enablePke();
try ctx.enableLeveledShe();

// Generate keys
var kp = try ctx.keyGen();
var pk = kp.getPublicKey();
var sk = kp.getPrivateKey();
try ctx.evalMultKeysGen(sk);

// Encrypt and compute
const values = [_]i64{ 1, 2, 3, 4 };
var pt = try ctx.makePackedPlaintext(&values);
var ct = try ctx.encrypt(pk, pt);
var ct_sum = try ctx.evalAdd(ct, ct);  // Homomorphic addition
var result = try ctx.decrypt(sk, ct_sum);
```

Available operations: `evalAdd`, `evalSub`, `evalMult`, `evalRotate`, `evalNegate`, serialization, bootstrapping.

## Dependencies

- **httpz** - HTTP server framework
- **pg** - PostgreSQL client
- **uuid** - UUID generation (v4)
- **OpenFHE** - Homomorphic encryption library (git submodule)

## CLI Arguments

All arguments are required:
- `--app-host` / `--app-port` - Server binding
- `--db-host` / `--db-port` / `--db-user` / `--db-password` / `--db-database` - PostgreSQL connection

## API Endpoints

- `POST /api/v0.1.0/register` - Register a public key, returns a session UUID

## Zig Build Patterns

### Named Modules
Libraries in `lib/` are exposed as named modules via `b.addModule()`. Import with `@import("module_name")` not file paths. This allows code outside `src/` to be imported cleanly.

### Test Discovery
Tests are discovered via `std.testing.refAllDecls(@This())` in `root.zig`. This recursively references all public declarations, including tests in imported modules. Only one test step (`mod_tests`) is needed.

### Module Linking
The C++ wrapper is built as a Zig library (`b.addLibrary`) and linked to `openfhe_mod` via `linkLibrary()`. This:
- Enables build caching (skips 26s C++ compilation when unchanged)
- Automatically propagates step dependencies to consumers
- No manual `step.dependOn()` needed on exe/tests

## Zig Reference

- https://www.openmymind.net/learning_zig/
- https://ziglang.org/documentation/0.15.2/
- https://ziglang.org/documentation/0.15.2/std/
