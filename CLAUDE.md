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
- **hadolint** - Lints Dockerfile for best practices (pinned package versions, layer optimization)
- **checkov** - IaC scanner for Dockerfile and GitHub Actions misconfigurations
- **trivy-config** - Scans Dockerfile, docker-compose.yml, nginx config for misconfigurations
- **trivy-images** - Scans Docker images (genz, nginx:alpine, postgres:18) for vulnerabilities
- **stackhawk** - Scans running application for security vulnerabilities using dynamic analysis (DAST)

Results are uploaded to GitHub Security tab (Code scanning alerts) and StackHawk dashboard.

## Pre-commit Hooks

Local git hooks prevent secrets from being committed to version control.

### Setup

```bash
# Install pre-commit framework
pip install pre-commit

# Install hooks
pre-commit install
```

### Configuration

- `.pre-commit-config.yaml` - Hook definitions and versions
- `.gitleaks.toml` - Gitleaks custom rules and allowlists

### Hooks Enabled

1. **Gitleaks** - Scans commits for secrets (API keys, passwords, tokens)
2. **Trailing whitespace** - Removes trailing spaces
3. **End of file fixer** - Ensures files end with newline
4. **YAML checker** - Validates YAML syntax
5. **Mixed line endings** - Checks for Windows vs Unix line endings
6. **Hadolint** - Lints Dockerfiles for best practices

### Running Manually

```bash
# Run on staged files (what pre-commit does automatically)
pre-commit run

# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run gitleaks --all-files

# Bypass hooks (NOT RECOMMENDED - security risk!)
git commit --no-verify  # DON'T DO THIS!
```

### Troubleshooting

**Hook fails on .env file**:
- Verify `.env` is in `.gitignore`
- Check if `.env` is tracked: `git ls-files | grep .env`
- If tracked, remove: `git rm --cached .env`

**False positives**:
- Add patterns to `.gitleaks.toml` allowlist
- Never bypass hooks for convenience

**Hook installation fails**:
- Ensure pre-commit is installed: `pre-commit --version`
- Re-run: `pre-commit install --install-hooks --overwrite`

## StackHawk DAST Scanning

Dynamic application security testing with StackHawk scans the running application for vulnerabilities.

### Local Scanning

```bash
# Ensure services are running
docker-compose up -d

# Run scan (requires hawk CLI and HAWK_API_KEY in .env)
hawk --api-key=$HAWK_API_KEY scan

# View results
# Visit https://app.stackhawk.com/applications
```

### Configuration

- `stackhawk.yml` - Scan configuration (application ID, target host, spider settings)
- `HAWK_API_KEY` - API key (set in `.env` locally, GitHub secrets for CI)
- Application ID: `889ee6e3-984f-4651-8e97-8bb68d3470a3`

### CI Integration

StackHawk runs automatically in GitHub Actions on every push to master and PR. The scan:
1. Starts all services (nginx, app, postgres) with SSL certificates
2. Waits for application to become healthy
3. Runs DAST scan against `https://localhost:443`
4. Uploads results to StackHawk platform

View scan results at https://app.stackhawk.com/scans

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

## Web UI

Access the key registration UI at `https://localhost/`.

**Directory**: `static/`
- `index.html` - Main UI entry point
- `css/style.css` - Styling
- `js/main.js` - Application logic (ES6 module)
- `js/openfhe-utils.js` - OpenFHE WASM utilities
- `js/openfhe/` - OpenFHE WASM library (3.2MB total)

**Static File Serving**: Nginx serves files from `static/` mounted to `/usr/share/nginx/html`

**BGV Parameters** (must match backend main.zig:11-14):
- Multiplicative depth: 2
- Plaintext modulus: 65537
- Security level: 128-bit

**Workflow**:
1. User clicks "Generate & Register Key"
2. WASM loads OpenFHE library (~3MB, cached after first load)
3. BGV context created, key pair generated
4. Public key serialized to base64 binary
5. POST to /api/v0.1.0/register
6. Session UUID displayed

**Testing**:
```bash
# Access UI
open https://localhost/

# Verify database after registration
docker exec -it genz-db-1 psql -U postgres -d genz_db \
  -c "SELECT session_id, length(public_key), issued_at FROM keys ORDER BY issued_at DESC LIMIT 1;"
```

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
