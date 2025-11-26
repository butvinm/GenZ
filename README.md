> [!WARNING]
> Work in progress

# Toy implementation of DNA processing service with Homomorphic Encryption

## Deployment

### Prerequisites

- Docker and Docker Compose
- OpenSSL (for certificate generation)

### Setup

1. Generate SSL certificates:

```bash
./scripts/generate-certs.sh
```

To regenerate certificates:

```bash
./scripts/generate-certs.sh --force
```

2. Start services:

```bash
docker-compose up
```

The API will be available at `https://localhost:443`.

### Configuration

Environment variables in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `HTTPS_PORT` | External HTTPS port | `443` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | `postgres` |
| `DB_DATABASE` | Database name | `genz_db` |

### Testing

```bash
curl -k -X POST "https://localhost:443/api/v0.1.0/register" \
  -H "Content-Type: application/json" \
  --data '{"publicKey": "UE9SVD02OTY5Cg=="}'
```

Note: `-k` flag skips SSL certificate verification (required for self-signed certificates).
