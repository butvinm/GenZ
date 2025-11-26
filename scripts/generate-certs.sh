#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_ROOT/certs"

CERT_FILE="$CERTS_DIR/server.crt"
KEY_FILE="$CERTS_DIR/server.key"

FORCE=false
if [[ "$1" == "--force" ]]; then
    FORCE=true
fi

mkdir -p "$CERTS_DIR"

if [[ -f "$CERT_FILE" && -f "$KEY_FILE" && "$FORCE" == false ]]; then
    echo "Certificates already exist at $CERTS_DIR"
    echo "Use --force to regenerate"
    exit 0
fi

echo "Generating self-signed SSL certificate..."

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "Certificate generated:"
echo "  Certificate: $CERT_FILE"
echo "  Private key: $KEY_FILE"
