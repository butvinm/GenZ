#!/bin/bash

set -e

API_URL=http://localhost:6969

echo "[create session]"
SESSION_ID=$(curl -s -k -X POST "${API_URL}/api/v0.1.0/register" | jq -e '.sessionId')

echo "SESSION_ID=$SESSION_ID"
