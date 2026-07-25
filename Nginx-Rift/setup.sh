#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "Building Docker image (compiles nginx from source)..."
docker compose -f env/docker-compose.yml build

echo ""
echo "Done. To run:"
echo ""
echo "  # Terminal 1 (server) — nginx runs with ASLR disabled (setarch -R):"
echo "  docker compose -f env/docker-compose.yml up"
echo ""
echo "  # Terminal 2 (attacker):"
echo "  python3 poc.py --cmd 'echo hello from depthfirst > /tmp/pwned'"
echo ""
echo "  # Verify RCE:"
echo "  docker compose -f env/docker-compose.yml exec nginx ls -la /tmp/pwned"
echo "  docker compose -f env/docker-compose.yml exec nginx cat /tmp/pwned"
