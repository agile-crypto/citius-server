#!/usr/bin/env bash
#
# Seed crypto policies into a running Citius server over plaintext gRPC.
#
# Usage: scripts/seed_policies.sh [ADDR] [POLICY_DIR]
#   ADDR        server address (default: localhost:50051)
#   POLICY_DIR  directory of <policy-name>.json policy documents
#               (default: dev/policies)
#
# The server keeps policies in memory, so they must be re-seeded after every
# server restart. The server must run with -grpc-reflection (grpcurl resolves
# the API through it) and without auth/TLS. An already-existing policy counts
# as success, so the script is safe to re-run.
#
# Requires: grpcurl, jq.

set -euo pipefail

ADDR=${1:-localhost:50051}
POLICY_DIR=${2:-dev/policies}
METHOD=caas.crypto.v1.CryptoPolicyService/CreateCryptoPolicy

shopt -s nullglob
files=("$POLICY_DIR"/*.json)
if [ ${#files[@]} -eq 0 ]; then
	echo "ERROR: no *.json policy documents in $POLICY_DIR" >&2
	exit 1
fi

failed=0
for f in "${files[@]}"; do
	name=$(basename "$f" .json)
	# policy_document is a string field: embed the file's JSON as a string.
	req=$(jq -n --arg name "$name" --rawfile doc "$f" \
		'{name: $name, policy_document: $doc, format: "json"}')
	if out=$(grpcurl -plaintext -d "$req" "$ADDR" "$METHOD" 2>&1); then
		echo "seeded   $name"
	elif grep -q 'AlreadyExists' <<<"$out"; then
		echo "exists   $name"
	else
		echo "FAILED   $name" >&2
		echo "$out" >&2
		failed=1
	fi
done

exit $failed
