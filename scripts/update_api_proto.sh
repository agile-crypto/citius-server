#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <repo_url> <go_module> <proto_packages> <proto_folder> <tmp_dir>" >&2
    echo "  repo_url       Git URL of the API repo  (e.g. git@github.ibm.com:org/api.git)" >&2
    echo "  go_module      Go module name            (e.g. github.ibm.com/citius/citius-server)" >&2
    echo "  proto_packages Comma-separated packages  (e.g. messages,services,types)" >&2
    echo "  proto_folder   Folder containing proto files (e.g. proto)" >&2
    echo "  tmp_dir        Temporary directory for keeping old state during the update" >&2
    exit 1
}

[[ $# -eq 5 ]] || usage

REPO_URL="$1"
GO_MODULE="$2"
PROTO_PACKAGES="$3"
PROTO_FOLDER="$4"
TMP_DIR="$5"

# Detect python command
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "ERROR: missing python command" >&2
    exit 1
fi

SCRIPT="$PYTHON proto/scripts/update_api_proto.py"

# Creates temporary directory
if ! mkdir "$TMP_DIR"; then
    echo "failed to create temporary directory" >&2
    exit 1
fi

# Step 1 — pull and rewrite proto/api

if ! $SCRIPT --keep-state --branch main \
        --go-module "$GO_MODULE" \
        --proto-packages "$PROTO_PACKAGES" \
        --tmp-dir "$TMP_DIR" \
        "$REPO_URL" "$PROTO_FOLDER" > /dev/null; then
    echo "failed to update API proto" >&2
    $SCRIPT --abort --tmp-dir "$TMP_DIR" > /dev/null
    rm -rf "$TMP_DIR"
    exit 1
fi

# Step 2 — generate Go code from the new protos
if ! (cd proto && buf generate); then
    echo "failed to update API proto" >&2
    $SCRIPT --abort --tmp-dir "$TMP_DIR" > /dev/null
    rm -rf "$TMP_DIR"
    exit 1
fi

# Step 3 — lint passed implicitly by --keep-state; finalize
$SCRIPT --continue --tmp-dir "$TMP_DIR" > /dev/null
rm -rf "$TMP_DIR"
echo "API proto files updated successfully."
echo "If the API proto layout has changed, please discard the stale generated code."
echo "You may delete the generated code folder, and re-run 'make proto'."
echo "You may need to update import statements in your Go code."