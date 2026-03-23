#!/bin/bash
# merge_catalog.sh - Merges split catalog JSON files into a single catalog.json
#
# This script combines all category-specific JSON files (symmetric.json, signatures.json, etc.)
# into a single standard_algorithms.json file for easy consumption by SDKs.
#
# Usage: ./merge_catalog.sh
# Output: ../standard_algorithms.json (one directory up, in proto/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/../standard_algorithms.json"

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Install with: brew install jq (macOS) or apt install jq (Linux)"
    exit 1
fi

# Find all JSON files in the directory (excluding the output file if it exists there)
JSON_FILES=$(find "$SCRIPT_DIR" -maxdepth 1 -name "*.json" -type f | sort)

if [ -z "$JSON_FILES" ]; then
    echo "Error: No JSON files found in $SCRIPT_DIR"
    exit 1
fi

echo "Merging catalog files..."
for f in $JSON_FILES; do
    echo "  - $(basename "$f")"
done

# Merge all JSON files:
# - Combine all templates maps into one
# - Filter out comment entries (keys starting with _comment)
# - Concatenate all families arrays
# - Add metadata
jq -s '{
  "version": "1.0.0",
  "description": "CaaS Standard Algorithm Catalog - Merged from category files",
  "lastUpdated": (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
  "templates": (map(.templates // {}) | add | with_entries(select(.key | startswith("_") | not))),
  "families": (map(.families // []) | add)
}' $JSON_FILES > "$OUTPUT_FILE"

# Count templates and families
TEMPLATE_COUNT=$(jq '.templates | length' "$OUTPUT_FILE")
FAMILY_COUNT=$(jq '.families | length' "$OUTPUT_FILE")

echo ""
echo "Generated: $OUTPUT_FILE"
echo "  Templates: $TEMPLATE_COUNT"
echo "  Families:  $FAMILY_COUNT"
