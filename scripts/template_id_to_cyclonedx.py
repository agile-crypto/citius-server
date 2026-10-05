#!/usr/bin/env python3
"""Export a template_id -> CycloneDX name mapping from standard_algorithms.json.

Usage:
    template_id_to_cyclonedx.py <standard_algorithms.json> <output.csv>

Templates without a `cyclonedx` block (or without `cyclonedx.name`) are
omitted from the output, and each omission is logged to stderr.
"""

import argparse
import csv
import json
import logging
import sys

log = logging.getLogger("template_id_to_cyclonedx")


def build_rows(catalog: dict) -> list[tuple[str, str]]:
    rows = []
    for key, template in catalog.get("templates", {}).items():
        template_id = template.get("templateId", key)
        cyclonedx = template.get("cyclonedx")
        if not cyclonedx:
            log.warning("omitted %s: no cyclonedx block", template_id)
            continue
        name = cyclonedx.get("name")
        if not name:
            log.warning("omitted %s: cyclonedx.name is missing", template_id)
            continue
        rows.append((template_id, name))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", help="path to standard_algorithms.json")
    parser.add_argument("output", help="path to the output CSV file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    with open(args.input, encoding="utf-8") as f:
        catalog = json.load(f)

    rows = build_rows(catalog)

    with open(args.output, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["template_id", "cyclone_dx"])
        writer.writerows(rows)

    total = len(catalog.get("templates", {}))
    log.info("wrote %d of %d templates to %s", len(rows), total, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
