#!/usr/bin/env python3
"""
replace_import_proto.py — Replace import paths in .proto source files.

This script finds and replaces a specific import path across one or more .proto
files, preserving the surrounding syntax. It supports plain string matching,
regex matching, and parametrized matching with named placeholders and/or
wildcards.

Proto import statements have the form:

  import "path/to/file.proto";
  import weak "path/to/file.proto";
  import public "path/to/file.proto";

All three forms are handled; the keyword (weak/public) is preserved.

USAGE
-----
  replace_import_proto.py [OPTIONS] <old_import> <new_import>

ARGUMENTS
---------
  old_import    The import path to search for (a string, regex, or parametrized
                pattern depending on the active mode).
  new_import    The import path to replace it with (a fixed string, or a
                parametrized pattern referencing the same {name} placeholders
                and * wildcards used in old_import).

TARGET OPTIONS (mutually exclusive, one is required)
-----------------------------------------------------
  -f <file>     Operate on a single .proto file.
  -r <folder>   Operate recursively on every .proto file found under <folder>
                and all its subdirectories.

MATCH MODE OPTIONS (mutually exclusive, default: plain string match)
--------------------------------------------------------------------
  --regex       Treat <old_import> as a regular expression. All import paths
                that match the regex are replaced by the fixed string
                <new_import>.

                Example 1 — replace any v1 types import with a fixed path:
                  replace_import_proto.py --regex -r ./proto \\
                    'v1/types/.*\\.proto' \\
                    'api/types/common.proto'

                Example 2 — replace any internal package import:
                  replace_import_proto.py --regex -f service.proto \\
                    '.*/internal/.*' \\
                    'shared/utils.proto'

  --parametrized
                Both <old_import> and <new_import> may contain two kinds of
                capture tokens, which can be freely combined:

                  {name}   Named placeholder. Matches one or more path segments
                           but never crosses a '/' boundary. The captured value
                           is substituted wherever {name} appears in
                           <new_import>. Every {name} in <new_import> must also
                           appear in <old_import>.

                  *        Anonymous wildcard. Matches any substring including
                           '/' characters (i.e. spans multiple path segments).
                           Wildcards are positional: the 1st * in <old_import>
                           maps to the 1st * in <new_import>, the 2nd to the
                           2nd, etc. When multiple wildcards are present, all
                           but the last match lazily (shortest possible match)
                           and the last matches greedily (longest possible
                           match). The number of * tokens must be the same in
                           both patterns.

                Example 1 — wildcard only, insert a new segment in the middle:
                  replace_import_proto.py --parametrized -r ./proto \\
                    'types/*' \\
                    'api/types/*'

                  types/common.proto  →  api/types/common.proto

                Example 2 — two wildcards, rename a versioned sub-path while
                keeping surrounding segments intact:
                  replace_import_proto.py --parametrized -r ./proto \\
                    '*/v1/*' \\
                    '*/v2/*'

                  org/myservice/v1/types/common.proto
                    →  org/myservice/v2/types/common.proto

                Example 3 — named placeholders only, prefix a package:
                  replace_import_proto.py --parametrized -r ./proto \\
                    '{pkg}/{file}.proto' \\
                    'api/{pkg}/{file}.proto'

                  messages/request.proto  →  api/messages/request.proto

                Example 4 — named placeholders combined with a wildcard:
                  replace_import_proto.py --parametrized -r ./proto \\
                    '{top}/*' \\
                    'api/{top}/*'

                  types/algo/params.proto  →  api/types/algo/params.proto

OTHER OPTIONS
-------------
  -h, --help    Show this help message and exit.
  --dry-run     Print what would be changed without modifying any files.
  -v, --verbose Print each file processed and every replacement made.
"""

import argparse
import os
import re
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Import line parsing
# ---------------------------------------------------------------------------

# Matches:  import "path";  or  import weak "path";  or  import public "path";
_IMPORT_RE = re.compile(
    r'^(?P<indent>\s*)import\s+(?P<keyword>(?:weak|public)\s+)?"(?P<path>[^"]+)"\s*;'
)


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

_WILDCARD_PREFIX = '_wc_'


def _build_old_pattern(old_import: str, regex: bool, parametrized: bool):
    """
    Return (compiled_regex, placeholder_names, wildcard_count).

    placeholder_names  — ordered list of {name} placeholders found in
                         old_import (empty when not --parametrized).
    wildcard_count     — number of * tokens found in old_import.
    """
    if parametrized:
        tokens = re.split(r'(\{[^}]+\}|\*)', old_import)

        wildcard_total = sum(1 for t in tokens if t == '*')
        wildcard_idx = 0

        pattern_parts: list[str] = []
        placeholder_names: list[str] = []

        for token in tokens:
            if token.startswith('{') and token.endswith('}'):
                name = token[1:-1]
                placeholder_names.append(name)
                pattern_parts.append(f'(?P<{name}>[^/]+)')
            elif token == '*':
                group_name = f'{_WILDCARD_PREFIX}{wildcard_idx}'
                is_last = (wildcard_idx == wildcard_total - 1)
                quantifier = '.*' if is_last else '.*?'
                pattern_parts.append(f'(?P<{group_name}>{quantifier})')
                wildcard_idx += 1
            else:
                pattern_parts.append(re.escape(token))

        full_pattern = ''.join(pattern_parts)
        return (
            re.compile(f'^{full_pattern}$'),
            placeholder_names,
            wildcard_total,
        )

    if regex:
        return re.compile(old_import), [], 0

    return re.compile(f'^{re.escape(old_import)}$'), [], 0


def _make_replacement(
    match: re.Match,
    new_import: str,
    placeholder_names: list[str],
    wildcard_count: int,
) -> str:
    result = new_import

    for name in placeholder_names:
        result = result.replace(f'{{{name}}}', match.group(name))

    for i in range(wildcard_count):
        group_name = f'{_WILDCARD_PREFIX}{i}'
        captured = match.group(group_name)
        result = result.replace('*', captured, 1)

    return result


# ---------------------------------------------------------------------------
# Line-level rewriter
# ---------------------------------------------------------------------------

def _try_replace_path(
    path: str,
    old_re: re.Pattern,
    new_import: str,
    placeholder_names: list[str],
    wildcard_count: int,
) -> Optional[str]:
    m = old_re.search(path)
    if m is None:
        return None
    if not placeholder_names and not wildcard_count:
        return new_import
    return _make_replacement(m, new_import, placeholder_names, wildcard_count)


def process_source(
    source: str,
    old_re: re.Pattern,
    new_import: str,
    placeholder_names: list[str],
    wildcard_count: int,
) -> tuple[str, int]:
    """
    Rewrite *source* (the full text of a .proto file), replacing matching
    import paths. Returns (new_source, number_of_replacements).
    """
    lines = source.splitlines(keepends=True)
    out = []
    replacements = 0

    for line in lines:
        m = _IMPORT_RE.match(line)
        if m:
            path = m.group('path')
            new_path = _try_replace_path(
                path, old_re, new_import, placeholder_names, wildcard_count
            )
            if new_path is not None and new_path != path:
                indent = m.group('indent')
                keyword = m.group('keyword') or ''
                line = f'{indent}import {keyword}"{new_path}";\n'
                replacements += 1
        out.append(line)

    return ''.join(out), replacements


# ---------------------------------------------------------------------------
# File / directory helpers
# ---------------------------------------------------------------------------

def process_file(
    filepath: str,
    old_re: re.Pattern,
    new_import: str,
    placeholder_names: list[str],
    wildcard_count: int,
    dry_run: bool,
    verbose: bool,
) -> int:
    """Process a single .proto file. Returns number of replacements made."""
    try:
        with open(filepath, 'r', encoding='utf-8') as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        print(f'[WARN] Cannot read {filepath}: {exc}', file=sys.stderr)
        return 0

    new_source, count = process_source(
        source, old_re, new_import, placeholder_names, wildcard_count
    )

    if count == 0:
        if verbose:
            print(f'  (no match) {filepath}')
        return 0

    if verbose or dry_run:
        tag = '[dry-run] ' if dry_run else ''
        print(f'  {tag}{filepath}: {count} replacement(s)')

    if not dry_run:
        try:
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write(new_source)
        except OSError as exc:
            print(f'[ERROR] Cannot write {filepath}: {exc}', file=sys.stderr)

    return count


def process_directory(
    folder: str,
    old_re: re.Pattern,
    new_import: str,
    placeholder_names: list[str],
    wildcard_count: int,
    dry_run: bool,
    verbose: bool,
) -> tuple[int, int]:
    """Walk *folder* recursively. Returns (files_changed, total_replacements)."""
    files_changed = 0
    total = 0
    for root, _dirs, files in os.walk(folder):
        for fname in files:
            if not fname.endswith('.proto'):
                continue
            fpath = os.path.join(root, fname)
            n = process_file(
                fpath, old_re, new_import, placeholder_names, wildcard_count,
                dry_run, verbose,
            )
            if n:
                files_changed += 1
                total += n
    return files_changed, total


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_parametrized(old_import: str, new_import: str) -> None:
    old_names = set(re.findall(r'\{(\w+)\}', old_import))
    new_names = re.findall(r'\{(\w+)\}', new_import)
    missing = set(new_names) - old_names
    if missing:
        sys.exit(
            '[ERROR] Placeholder(s) in new_import not present in old_import: '
            + ', '.join(f'{{{n}}}' for n in sorted(missing))
        )

    old_wc = old_import.count('*')
    new_wc = new_import.count('*')
    if old_wc != new_wc:
        sys.exit(
            f'[ERROR] Wildcard count mismatch: old_import has {old_wc} * '
            f'but new_import has {new_wc} *. They must be equal.'
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='replace_import_proto.py',
        description=(
            'Replace import paths in .proto source files.\n\n'
            'Default mode: plain exact string match.\n'
            '--regex: treat old_import as a regular expression.\n'
            '--parametrized: use {name} placeholders (single segment) and/or\n'
            '  * wildcards (multi-segment, positional) in both import paths.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
        add_help=False,
    )

    parser.add_argument('-h', '--help', action='help',
                        help='Show this help message and exit.')

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('-f', metavar='FILE', dest='file',
                        help='Operate on a single .proto file.')
    target.add_argument('-r', metavar='FOLDER', dest='folder',
                        help='Operate recursively on all .proto files under FOLDER.')

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--regex', action='store_true',
                      help='Treat old_import as a regular expression.')
    mode.add_argument(
        '--parametrized', action='store_true',
        help=(
            'Enable capture tokens in both import paths. '
            '{name} matches one segment (no /). '
            '* matches any substring including / (multi-segment, positional). '
            'All but the last * are lazy; the last is greedy. '
            'Wildcard count must be equal in both patterns.'
        ),
    )

    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would change without modifying any files.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print each file processed and every replacement made.')

    parser.add_argument('old_import', help='Import path to search for.')
    parser.add_argument('new_import', help='Import path to replace it with.')

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.parametrized:
        validate_parametrized(args.old_import, args.new_import)

    try:
        old_re, placeholder_names, wildcard_count = _build_old_pattern(
            args.old_import, args.regex, args.parametrized
        )
    except re.error as exc:
        sys.exit(f'[ERROR] Invalid regular expression: {exc}')

    if args.file:
        if not os.path.isfile(args.file):
            sys.exit(f'[ERROR] File not found: {args.file}')
        if verbose := args.verbose or args.dry_run:
            print(f'Processing file: {args.file}')
        n = process_file(
            args.file, old_re, args.new_import, placeholder_names,
            wildcard_count, args.dry_run, args.verbose,
        )
        print(f'{n} replacement(s) in 1 file.')
    else:
        if not os.path.isdir(args.folder):
            sys.exit(f'[ERROR] Folder not found: {args.folder}')
        if args.verbose or args.dry_run:
            print(f'Processing folder: {args.folder}')
        files_changed, total = process_directory(
            args.folder, old_re, args.new_import, placeholder_names,
            wildcard_count, args.dry_run, args.verbose,
        )
        print(f'{total} replacement(s) across {files_changed} file(s).')


if __name__ == '__main__':
    main()
