#!/usr/bin/env python3
"""Add 'option go_package = ...' to .proto files that don't already have it."""

import argparse
import re
import sys
from pathlib import Path

GO_PACKAGE_RE = re.compile(r'^\s*option\s+go_package\s*=.*$', re.MULTILINE)
# Insert after the last top-level option line, or after the package line if none exist
PACKAGE_LINE_RE = re.compile(r'^(\s*package\s+\S+\s*;.*)$', re.MULTILINE)
OPTION_LINE_RE = re.compile(r'^(option\s+[^;]+;)$', re.MULTILINE)


def process_file(path: Path, go_package: str) -> bool:
    original = path.read_text(encoding='utf-8')

    if GO_PACKAGE_RE.search(original):
        print(f'  skipped: {path} (go_package already present)')
        return False

    go_package_line = f'option go_package = "{go_package}";'

    # Prefer inserting after the last existing option line
    last_option = None
    for m in OPTION_LINE_RE.finditer(original):
        last_option = m

    if last_option:
        insert_pos = last_option.end()
        result = original[:insert_pos] + '\n' + go_package_line + original[insert_pos:]
    else:
        # Fall back to inserting after the package line
        pkg_match = PACKAGE_LINE_RE.search(original)
        if not pkg_match:
            print(f'  skipped: {path} (no package declaration found)')
            return False
        insert_pos = pkg_match.end()
        result = original[:insert_pos] + '\n' + go_package_line + original[insert_pos:]

    path.write_text(result, encoding='utf-8')
    print(f'  updated: {path}')
    return True


def collect_files(args) -> list[Path]:
    files = []
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            sys.exit(f'Error: {args.file} is not a file')
        if p.suffix != '.proto':
            sys.exit(f'Error: {args.file} is not a .proto file')
        files.append(p)
    if args.list:
        for entry in args.list.split(','):
            p = Path(entry.strip())
            if not p.is_file():
                sys.exit(f'Error: {entry.strip()} is not a file')
            if p.suffix != '.proto':
                sys.exit(f'Error: {entry.strip()} is not a .proto file')
            files.append(p)
    if args.recursive:
        root = Path(args.recursive)
        if not root.is_dir():
            sys.exit(f'Error: {args.recursive} is not a directory')
        files.extend(sorted(root.rglob('*.proto')))
    return files


def main():
    parser = argparse.ArgumentParser(
        description="Add 'option go_package = ...' to .proto files"
    )
    parser.add_argument('go_package', help='Go package path to set (e.g. github.com/org/repo/gen/go)')
    parser.add_argument('-f', dest='file', metavar='FILE',
                        help='single .proto file')
    parser.add_argument('-l', dest='list', metavar='FILE1,FILE2,...',
                        help='comma-separated list of .proto files')
    parser.add_argument('-r', dest='recursive', metavar='DIR',
                        help='directory to search recursively for .proto files')
    args = parser.parse_args()

    if not any([args.file, args.list, args.recursive]):
        parser.print_help()
        sys.exit(1)

    files = collect_files(args)
    if not files:
        print('No .proto files found.')
        return

    updated = sum(process_file(f, args.go_package) for f in files)
    print(f'\nDone: {updated}/{len(files)} file(s) modified.')


if __name__ == '__main__':
    main()
