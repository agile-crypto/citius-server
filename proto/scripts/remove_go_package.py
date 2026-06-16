#!/usr/bin/env python3
"""Remove 'option go_package = ...' lines from .proto files."""

import argparse
import re
import sys
from pathlib import Path

GO_PACKAGE_RE = re.compile(r'^\s*option\s+go_package\s*=.*$')


def is_blank(line: str) -> bool:
    return line.strip() == ''


def process_file(path: Path) -> bool:
    original = path.read_text(encoding='utf-8')
    lines = original.splitlines(keepends=True)
    filtered = []
    i = 0
    while i < len(lines):
        if GO_PACKAGE_RE.match(lines[i]):
            # If preceded and followed by a blank line, drop the following blank too
            preceded_by_blank = filtered and is_blank(filtered[-1])
            followed_by_blank = (i + 1 < len(lines)) and is_blank(lines[i + 1])
            if preceded_by_blank and followed_by_blank:
                i += 2  # skip go_package line + trailing blank
            else:
                i += 1  # skip only the go_package line
        else:
            filtered.append(lines[i])
            i += 1
    result = ''.join(filtered)
    if result != original:
        path.write_text(result, encoding='utf-8')
        print(f'  updated: {path}')
        return True
    print(f'  skipped: {path} (no go_package option found)')
    return False


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
        description="Remove 'option go_package = ...' lines from .proto files"
    )
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

    updated = sum(process_file(f) for f in files)
    print(f'\nDone: {updated}/{len(files)} file(s) modified.')


if __name__ == '__main__':
    main()
