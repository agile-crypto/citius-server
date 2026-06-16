#!/usr/bin/env python3
"""Replace the package declaration in .proto files."""

import argparse
import re
import sys
from pathlib import Path


def make_pattern(old_package: str) -> re.Pattern:
    return re.compile(r'^(\s*package\s+)' + re.escape(old_package) + r'(\s*;.*)$', re.MULTILINE)


def process_file(path: Path, pattern: re.Pattern, new_package: str) -> bool:
    original = path.read_text(encoding='utf-8')
    result = pattern.sub(r'\g<1>' + new_package + r'\g<2>', original)
    if result != original:
        path.write_text(result, encoding='utf-8')
        print(f'  updated: {path}')
        return True
    print(f'  skipped: {path} (package not found)')
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
        description="Replace 'package <old>;' with 'package <new>;' in .proto files"
    )
    parser.add_argument('old_package', help='package name to replace')
    parser.add_argument('new_package', help='replacement package name')
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

    pattern = make_pattern(args.old_package)
    updated = sum(process_file(f, pattern, args.new_package) for f in files)
    print(f'\nDone: {updated}/{len(files)} file(s) modified.')


if __name__ == '__main__':
    main()
