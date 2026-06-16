#!/usr/bin/env python3
"""
update_api_proto.py — Pull a fresh proto/api from a remote repository and
re-wire all go_package options and import paths to match the citius-server
layout.

OVERVIEW
--------
The script performs the following steps in order:

  1. Rename proto/api  →  proto/api-backup
  2. Clone <repo_url> into proto/fetched-repo  (shallow, single branch)
  3. Copy proto/fetched-repo/<proto_folder>/{proto_package}  →  proto/api, for all {proto_package} in PROTO_PACKAGES_API 
     NB: Update the list PROTO_PACKAGES_API in this script if the structure of the fetched proto changes (e.g. new subfolders are added).
  4. Remove every existing go_package option from proto/api/**/*.proto
  5. For each direct subfolder F of proto/api:
       a. Add  option go_package = "github.ibm.com/citius/citius-server/gen/go/api/F;api";
          to every .proto file inside that subfolder.
       b. For every *other* subfolder S of proto/api, rewrite import paths
          inside proto/api/F/**  of the form
            import "S/..."
          to
            import "api/S/..."
  6. For every .proto file directly in proto/api/ (root-level, not in
     subdirectories):
       a. Remove any existing go_package option and add
            option go_package = "github.ibm.com/citius/citius-server/gen/go/api;api";
       b. Rewrite import paths as in step 5b (S/... → api/S/...) for every
          subfolder S.
  7. Run  buf lint  from the proto/ directory.
  8. On SUCCESS: delete proto/api-backup and proto/fetched-repo.
  9. On FAILURE: report the lint error and ask the user whether to restore
     the previous state (yes/no).  See "SESSION RESUME" below.

SESSION RESUME
--------------
After a failed run (proto/api-backup exists), subsequent invocations MUST
supply one of:

  --continue   Re-run buf lint against the current proto/api.
               On success: delete proto/api-backup and proto/fetched-repo.
               On failure: print the error and exit (nothing is changed).

  --abort      Restore the previous state:
               - Delete proto/api and proto/fetched-repo.
               - Rename proto/api-backup back to proto/api.

Running the script without either flag when proto/api-backup exists is an
error.

USAGE
-----
  update_api_proto.py [OPTIONS] <repo_url> <proto_folder>

  update_api_proto.py --continue
  update_api_proto.py --abort

ARGUMENTS
---------
  repo_url       URL of the git repository to pull (e.g.
                 https://github.com/org/repo.git).
  proto_folder   Name of the folder *inside the cloned repository* whose
                 contents become the new proto/api.
                 Example: if the repo has  myrepo/proto_ex/*.proto  and you
                 pass proto_folder=proto_ex, then proto_ex/ is copied to
                 proto/api.

OPTIONS
-------
  --branch BRANCH   Git branch to check out (default: repository default).
  --continue        Resume a previously interrupted session (re-lint only).
  --abort           Restore the previous state after a failed session.
  --debug           Enable debug-level output (internal step details, paths,
                    per-file actions). Hidden by default.
  -h, --help        Show this help message and exit.

EXAMPLES
--------
  # Pull from a GitHub repo, use the repo's folder named "proto" as proto/api (branch defaults to repo default):
  update_api_proto.py https://github.com/org/myrepo.git proto

  # Same, but target a specific branch:
  update_api_proto.py --branch develop https://github.com/org/myrepo.git proto

  # After a lint failure, try again after manual fixes:
  update_api_proto.py --continue

  # After a failure, give up and restore:
  update_api_proto.py --abort
"""

import argparse
import logging
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (all relative to the repository root, resolved at runtime)
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent          # proto/scripts/
PROTO_DIR = SCRIPT_DIR.parent                          # proto/
API_DIR = PROTO_DIR / 'api'                            # proto/api/
API_BACKUP_DIR = PROTO_DIR / 'api-backup'              # proto/api-backup/
FETCHED_REPO_DIR = PROTO_DIR / 'fetched-repo'         # proto/fetched-repo/

PROTO_SUBFOLDERS_SERVER = ['api', 'server']
PROTO_PACKAGES_API = ['messages', 'services', 'types']

GO_MODULE = 'github.ibm.com/citius/citius-server'
GO_PKG_API_ROOT = f'{GO_MODULE}/gen/go/api'

REMOVE_GO_PKG_SCRIPT = SCRIPT_DIR / 'remove_go_package.py'
ADD_GO_PKG_SCRIPT = SCRIPT_DIR / 'add_go_package.py'
REPLACE_IMPORT_PROTO_SCRIPT = SCRIPT_DIR / 'replace_import_proto.py'


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

class _LevelPrefixFormatter(logging.Formatter):
    """Formats log records as plain terminal lines with level-dependent prefixes.

    DEBUG   → [DEBUG] message
    WARNING → [WARN]  message
    ERROR   → [ERROR] message
    INFO    → message  (no prefix — indistinguishable from a plain print)
    """
    _PREFIXES = {
        logging.DEBUG:   '[DEBUG] ',
        logging.WARNING: '[WARN] ',
        logging.ERROR:   '[ERROR] ',
    }

    def format(self, record: logging.LogRecord) -> str:
        prefix = self._PREFIXES.get(record.levelno, '')
        return prefix + record.getMessage()


def _setup_logging(debug: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_LevelPrefixFormatter())
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, handlers=[handler])


logger = logging.getLogger('update_api_proto')


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def die(msg: str) -> None:
    logger.error(msg)
    sys.exit(1)


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command, streaming its output. Raises on non-zero exit if check=True."""
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result


def run_captured(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command capturing stdout/stderr. Returns (returncode, stdout, stderr)."""
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    return result.returncode, result.stdout, result.stderr


def require_script(path: Path) -> None:
    if not path.is_file():
        die(f'Required helper script not found: {path}')


def ask_yes_no(question: str) -> bool:
    while True:
        answer = input(f'{question} [yes/no]: ').strip().lower()
        if answer in ('yes', 'y'):
            return True
        if answer in ('no', 'n'):
            return False
        print('Please answer yes or no.')


def get_api_subfolders() -> list[str]:
    """Return the list of direct subfolder names inside proto/api/."""
    if not API_DIR.is_dir():
        die(f'proto/api directory not found: {API_DIR}')
    subfolders = [p.name for p in sorted(API_DIR.iterdir()) if p.is_dir()]
    return subfolders


def get_api_root_protos() -> list[Path]:
    """Return .proto files directly in proto/api/ (not in subdirectories)."""
    if not API_DIR.is_dir():
        die(f'proto/api directory not found: {API_DIR}')
    return sorted(p for p in API_DIR.iterdir() if p.is_file() and p.suffix == '.proto')


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------

def step_backup() -> None:
    logger.debug('\n[Step 1] Renaming proto/api → proto/api-backup ...')
    if not API_DIR.exists():
        die(f'proto/api not found at {API_DIR}. Nothing to back up.')
    if API_BACKUP_DIR.exists():
        die(
            f'proto/api-backup already exists at {API_BACKUP_DIR}. '
            'A previous session may have been interrupted. '
            'Run with --continue to resume or --abort to restore.'
        )
    API_DIR.rename(API_BACKUP_DIR)
    logger.debug(f'  Backed up to {API_BACKUP_DIR}')


def step_clone(repo_url: str, branch: str | None) -> None:
    logger.debug(f'\n[Step 2] Cloning {repo_url} into proto/fetched-repo ...')
    if FETCHED_REPO_DIR.exists():
        logger.debug(f'  Removing stale {FETCHED_REPO_DIR} ...')
        shutil.rmtree(FETCHED_REPO_DIR)
    cmd = ['git', 'clone', '--depth', '1']
    if branch:
        cmd += ['--branch', branch]
    cmd += [repo_url, str(FETCHED_REPO_DIR)]
    try:
        run(cmd)
    except subprocess.CalledProcessError:
        die(f'git clone failed for {repo_url}')
    logger.debug(f'  Cloned into {FETCHED_REPO_DIR}')


def step_copy(proto_folder: str) -> None:
    logger.debug(f'\n[Step 3] Copying proto/fetched-repo/{proto_folder} → proto/api ...')
    src = FETCHED_REPO_DIR / proto_folder
    if not src.exists():
        die(
            f'Folder "{proto_folder}" not found inside the cloned repository.\n'
            f'  Expected: {src}\n'
            f'  Available top-level entries: '
            + ', '.join(p.name for p in sorted(FETCHED_REPO_DIR.iterdir()))
        )
    if not src.is_dir():
        die(f'"{proto_folder}" exists in the cloned repo but is not a directory: {src}')
    if API_DIR.exists():
        logger.debug(f'  Removing stale {API_DIR} ...')
        shutil.rmtree(API_DIR)
    for pkg in PROTO_PACKAGES_API:
        pkg_src = src / pkg
        if not pkg_src.is_dir():
            die(f'Expected package subfolder "{pkg}" not found in {src}.')
        shutil.copytree(pkg_src, API_DIR / pkg)
        logger.debug(f'  Copied {pkg_src} → {API_DIR / pkg}')


def step_remove_go_package() -> None:
    logger.debug('\n[Step 4] Removing all go_package options from proto/api/**/*.proto ...')
    require_script(REMOVE_GO_PKG_SCRIPT)
    try:
        run([sys.executable, str(REMOVE_GO_PKG_SCRIPT), '-r', str(API_DIR)])
    except subprocess.CalledProcessError:
        die('remove_go_package.py failed.')


def step_add_go_packages_and_fix_imports(subfolders: list[str]) -> None:
    logger.debug('\n[Step 5] Adding go_package options and fixing import paths in proto/api subfolders ...')
    require_script(ADD_GO_PKG_SCRIPT)

    for pkg in PROTO_PACKAGES_API:
        pkg_dir = API_DIR / pkg
        if not pkg_dir.is_dir():
            die(f'Expected subfolder not found: {pkg_dir}')

        # 5a — add go_package
        go_pkg = f'{GO_PKG_API_ROOT}/{pkg};api'
        logger.debug(f'\n  [{pkg}] Adding go_package = "{go_pkg}" ...')
        try:
            run([sys.executable, str(ADD_GO_PKG_SCRIPT), go_pkg, '-r', str(pkg_dir)])
        except subprocess.CalledProcessError:
            die(f'add_go_package.py failed for subfolder "{pkg}".')

        # 5b — rewrite imports: for every *other* subfolder S, rewrite S/... → api/S/...
        logger.debug(f'  [{pkg}] Rewriting cross-subfolder import paths ...')
        for p in PROTO_PACKAGES_API:
            _rewrite_imports_in_dir(pkg_dir, old_prefix=p, new_prefix=f'api/{p}')


def step_fix_root_api_protos(subfolders: list[str]) -> None:
    root_protos = get_api_root_protos()
    if not root_protos:
        logger.debug('\n[Step 6] No root-level .proto files in proto/api/ — skipping.')
        return

    print(f'\n[Step 6] Processing {len(root_protos)} root-level .proto file(s) in proto/api/ ...')
    require_script(REMOVE_GO_PKG_SCRIPT)
    require_script(ADD_GO_PKG_SCRIPT)

    go_pkg = f'{GO_PKG_API_ROOT};api'

    for proto_file in root_protos:
        logger.debug(f'\n  [{proto_file.name}]')

        # 6a — remove existing go_package, then add the correct one
        try:
            run([sys.executable, str(REMOVE_GO_PKG_SCRIPT), '-f', str(proto_file)])
        except subprocess.CalledProcessError:
            die(f'remove_go_package.py failed for {proto_file}.')
        try:
            run([sys.executable, str(ADD_GO_PKG_SCRIPT), go_pkg, '-f', str(proto_file)])
        except subprocess.CalledProcessError:
            die(f'add_go_package.py failed for {proto_file}.')

        # 6b — rewrite imports: S/... → api/S/... for each subfolder S
        for s in subfolders:
            _rewrite_imports_in_file(proto_file, old_prefix=s, new_prefix=f'api/{s}')


def step_lint() -> tuple[bool, str]:
    lint_paths = [PROTO_DIR / subfolder for subfolder in PROTO_SUBFOLDERS_SERVER]
    logger.debug('\n[Step 7] Running buf lint on: ' + ', '.join(str(p) for p in lint_paths))
    lint_opts = [['--path', str(p)] for p in lint_paths]
    lint_opts = [opt for sublist in lint_opts for opt in sublist]
    rc, stdout, stderr = run_captured(['buf', 'lint'] + lint_opts, cwd=PROTO_DIR)
    output = (stdout + stderr).strip()
    if rc == 0:
        logger.debug('  buf lint passed.')
        return True, ''
    logger.debug('  buf lint FAILED:')
    print(output)
    return False, output


def step_cleanup() -> None:
    logger.debug('\n[Step 8] Cleaning up backup and fetched-repo ...')
    if API_BACKUP_DIR.exists():
        shutil.rmtree(API_BACKUP_DIR)
        logger.debug(f'  Removed {API_BACKUP_DIR}')
    if FETCHED_REPO_DIR.exists():
        shutil.rmtree(FETCHED_REPO_DIR)
        logger.debug(f'  Removed {FETCHED_REPO_DIR}')


def step_restore() -> None:
    print('\nRestoring previous state ...')
    if API_DIR.exists():
        shutil.rmtree(API_DIR)
        logger.debug(f'  Removed {API_DIR}')
    if FETCHED_REPO_DIR.exists():
        shutil.rmtree(FETCHED_REPO_DIR)
        logger.debug(f'  Removed {FETCHED_REPO_DIR}')
    if API_BACKUP_DIR.exists():
        API_BACKUP_DIR.rename(API_DIR)
        logger.debug(f'  Restored {API_BACKUP_DIR} → {API_DIR}')
    else:
        logger.warning('proto/api-backup not found — nothing to restore.')
    print('State restored.')


# ---------------------------------------------------------------------------
# Import rewriting helpers (delegate to replace_import_proto.py)
# ---------------------------------------------------------------------------

def _rewrite_imports_in_file(proto_file: Path, old_prefix: str, new_prefix: str) -> None:
    require_script(REPLACE_IMPORT_PROTO_SCRIPT)
    try:
        run([
            sys.executable, str(REPLACE_IMPORT_PROTO_SCRIPT),
            '--parametrized', '-f', str(proto_file),
            f'{old_prefix}/*', f'{new_prefix}/*',
        ])
    except subprocess.CalledProcessError:
        die(f'replace_import_proto.py failed for {proto_file} ({old_prefix} → {new_prefix})')


def _rewrite_imports_in_dir(directory: Path, old_prefix: str, new_prefix: str) -> None:
    require_script(REPLACE_IMPORT_PROTO_SCRIPT)
    try:
        run([
            sys.executable, str(REPLACE_IMPORT_PROTO_SCRIPT),
            '--parametrized', '-r', str(directory),
            f'{old_prefix}/*', f'{new_prefix}/*',
        ])
    except subprocess.CalledProcessError:
        die(f'replace_import_proto.py failed for {directory} ({old_prefix} → {new_prefix})')


# ---------------------------------------------------------------------------
# Session modes
# ---------------------------------------------------------------------------

def run_continue() -> None:
    if not API_BACKUP_DIR.exists():
        die(
            'proto/api-backup does not exist — no interrupted session to continue.\n'
            'Run without --continue to start a fresh update.'
        )
    ok, err = step_lint()
    if ok:
        step_cleanup()
        print('\nDone. proto/api is up to date.')
    else:
        print('\nbuf lint still fails. Fix the issues and run --continue again.')
        sys.exit(1)


def run_abort() -> None:
    if not API_BACKUP_DIR.exists():
        die(
            'proto/api-backup does not exist — no interrupted session to abort.\n'
            'Nothing to restore.'
        )
    step_restore()


def run_main(repo_url: str, proto_folder: str, branch: str | None) -> None:
    # Guard: if a previous session left api-backup, require explicit flag
    if API_BACKUP_DIR.exists():
        die(
            'A session is in progress.\n'
            '  --continue  Re-run buf lint; clean up on success.\n'
            '  --abort     Restore the previous state.'
        )

    # Check required helper scripts are present before touching anything
    require_script(REMOVE_GO_PKG_SCRIPT)
    require_script(ADD_GO_PKG_SCRIPT)

    step_backup()
    step_clone(repo_url, branch)
    step_copy(proto_folder)

    # Discover subfolders AFTER copying (they come from the fetched repo)
    subfolders = get_api_subfolders()
    if not subfolders:
        die(f'No subfolders found inside proto/api after copy from "{proto_folder}".')
    logger.debug(f'\n  Discovered api subfolders: {", ".join(subfolders)}')

    step_remove_go_package()
    step_add_go_packages_and_fix_imports(subfolders)
    step_fix_root_api_protos(subfolders)

    ok, lint_err = step_lint()
    if ok:
        step_cleanup()
        print('\nDone. proto/api updated successfully.')
        return

    # Lint failed — ask what to do
    print('\nbuf lint failed with error:')
    print(lint_err)
    restore = ask_yes_no('\n\nRestore previous state?')
    if restore:
        step_restore()
        print('\nPrevious state restored.')
    else:
        # Keep proto/api and proto/api-backup as-is, remove fetched-repo only
        if FETCHED_REPO_DIR.exists():
            shutil.rmtree(FETCHED_REPO_DIR)
            logger.debug(f'  Removed {FETCHED_REPO_DIR}')
        print(
            '\nFix the issues manually, then run:\n'
            '  update_api_proto.py --continue   to re-lint and finish\n'
            '  update_api_proto.py --abort      to restore the previous state'
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='update_api_proto.py',
        description=(
            'Pull a fresh proto/api from a remote git repository and\n'
            're-wire all go_package options and import paths to match\n'
            'the citius-server layout.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
        add_help=False,
    )

    parser.add_argument('-h', '--help', action='help',
                        help='Show this help message and exit.')

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--continue', dest='resume', action='store_true',
                      help='Re-lint after manual fixes; clean up on success.')
    mode.add_argument('--abort', action='store_true',
                      help='Restore previous state after a failed session.')

    parser.add_argument('--branch', metavar='BRANCH', default=None,
                        help='Git branch to check out (default: repo default branch).')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug-level output (shows internal step details).')

    parser.add_argument('repo_url', nargs='?',
                        help='URL of the git repository to clone.')
    parser.add_argument('proto_folder', nargs='?',
                        help='Folder name inside the cloned repo to use as proto/api.')

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.debug)

    if args.resume:
        run_continue()
        return

    if args.abort:
        run_abort()
        return

    # Normal run — both positional arguments are required
    if not args.repo_url:
        parser.print_help()
        die('\nrepo_url is required for a normal run.')
    if not args.proto_folder:
        parser.print_help()
        die('\nproto_folder is required for a normal run.')

    run_main(args.repo_url, args.proto_folder, args.branch)


if __name__ == '__main__':
    main()
