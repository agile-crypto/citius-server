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
After a failed run (proto/api-backup exists) or a successful run with --keep-state, subsequent invocations MUST
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
  --keep-state      Interrupt the session, even after a successful update, without cleaning up temporary state. Use this if you want to inspect the changes. The session must be terminated with "--continue" or "--abort" options.
  --debug           Enable debug-level output (internal step details, paths,
                    per-file actions). Hidden by default.
  -h, --help        Show this help message and exit.
  --go-module       Go module name of the current repo, used to construct go_package options
                    (default: github.ibm.com/citius/citius-server).
  --proto-packages  Comma-separated list of proto packages to copy from the fetched repo and update (default: messages,services,types).
  --tmp-dir         Directory to use for temporary state (default: proto/).

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

API_BACKUP_DIRNAME = 'api-backup'
FETCHED_REPO_DIRNAME = 'fetched-repo'

PROTO_SUBFOLDERS_SERVER = ['api', 'server']
DEFAULT_PROTO_PACKAGES_API = ['messages', 'services', 'types']

DEFAULT_GO_MODULE = 'github.ibm.com/citius/citius-server'
GO_PKG_API_ROOT_RELATIVE = 'gen/go/api'
DEFAULT_GO_PKG_API_ROOT = f'{DEFAULT_GO_MODULE}/{GO_PKG_API_ROOT_RELATIVE}'

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

def go_pkg_api_root(go_module: str) -> str:
    return f'{go_module}/{GO_PKG_API_ROOT_RELATIVE}'

def get_api_backup_dir(tmp_dir: Path) -> Path:
    return tmp_dir / API_BACKUP_DIRNAME

def get_fetched_repo_dir(tmp_dir: Path) -> Path:
    return tmp_dir / FETCHED_REPO_DIRNAME

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


def get_api_root_protos() -> list[Path]:
    """Return .proto files directly in proto/api/ (not in subdirectories)."""
    if not API_DIR.is_dir():
        die(f'proto/api directory not found: {API_DIR}')
    return sorted(p for p in API_DIR.iterdir() if p.is_file() and p.suffix == '.proto')


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------

def step_backup(tmp_dir: Path) -> None:
    api_backup_dir = get_api_backup_dir(tmp_dir)
    logger.debug('\n[Step 1] Renaming proto/api → proto/api-backup ...')
    if not API_DIR.exists():
        die(f'proto/api not found at {API_DIR}. Nothing to back up.')
    if api_backup_dir.exists():
        die(
            f'proto/api-backup already exists at {api_backup_dir}. '
            'A previous session may have been interrupted. '
            'Run with --continue to resume or --abort to restore.'
        )
    API_DIR.rename(api_backup_dir)
    logger.debug(f'  Backed up to {api_backup_dir}')


def step_clone(repo_url: str, branch: str | None, tmp_dir: Path) -> None:
    fetched_repo_dir = get_fetched_repo_dir(tmp_dir)
    logger.debug(f'\n[Step 2] Cloning {repo_url} into proto/fetched-repo ...')
    if fetched_repo_dir.exists():
        logger.debug(f'  Removing stale {fetched_repo_dir} ...')
        shutil.rmtree(fetched_repo_dir)
    cmd = ['git', 'clone', '--depth', '1']
    if branch:
        cmd += ['--branch', branch]
    cmd += [repo_url, str(fetched_repo_dir)]
    ret, _, stderr = run_captured(cmd)
    if ret != 0:
        die(f'git clone failed for {repo_url}: {stderr}')
    logger.debug(f'  Cloned into {fetched_repo_dir}')


def step_copy(proto_folder: str, proto_packages: list[str], tmp_dir: Path) -> None:
    logger.debug(f'\n[Step 3] Copying proto/fetched-repo/{proto_folder} → proto/api ...')
    fetched_repo_dir = get_fetched_repo_dir(tmp_dir)
    src = fetched_repo_dir / proto_folder
    if not src.exists():
        die(
            f'Folder "{proto_folder}" not found inside the cloned repository.\n'
            f'  Expected: {src}\n'
            f'  Available top-level entries: '
            + ', '.join(p.name for p in sorted(fetched_repo_dir.iterdir()))
        )
    if not src.is_dir():
        die(f'"{proto_folder}" exists in the cloned repo but is not a directory: {src}')
    if API_DIR.exists():
        logger.debug(f'  Removing stale {API_DIR} ...')
        shutil.rmtree(API_DIR)
    for pkg in proto_packages:
        pkg_src = src / pkg
        if not pkg_src.is_dir():
            die(f'Expected package subfolder "{pkg}" not found in {src}.')
        shutil.copytree(pkg_src, API_DIR / pkg)
        logger.debug(f'  Copied {pkg_src} → {API_DIR / pkg}')
    root_protos = [p for p in src.iterdir() if p.is_file() and p.suffix == '.proto']
    for proto in root_protos:
        shutil.copy2(proto, API_DIR / proto.name)
        logger.debug(f'  Copied {proto} → {API_DIR / proto.name}')


def step_remove_go_package() -> None:
    logger.debug('\n[Step 4] Removing all go_package options from proto/api/**/*.proto ...')
    require_script(REMOVE_GO_PKG_SCRIPT)
    cmd = [sys.executable, str(REMOVE_GO_PKG_SCRIPT), '-r', str(API_DIR)]
    ret, stdout, stderr = run_captured(cmd)
    if ret != 0:
        logger.debug('  remove_go_package.py (stdout): ' + stdout)
        logger.debug('  remove_go_package.py (stderr): ' + stderr)
        die('remove_go_package.py failed')

def step_add_go_packages_and_fix_imports(proto_packages: list[str], go_package_api_root: str) -> None:
    logger.debug('\n[Step 5] Adding go_package options and fixing import paths in proto/api subfolders ...')
    require_script(ADD_GO_PKG_SCRIPT)

    for pkg in proto_packages:
        pkg_dir = API_DIR / pkg
        if not pkg_dir.is_dir():
            die(f'Expected subfolder not found: {pkg_dir}')

        # 5a — add go_package
        go_pkg = f'{go_package_api_root}/{pkg};api'
        logger.debug(f'\n  [{pkg}] Adding go_package = "{go_pkg}" ...')

        cmd = [sys.executable, str(ADD_GO_PKG_SCRIPT), go_pkg, '-r', str(pkg_dir)]
        ret, stdout, stderr = run_captured(cmd)
        if ret != 0:
            logger.debug(f'  {ADD_GO_PKG_SCRIPT} (stdout): {stdout}')
            logger.debug(f'  {ADD_GO_PKG_SCRIPT} (stderr): {stderr}')
            die(f'add_go_package.py failed for subfolder "{pkg}".')

        # 5b — rewrite imports: for every *other* subfolder S, rewrite S/... → api/S/...
        logger.debug(f'  [{pkg}] Rewriting cross-subfolder import paths ...')
        for p in proto_packages:
            _rewrite_imports_in_dir(pkg_dir, old_prefix=p, new_prefix=f'api/{p}')


def step_fix_root_api_protos(proto_packages: list[str], go_package_api_root: str) -> None:
    root_protos = get_api_root_protos()
    if not root_protos:
        logger.debug('\n[Step 6] No root-level .proto files in proto/api/ — skipping.')
        return

    logger.debug(f'\n[Step 6] Processing {len(root_protos)} root-level .proto file(s) in proto/api/ ...')
    require_script(ADD_GO_PKG_SCRIPT)

    go_pkg = f'{go_package_api_root};api'

    for proto_file in root_protos:
        logger.debug(f'\n  [{proto_file.name}]')

        # 6a — add go package (old one removed in step 4)
        cmd = [sys.executable, str(ADD_GO_PKG_SCRIPT), go_pkg, '-f', str(proto_file)]
        ret, stdout, stderr = run_captured(cmd)
        if ret != 0:
            logger.debug(f'  {ADD_GO_PKG_SCRIPT} (stdout): {stdout}')
            logger.debug(f'  {ADD_GO_PKG_SCRIPT} (stderr): {stderr}')
            die(f'add_go_package.py failed for {proto_file}.')

        # 6b — rewrite imports: S/... → api/S/... for each subfolder S
        for s in proto_packages:
            _rewrite_imports_in_file(proto_file, old_prefix=s, new_prefix=f'api/{s}')


def step_lint(api_dir: Path) -> tuple[bool, str]:
    lint_cmd = ['buf', 'lint', '--path', str(api_dir)]
    logger.debug('\n[Step 7] Running buf lint on ' + str(api_dir))
    rc, stdout, stderr = run_captured(lint_cmd)
    output = (stdout + stderr).strip()
    if rc == 0:
        logger.debug('  buf lint passed.')
        return True, ''
    logger.debug('  buf lint FAILED:')
    return False, output


def step_cleanup(tmp_dir: Path) -> None:
    logger.debug('\n[Step 8] Cleaning up backup and fetched-repo ...')
    api_backup_dir = get_api_backup_dir(tmp_dir)
    if api_backup_dir.exists():
        shutil.rmtree(api_backup_dir)
        logger.debug(f'  Removed {api_backup_dir}')
    fetched_repo_dir = get_fetched_repo_dir(tmp_dir)
    if fetched_repo_dir.exists():
        shutil.rmtree(fetched_repo_dir)
        logger.debug(f'  Removed {fetched_repo_dir}')


def step_restore(tmp_dir: Path) -> None:
    api_backup_dir = get_api_backup_dir(tmp_dir)
    fetched_repo_dir = get_fetched_repo_dir(tmp_dir)
    if API_DIR.exists():
        shutil.rmtree(API_DIR)
        logger.debug(f'  Removed {API_DIR}')
    if fetched_repo_dir.exists():
        shutil.rmtree(fetched_repo_dir)
        logger.debug(f'  Removed {fetched_repo_dir}')
    if api_backup_dir.exists():
        api_backup_dir.rename(API_DIR)
        logger.debug(f'  Restored {api_backup_dir} → {API_DIR}')
    else:
        logger.warning('proto/api-backup not found — nothing to restore.')
    print('State restored.')


# ---------------------------------------------------------------------------
# Import rewriting helpers (delegate to replace_import_proto.py)
# ---------------------------------------------------------------------------

def _rewrite_imports_in_file(proto_file: Path, old_prefix: str, new_prefix: str) -> None:
    require_script(REPLACE_IMPORT_PROTO_SCRIPT)
    cmd = [
        sys.executable, str(REPLACE_IMPORT_PROTO_SCRIPT),
        '--parametrized', '-f', str(proto_file),
        f'{old_prefix}/*', f'{new_prefix}/*',
    ]
    ret, stdout, stderr = run_captured(cmd)
    if ret != 0:
        logger.debug(f'  {REPLACE_IMPORT_PROTO_SCRIPT} (stdout): {stdout}')
        logger.debug(f'  {REPLACE_IMPORT_PROTO_SCRIPT} (stderr): {stderr}')
        die(f'replace_import_proto.py failed for {proto_file} ({old_prefix} → {new_prefix})')


def _rewrite_imports_in_dir(directory: Path, old_prefix: str, new_prefix: str) -> None:
    require_script(REPLACE_IMPORT_PROTO_SCRIPT)
    cmd = [
        sys.executable, str(REPLACE_IMPORT_PROTO_SCRIPT),
            '--parametrized', '-r', str(directory),
            f'{old_prefix}/*', f'{new_prefix}/*',
        ]
    ret, stdout, stderr = run_captured(cmd)
    if ret != 0:
        logger.debug(f'  {REPLACE_IMPORT_PROTO_SCRIPT} (stdout): {stdout}')
        logger.debug(f'  {REPLACE_IMPORT_PROTO_SCRIPT} (stderr): {stderr}')
        die(f'replace_import_proto.py failed for {directory} ({old_prefix} → {new_prefix})')


# ---------------------------------------------------------------------------
# Session modes
# ---------------------------------------------------------------------------

def run_continue(proto_packages: list[str], tmp_dir: Path) -> None:
    api_backup_dir = get_api_backup_dir(tmp_dir)
    if not api_backup_dir.exists():
        die(
            'proto/api-backup does not exist — no interrupted session to continue.\n'
            'If the temporary directory is not the default, you must provide the same --tmp-dir that was used in the original run.\n'
            'Run without --continue to start a fresh update.'
        )
    ok, err = step_lint(API_DIR)
    if ok:
        step_cleanup(tmp_dir)
        print('\nDone: proto/api is up to date.')
    else:
        print(err)
        print('\nbuf lint still fails. Fix the issues and run --continue again.')
        sys.exit(1)


def run_abort(tmp_dir: Path) -> None:
    api_backup_dir = get_api_backup_dir(tmp_dir)
    if not api_backup_dir.exists():
        die(
            'proto/api-backup does not exist — no interrupted session to abort.\n'
            'If the temporary directory is not the default, you must provide the same --tmp-dir that was used in the original run.\n'
            'Nothing to restore.'
        )
    step_restore(tmp_dir)


def run_main(repo_url: str, proto_folder: str, branch: str | None, go_module: str, proto_packages: list[str], go_package_api_root: str, keep_state: bool, tmp_dir: Path) -> None:
    # Guard: if a previous session left api-backup, require explicit flag
    api_backup_dir = get_api_backup_dir(tmp_dir)
    if api_backup_dir.exists():
        die(
            'A session is in progress.\n'
            '  --continue  Re-run buf lint; clean up on success.\n'
            '  --abort     Restore the previous state.'
        )

    # Check required helper scripts are present before touching anything
    require_script(REMOVE_GO_PKG_SCRIPT)
    require_script(ADD_GO_PKG_SCRIPT)

    print(f'Updating proto/api from repository {repo_url}...')
    step_backup(tmp_dir)
    step_clone(repo_url, branch, tmp_dir)
    step_copy(proto_folder, proto_packages, tmp_dir)

    step_remove_go_package()
    step_add_go_packages_and_fix_imports(proto_packages, go_package_api_root)
    step_fix_root_api_protos(proto_packages, go_package_api_root)

    ok, lint_err = step_lint(API_DIR)
    if ok:
        if not keep_state:
            step_cleanup(tmp_dir)
        print('Done: proto/api updated successfully.')
        if keep_state:
            print('Note: Terminate the session with --continue or --abort when you are done inspecting the changes.')
        return

    # Lint failed — ask what to do
    print('\nbuf lint failed with error:')
    print(lint_err)
    restore = ask_yes_no('\n\nRestore previous state?')
    if restore:
        step_restore(tmp_dir)
        print('\nPrevious state restored.')
    else:
        fetched_repo_dir = get_fetched_repo_dir(tmp_dir)
        # Keep proto/api and proto/api-backup as-is, remove fetched-repo only
        if fetched_repo_dir.exists():
            shutil.rmtree(fetched_repo_dir)
            logger.debug(f'  Removed {fetched_repo_dir}')
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
    
    parser.add_argument('--go-module', metavar='GO_MODULE', default=DEFAULT_GO_MODULE,
                        help='Go module name for the updated proto files.')
    
    parser.add_argument('--proto-packages', metavar='PKG1,PKG2,...', default=','.join(DEFAULT_PROTO_PACKAGES_API),
                        help='Comma-separated list of proto packages to update.')

    parser.add_argument('--keep-state', default=False, action='store_true',
                        help='Interrupt the session, even after a successful update, without cleaning up temporary state. Use this if you want to inspect the changes. The session must be terminated with --continue or --abort.')

    parser.add_argument('--tmp-dir', metavar='TMP_DIR', default=str(PROTO_DIR),
                        help='Directory to use for temporary keeping old state (default: proto/).')
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.debug)

    proto_packages = [pkg.strip() for pkg in args.proto_packages.split(',') if pkg.strip()]
    tmp_dir_path = Path(args.tmp_dir)
    if args.resume:
        run_continue(proto_packages, tmp_dir_path)
        return

    if args.abort:
        run_abort(tmp_dir_path)
        return

    # Normal run — both positional arguments are required
    if not args.repo_url:
        parser.print_help()
        die('\nrepo_url is required for a normal run.')
    if not args.proto_folder:
        parser.print_help()
        die('\nproto_folder is required for a normal run.')

    go_package_api_root = go_pkg_api_root(args.go_module)
    
    run_main(args.repo_url, args.proto_folder, args.branch, args.go_module, proto_packages, go_package_api_root, args.keep_state, tmp_dir_path)


if __name__ == '__main__':
    main()
