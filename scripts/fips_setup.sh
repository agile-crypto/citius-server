#!/usr/bin/env bash
# fips_setup.sh: write an OpenSSL config that activates the FIPS provider,
# in a directory you own, so the server can register its openssl-fips
# instance and the FIPS smoke tests can run. Nothing under /etc is touched.
#
#   scripts/fips_setup.sh [DIR]          # default DIR: ~/.config/citius/fips
#
# Then start the server with the printed config:
#
#   citius-server --fips-config DIR/fips_activate.cnf ...
#   # or: export OPENSSL_FIPS_CONFIG=DIR/fips_activate.cnf
#
# The smoke tests read the same OPENSSL_FIPS_CONFIG variable; without it
# they look for the system fipsmodule.cnf and skip when it is absent.
#
# Two kinds of OpenSSL are handled:
#   - Upstream OpenSSL 3: `openssl fipsinstall` writes DIR/fipsmodule.cnf
#     (the module's integrity MAC), and the activation config includes it.
#   - RHEL/Fedora builds: fipsinstall is disabled; the vendor fips.so checks
#     itself, so the activation config just activates the provider.
#
# Environment:
#   OPENSSL        openssl binary (default: openssl on PATH)
#   FIPS_MODULE    path to fips.so (default: <modulesdir>/fips.so)
set -euo pipefail
umask 077

dir="${1:-${XDG_CONFIG_HOME:-$HOME/.config}/citius/fips}"
openssl_bin="${OPENSSL:-openssl}"

command -v "$openssl_bin" >/dev/null || { echo "fips_setup: $openssl_bin not found" >&2; exit 1; }

modules_dir="$("$openssl_bin" info -modulesdir)"
module="${FIPS_MODULE:-$modules_dir/fips.so}"
[[ -f "$module" ]] || { echo "fips_setup: no FIPS module at $module (install the OpenSSL FIPS provider, or set FIPS_MODULE)" >&2; exit 1; }

# The paths are written into an OpenSSL config, which expands $VAR and
# ends a value at whitespace or a comment: refuse any path it would misread.
for path in "$dir" "$module"; do
	if [[ "$path" =~ [[:space:]\$#\"\'\\] ]]; then
		echo "fips_setup: path '$path' contains a character an OpenSSL config cannot hold (whitespace, \$, #, quote or backslash)" >&2
		exit 1
	fi
done

# Only a directory created here is made private: an existing one, which the
# caller may share, keeps its mode. The files are private either way.
if [[ ! -d "$dir" ]]; then
	mkdir -p "$dir"
	chmod 700 "$dir"
fi
activate="$dir/fips_activate.cnf"
module_cnf="$dir/fipsmodule.cnf"

# The provider list shared by both kinds: default for non-FIPS algorithms,
# fips for fips=yes fetches.
header="openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
fips = fips_sect

[default_sect]
activate = 1
"

if fipsinstall_out="$("$openssl_bin" fipsinstall -module "$module" -out "$module_cnf" 2>&1)"; then
	# fipsmodule.cnf defines [fips_sect] with activate = 1 and the MAC.
	printf '%s\n.include %s\n' "$header" "$module_cnf" >"$activate"
	kind="upstream (fipsinstall wrote $module_cnf)"
elif grep -qi "not enabled in the Red Hat" <<<"$fipsinstall_out"; then
	rm -f "$module_cnf"
	printf '%s\n[fips_sect]\nactivate = 1\nmodule = %s\n' "$header" "$module" >"$activate"
	kind="vendor (self-checking fips.so; fipsinstall is disabled in this build)"
else
	echo "fips_setup: openssl fipsinstall failed:" >&2
	echo "$fipsinstall_out" >&2
	exit 1
fi
chmod 600 "$activate"

# Check that the provider loads, and that fips=yes really restricts: SHA-256
# must be fetchable and MD5 must not.
probe="$(mktemp)"
trap 'rm -f "$probe"' EXIT
echo citius >"$probe"
# Capture the listing first: grep -q exiting early under pipefail would
# fail the pipeline with SIGPIPE even when the provider is listed.
providers="$(OPENSSL_CONF="$activate" "$openssl_bin" list -providers 2>/dev/null || true)"
if ! grep -q "^  fips" <<<"$providers"; then
	echo "fips_setup: the fips provider did not activate with $activate" >&2
	exit 1
fi
if ! OPENSSL_CONF="$activate" "$openssl_bin" dgst -sha256 -propquery fips=yes "$probe" >/dev/null 2>&1; then
	echo "fips_setup: SHA-256 is not available from the fips provider" >&2
	exit 1
fi
if OPENSSL_CONF="$activate" "$openssl_bin" dgst -md5 -propquery fips=yes "$probe" >/dev/null 2>&1; then
	echo "fips_setup: MD5 resolved under fips=yes; the fips provider is not restricting" >&2
	exit 1
fi

cat <<EOF
FIPS provider activated: $kind
Activation config: $activate

Start the server with:
  --fips-config $activate
or:
  export OPENSSL_FIPS_CONFIG=$activate

Run the FIPS smoke tests with the same variable set, e.g.:
  OPENSSL_FIPS_CONFIG=$activate go test ./test/smoke/crypto/ -run 'FIPS' -v
EOF
