# Citius server associated scripts

## 1. Starting the server

The script `run_server.sh` can be used to start the Citius server with both TLS and auth enabled. It requires the following environment variables to be set:

| Environment variable | Description | Default value |
| -------------------- | ----------- | ------------- |
| ZITADEL_DIR | Directory for Zitadel related setup  | bootstrap/zitadel |
ZITADEL_ENV_FILE| File containing the Zitadel environment variables for authentication and authorization | bootstrap/zitadel/citius-zitadel.env |
ZITADEL_TLS_CERT | File containg the server's TLS certificate | bootstrap/zitadel/certs/local.crt |
ZITADEL_TLS_KEY | File containing the server's private key for TLS certificate | bootstrap/zitadel/certs/local.key |
ADDR | Address of the Citius server | 127.0.0.1:50051 |
CATALOG | Path to the catalog of algorithms | proto/standard_algorithms.json |

The script is meant to be used together with the **reference-implementation example**, available in the Go SDK.

## 2. Enabling the FIPS provider instance

The server registers an `openssl-fips` provider instance only when it is given an OpenSSL config that activates the FIPS provider (`--fips-config`, which defaults to `$OPENSSL_FIPS_CONFIG`). `fips_setup.sh` writes that config in a directory you own, without touching `/etc`, and checks that `fips=yes` really restricts algorithms:

```bash
scripts/fips_setup.sh                      # writes ~/.config/citius/fips/fips_activate.cnf
export OPENSSL_FIPS_CONFIG=~/.config/citius/fips/fips_activate.cnf
scripts/run_server.sh                      # or: citius-server --fips-config "$OPENSSL_FIPS_CONFIG" ...
```

On upstream OpenSSL the script runs `openssl fipsinstall` and includes the resulting `fipsmodule.cnf`. On RHEL and Fedora, where `fipsinstall` is disabled and the vendor `fips.so` checks itself, it activates the module directly. The FIPS smoke tests read the same variable, and skip when it is unset and no system `fipsmodule.cnf` exists.

## 3. Updating the API Proto defintions

The script `update_api_proto.sh` can be used to pull the latest `proto` of the API repository into this repository, and re-generated the Go code for those protos. If the layout is changed, it may be necessary to remove the `gen` folder before running the script, to avoid old and new proto definitions to co-exist. 