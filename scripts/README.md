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

## 2. Updating the API Proto defintions

The script `update_api_proto.sh` can be used to pull the latest `proto` of the API repository into this repository, and re-generated the Go code for those protos. If the layout is changed, it may be necessary to remove the `gen` folder before running the script, to avoid old and new proto definitions to co-exist. 