# Server — Makefile
#
# Targets:
#   ci          — CI entry point: lint + test-race + smoke (merge gate)
#   build       — compile all internal packages
#   test        — run all tests (no race detector)
#   test-race   — run all tests with race detector
#   test-cover  — run tests with coverage report
#   smoke       — run smoke tests under test/smoke/...
#   vet         — go vet
#   lint        — lint-go + lint-proto
#   lint-go     — golangci-lint
#   lint-proto  — buf lint + buf breaking
#   fmt         — format Go source
#   proto       — generate Go code from proto definitions
#   generate    — go generate
#   clean       — remove build artifacts
#   test-pkg    — run a specific package's tests (PKG=internal/core)
#   run         — build and run the gRPC server (ADDR=:50051 CATALOG=path)
#   run-dev     — go run the gRPC server (no build artefact)
#   hooks       — install .githooks/ as the local git hooks directory (run once per clone)

.PHONY: help build test test-race test-cover smoke vet lint lint-go lint-proto
.PHONY: fmt proto generate clean ci test-pkg run run-dev run-dev-tls hooks _hooks-check
.PHONY: zitadel-up zitadel-up-dev zitadel-down zitadel-reset zitadel-reset-dev zitadel-nuke zitadel-env test-integration-auth-e2e test-integration-auth-e2e-macos-podman
.PHONY: proto-update-api

# Default goal: print help when `make` is run with no arguments.
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help — auto-generated from `## ` comments next to each target
# ---------------------------------------------------------------------------
help: ## Show this help (list all available targets)
	@printf "\n\033[1mUsage:\033[0m make <target> [VAR=value ...]\n\n"
	@printf "\033[1mTargets:\033[0m\n"
	@awk 'BEGIN {FS = ":.*##"} \
	     /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)
	@printf "\n\033[1mTunable variables (override on the command line):\033[0m\n"
	@printf "  \033[33m%-14s\033[0m %s (default: %s)\n" "ADDR"     "gRPC listen address"   "$(ADDR)"
	@printf "  \033[33m%-14s\033[0m %s (default: %s)\n" "CATALOG"  "algorithm catalog path" "$(CATALOG)"
	@printf "  \033[33m%-14s\033[0m %s (default: %s)\n" "BIN_DIR"  "build output directory" "$(BIN_DIR)"
	@printf "  \033[33m%-14s\033[0m %s (default: %s)\n" "OPENSSL_PREFIX" "OpenSSL 3.5+ install used for cgo" "$(OPENSSL_PREFIX)"
	@printf "  \033[33m%-14s\033[0m %s (e.g. PKG=internal/core)\n" "PKG" "package for test-pkg"
	@printf "\n\033[1mExamples:\033[0m\n"
	@printf "  make run ADDR=:9000\n"
	@printf "  make test-pkg PKG=internal/policy\n"
	@printf "  make ci\n\n"

# ---------------------------------------------------------------------------
# Server runtime defaults (override on the command line, e.g. `make run ADDR=:9000`)
# ---------------------------------------------------------------------------
ADDR    ?= 127.0.0.1:50051
CATALOG ?= proto/standard_algorithms.json
BIN_DIR ?= bin
SERVER_BIN := $(BIN_DIR)/caas-server
SERVER_PKG := ./internal/cmd/server/main

MODULE := github.com/agile-crypto/citius-server

# ---------------------------------------------------------------------------
# OpenSSL 3.5+ toolchain (required by github.com/agile-crypto/ossl-go, a cgo
# dependency of internal/provider/openssl).
#
# A typical system OpenSSL (3.0.x / 1.1.1 are both common) predates what
# ossl-go's cgo preamble requires and fails to compile against it. Every
# recipe below is built and linked against OPENSSL_PREFIX instead; override
# it for a different install location, e.g. `make test OPENSSL_PREFIX=/usr`.
# ---------------------------------------------------------------------------
OPENSSL_PREFIX ?= /opt/openssl3.5.2
export PKG_CONFIG_PATH := $(OPENSSL_PREFIX)/lib64/pkgconfig:$(PKG_CONFIG_PATH)
export CGO_LDFLAGS := -Wl,-rpath,$(OPENSSL_PREFIX)/lib64 $(CGO_LDFLAGS)

# ---------------------------------------------------------------------------
# CI gate — MUST pass before merge
# ---------------------------------------------------------------------------
ci: _hooks-check lint test-race smoke ## CI entry point: lint + test-race + smoke (merge gate)

# Warn (not fail) if the git hooks have not been installed in this clone.
_hooks-check:
	@if [ "$$(git config core.hooksPath 2>/dev/null)" != ".githooks" ]; then \
	    echo " Git hooks not installed. Run 'make hooks' to block bad pushes."; \
	fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build: ## Compile all internal packages
	go build ./internal/...

# ---------------------------------------------------------------------------
# Run the gRPC server
# ---------------------------------------------------------------------------
# Compile to ./bin/caas-server and execute it.
# Override defaults: make run ADDR=:9000 CATALOG=/etc/caas/catalog.json
run: $(SERVER_BIN) ## Build and run the gRPC server (override ADDR= / CATALOG=)
	@echo "Starting CaaS gRPC server on $(ADDR) (catalog=$(CATALOG))"
	$(SERVER_BIN) -addr $(ADDR) -catalog $(CATALOG)

$(SERVER_BIN):
	@mkdir -p $(BIN_DIR)
	go build -o $(SERVER_BIN) $(SERVER_PKG)

TLS_CERT_FOLDER := bootstrap/zitadel/certs
TLS_CERT_FILE := $(TLS_CERT_FOLDER)/local.crt
TLS_KEY_FILE  := $(TLS_CERT_FOLDER)/local.key

# Fast-iteration variant: skips the binary, runs straight from source.
run-dev: ## Run the gRPC server via 'go run' (no build artefact) with gRPC reflection and health service enabled
	@echo "Starting CaaS gRPC server (go run) on $(ADDR)"
	go run $(SERVER_PKG) -addr $(ADDR) -catalog $(CATALOG) -grpc-reflection -grpc-health

ROOT_CA=$$(mkcert -CAROOT)/rootCA.pem ## Needs to be quoted because it contains spaces on macOS.
run-dev-tls: ## Run the gRPC server via 'go run' (no build artefact) with TLS and gRPC reflection enabled. Requires TLS cert and key files to exist, and a root CA to be installed via mkcert.
	@set -e; \
	if [ ! -f $(TLS_CERT_FILE) ]; then \
		echo "ERROR: TLS cert file $(TLS_CERT_FILE) not found. Run 'make zitadel-up' first."; \
		exit 1; \
	fi; \
	if [ ! -f $(TLS_KEY_FILE) ]; then \
		echo "ERROR: TLS key file $(TLS_KEY_FILE) not found. Run 'make zitadel-up' first."; \
		exit 1; \
	fi;
	@echo "INFO: Starting CaaS gRPC server (go run) on $(ADDR) with TLS and gRPC reflection enabled"
	@echo "INFO: Use 'grpcurl -cacert "$(ROOT_CA)" localhost:50051 list' to list services"
	@echo "INFO: Use 'grpcurl -cacert "$(ROOT_CA)" 127.0.0.1:50051 grpc.health.v1.Health/Check' to check health"
	@echo "INFO: TLS Setting used: TLS_CERT_FILE=$(TLS_CERT_FILE) TLS_KEY_FILE=$(TLS_KEY_FILE)"
	go run $(SERVER_PKG) -addr $(ADDR) -catalog $(CATALOG) -tls-cert $(TLS_CERT_FILE) -tls-key $(TLS_KEY_FILE) -grpc-reflection -grpc-health


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
test: ## Run all unit tests (no race detector)
	go test ./internal/... -count=1

test-race: ## Run all unit tests with the race detector
	go test ./internal/... -race -count=1

test-cover: ## Run tests and generate HTML coverage report
	go test ./internal/... -coverprofile=coverage.out -count=1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-pkg: ## Run a specific package's tests (PKG=internal/core)
	go test ./$(PKG)/... -v -count=1

smoke: ## Run smoke tests under test/smoke/...
	go test ./test/smoke/... -v -count=1

# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
vet: ## Run 'go vet' on all internal packages
	go vet ./internal/...

lint: lint-go lint-proto ## Run all linters (Go + proto)

lint-go: ## Run golangci-lint on the whole module (gen/ excluded via .golangci.yml)
	golangci-lint run ./...

lint-proto: ## Run 'buf lint' on the proto tree
	cd proto && buf lint
	@echo "buf lint passed"

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
fmt: ## Format Go source (gofmt + goimports)
	gofmt -w .
	goimports -w .

# ---------------------------------------------------------------------------
# Proto code generation
# ---------------------------------------------------------------------------
proto: ## Generate Go code from proto definitions (buf generate)
	cd proto && buf generate
	@echo "Proto generation complete"

# ---------------------------------------------------------------------------
# Proto code generation
# ---------------------------------------------------------------------------

API_REPO_URL := git@github.ibm.com:citius/api.git
PROTO_PACKAGES := messages,services,types
PROTO_FOLDER := proto
TMP_DIR_PROTO := tmp_proto

proto-update-api: ## Update the API proto definitions to match the latest version of the API specification (as defined by the main branch of the API repo)
	@bash scripts/update_api_proto.sh "$(API_REPO_URL)" "$(MODULE)" "$(PROTO_PACKAGES)" "$(PROTO_FOLDER)" "$(TMP_DIR_PROTO)"

# ---------------------------------------------------------------------------
# Go generate
# ---------------------------------------------------------------------------
generate: ## Run 'go generate' across internal/...
	go generate ./internal/...

# ---------------------------------------------------------------------------
# Git hooks — run once after cloning
# ---------------------------------------------------------------------------
hooks: ## Install .githooks/ as the local git hooks directory (run once per clone)
	git config core.hooksPath .githooks
	@echo "Git hooks installed from .githooks/"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean: ## Remove build artefacts, coverage reports, and Go caches
	rm -rf coverage.out coverage.html $(BIN_DIR)
	go clean -cache -testcache

# ---------------------------------------------------------------------------
# Zitadel local stack (bootstrap/zitadel)
# ---------------------------------------------------------------------------
ZITADEL_DIR := bootstrap/zitadel

zitadel-up: ## Boot the local Zitadel stack and seed the citius project
	$(ZITADEL_DIR)/bootstrap.sh up

zitadel-up-dev: ## Like zitadel-up but also provisions a human console-UI admin account
	CITIUS_DEV_CONSOLE=1 $(ZITADEL_DIR)/bootstrap.sh up

zitadel-down: ## Stop the local Zitadel stack (preserve data volumes)
	$(ZITADEL_DIR)/bootstrap.sh down

zitadel-reset: ## Stop the stack and wipe data volumes
	$(ZITADEL_DIR)/bootstrap.sh reset

zitadel-reset-dev: ## Like zitadel-reset but also provisions a human console-UI admin account
	CITIUS_DEV_CONSOLE=1 $(ZITADEL_DIR)/bootstrap.sh reset

zitadel-nuke: ## Wipe everything including .env (next up regenerates all secrets)
	$(ZITADEL_DIR)/bootstrap.sh nuke

zitadel-env: ## Print sourced env entries written by bootstrap.sh
	$(ZITADEL_DIR)/bootstrap.sh env

ZITADEL_ENV_FILE := $(ZITADEL_DIR)/citius-zitadel.env
ZITADEL_TLS_CERT := $(ZITADEL_DIR)/certs/local.crt
ZITADEL_TLS_KEY  := $(ZITADEL_DIR)/certs/local.key

test-integration-auth-e2e: ## One-shot: build, start caas-server, run auth integration suite, tear server down
	@test -f $(ZITADEL_ENV_FILE) || (echo "ERROR: $(ZITADEL_ENV_FILE) not found - run make zitadel-up first" && exit 1)
	@test -f $(ZITADEL_TLS_CERT) || (echo "ERROR: $(ZITADEL_TLS_CERT) not found - run make zitadel-up first" && exit 1)
	@go build -o $(SERVER_BIN) $(SERVER_PKG)
	@bash -c '\
	  set -e; \
	  log=$$(mktemp -t caas-server.XXXXXX.log); \
	  env $$(grep -v "^#" $(ZITADEL_ENV_FILE) | sed "s/^export //") \
	    TLS_CERT_FILE=$(abspath $(ZITADEL_TLS_CERT)) TLS_KEY_FILE=$(abspath $(ZITADEL_TLS_KEY)) \
	    $(SERVER_BIN) -addr $(ADDR) -catalog $(CATALOG) >"$$log" 2>&1 & \
	  pid=$$!; \
	  trap "kill $$pid 2>/dev/null; wait $$pid 2>/dev/null; rm -f \"$$log\"" EXIT INT TERM; \
	  port=$$(printf "%s" "$(ADDR)" | sed "s/.*://"); \
	  echo "waiting for caas-server (pid=$$pid) on :$$port ..."; \
	  for i in $$(seq 1 50); do \
	    if ! kill -0 $$pid 2>/dev/null; then echo "caas-server died early; log:"; cat "$$log"; exit 1; fi; \
	    if (exec 3<>/dev/tcp/127.0.0.1/$$port) 2>/dev/null; then exec 3<&-; exec 3>&-; break; fi; \
	    sleep 0.1; \
	  done; \
	  if ! (exec 3<>/dev/tcp/127.0.0.1/$$port) 2>/dev/null; then echo "caas-server never listened; log:"; cat "$$log"; exit 1; fi; \
	  exec 3<&-; exec 3>&-; \
	  echo "caas-server up; running tests"; \
	  env $$(grep -v "^#" $(ZITADEL_ENV_FILE) | sed "s/^export //") \
	    go test -tags "integration zitadel" -count=1 ./test/integration/auth/...; \
	  rc=$$?; \
	  echo "tests exited rc=$$rc; shutting caas-server down"; \
	  exit $$rc \
	'

test-integration-auth-e2e-macos-podman: ## One-shot (macOS/Podman): start caas-server via scripts/run_server.sh, run auth integration suite, tear server down
	@test -f $(ZITADEL_ENV_FILE) || (echo "ERROR: $(ZITADEL_ENV_FILE) not found - run 'ENGINE=PODMAN make zitadel-up' first" && exit 1)
	@bash -c '\
	  set -e; \
	  bash ./scripts/run_server.sh & \
	  pid=$$!; \
	  trap "kill $$pid 2>/dev/null; wait $$pid 2>/dev/null" EXIT INT TERM; \
	  port=$$(printf "%s" "$(ADDR)" | sed "s/.*://"); \
	  echo "waiting for caas-server (run_server.sh pid=$$pid) on :$$port ..."; \
	  for i in $$(seq 1 100); do \
	    if ! kill -0 $$pid 2>/dev/null; then echo "run_server.sh exited early"; exit 1; fi; \
	    if (exec 3<>/dev/tcp/127.0.0.1/$$port) 2>/dev/null; then exec 3<&-; exec 3>&-; break; fi; \
	    sleep 0.1; \
	  done; \
	  if ! (exec 3<>/dev/tcp/127.0.0.1/$$port) 2>/dev/null; then echo "caas-server never listened on :$$port"; exit 1; fi; \
	  exec 3<&-; exec 3>&-; \
	  echo "caas-server up; running tests"; \
	  set +e; \
	  go test -tags "integration zitadel" -count=1 ./test/integration/auth/...; \
	  rc=$$?; \
	  echo "tests exited rc=$$rc; shutting caas-server down"; \
	  exit $$rc \
	'
