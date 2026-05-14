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
.PHONY: fmt proto generate clean ci test-pkg run run-dev hooks _hooks-check
.PHONY: zitadel-up zitadel-up-dev zitadel-down zitadel-reset zitadel-reset-dev zitadel-nuke zitadel-env test-integration-auth

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
	@printf "  \033[33m%-14s\033[0m %s (e.g. PKG=internal/core)\n" "PKG" "package for test-pkg"
	@printf "\n\033[1mExamples:\033[0m\n"
	@printf "  make run ADDR=:9000\n"
	@printf "  make test-pkg PKG=internal/policy\n"
	@printf "  make ci\n\n"

# ---------------------------------------------------------------------------
# Server runtime defaults (override on the command line, e.g. `make run ADDR=:9000`)
# ---------------------------------------------------------------------------
ADDR    ?= :50051
CATALOG ?= proto/standard_algorithms.json
BIN_DIR ?= bin
SERVER_BIN := $(BIN_DIR)/caas-server
SERVER_PKG := ./internal/cmd/server/main

MODULE := github.ibm.com/citius/citius-server

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

# Fast-iteration variant: skips the binary, runs straight from source.
run-dev: ## Run the gRPC server via 'go run' (no build artefact)
	@echo "Starting CaaS gRPC server (go run) on $(ADDR)"
	go run $(SERVER_PKG) -addr $(ADDR) -catalog $(CATALOG)

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

lint-go: ## Run golangci-lint on internal/...
	golangci-lint run ./internal/...

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

test-integration-auth: ## Run the Zitadel-tagged auth integration suite (requires zitadel-up)
	go test -tags 'integration zitadel' -count=1 ./test/integration/auth/...
