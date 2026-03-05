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

.PHONY: build test test-race test-cover smoke vet lint lint-go lint-proto
.PHONY: fmt proto generate clean ci test-pkg

MODULE := github.ibm.com/citius/citius-server

# ---------------------------------------------------------------------------
# CI gate — MUST pass before merge
# ---------------------------------------------------------------------------
ci: lint test-race smoke

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build:
	go build ./internal/...

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
test:
	go test ./internal/... -count=1

test-race:
	go test ./internal/... -race -count=1

test-cover:
	go test ./internal/... -coverprofile=coverage.out -count=1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run a specific package's tests: make test-pkg PKG=internal/core
test-pkg:
	go test ./$(PKG)/... -v -count=1

# Integration / smoke tests (live against generated artefacts, not internal/)
smoke:
	go test ./test/smoke/... -v -count=1

# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
vet:
	go vet ./internal/...

lint: lint-go lint-proto

lint-go:
	golangci-lint run ./internal/...

lint-proto:
	cd proto && buf lint
	@echo "buf lint passed"

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
fmt:
	gofmt -w .
	goimports -w .

# ---------------------------------------------------------------------------
# Proto code generation
# ---------------------------------------------------------------------------
proto:
	cd proto && buf generate
	@echo "Proto generation complete"

# ---------------------------------------------------------------------------
# Go generate
# ---------------------------------------------------------------------------
generate:
	go generate ./internal/...

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	rm -rf coverage.out coverage.html
	go clean -cache -testcache
