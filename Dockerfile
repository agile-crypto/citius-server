# Multi-stage build for the Citius (caas) gRPC server.
#
# Build context is the citius-server repository root so the Go workspace
# (go.work with the vault-storage module) and the proto catalog are available.
#
# The server links against OpenSSL through the ossl-go cgo binding for its
# cryptographic provider, which requires OpenSSL >= 3.2 (for the threads API in
# <openssl/thread.h>). Debian trixie ships OpenSSL 3.5, so both the build and
# runtime images are trixie-based with cgo enabled.

FROM golang:1.26-trixie AS build
WORKDIR /src

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Copy the workspace manifests first for layer caching.
COPY go.work go.work.sum ./
COPY go.mod go.sum ./
COPY vault-storage/go.mod vault-storage/go.sum ./vault-storage/
RUN go mod download all || true

# Copy the full source and build the server binary with cgo + OpenSSL.
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /out/caas-server ./internal/cmd/server/main

FROM debian:trixie-slim
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/caas-server /app/caas-server
COPY --from=build /src/proto/standard_algorithms.json /app/proto/standard_algorithms.json
EXPOSE 50051
ENTRYPOINT ["/app/caas-server"]
CMD ["-addr", ":50051", "-catalog", "/app/proto/standard_algorithms.json"]
