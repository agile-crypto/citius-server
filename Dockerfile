# Multi-stage build for the Citius (caas) gRPC server.
#
# Build context is the citius-server repository root so the Go workspace
# (go.work with the vault-storage module) and the proto catalog are available.
# The runtime image is distroless; the server listens on gRPC and requires TLS
# and Zitadel introspection configuration supplied through the environment.

FROM golang:1.26 AS build
WORKDIR /src

# Copy the workspace manifests first for layer caching.
COPY go.work go.work.sum ./
COPY go.mod go.sum ./
COPY vault-storage/go.mod vault-storage/go.sum ./vault-storage/
RUN go mod download all || true

# Copy the full source and build the server binary.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/caas-server ./internal/cmd/server/main

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/caas-server /app/caas-server
COPY --from=build /src/proto/standard_algorithms.json /app/proto/standard_algorithms.json
EXPOSE 50051
ENTRYPOINT ["/app/caas-server"]
CMD ["-addr", ":50051", "-catalog", "/app/proto/standard_algorithms.json"]
