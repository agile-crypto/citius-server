# Development image for docker-compose.yml: Go toolchain on Debian trixie
# (OpenSSL 3.5, required by the ossl-go cgo binding) plus grpcurl and jq for
# the healthcheck and policy seeding. Sources are bind-mounted at runtime, not
# copied, so this image only changes when the toolchain does.
FROM docker.io/library/golang:1.26-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev pkg-config jq \
 && rm -rf /var/lib/apt/lists/*

RUN go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
