module github.com/agile-crypto/citius-server

go 1.26.0

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2
	buf.build/go/protovalidate v1.4.0
	github.com/agile-crypto/citius-api-go v0.3.0
	github.com/agile-crypto/citius-core v0.4.2
	github.com/agile-crypto/citius-provider-go v0.1.0
	github.com/agile-crypto/ossl-go v0.1.0
	github.com/cloudflare/circl v1.6.4
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.31.0
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	cel.dev/cel-go v0.32.0 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/go-chi/chi/v5 v5.2.5 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/muhlemmer/httpforwarded v0.1.0 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/zitadel/logging v0.7.0 // indirect
	github.com/zitadel/oidc/v3 v3.47.5 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	github.com/zitadel/zitadel-go/v3 v3.29.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260921155816-b14227669459 // indirect
)

require (
	cel.dev/expr v0.25.3 // indirect
	github.com/agile-crypto/zitadel-grpc-auth v0.1.0
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/crypto v0.57.0
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260918162117-cecb64721679 // indirect
)

replace github.com/agile-crypto/citius-api-go => ../api

replace github.com/agile-crypto/citius-core => ../citius-core
