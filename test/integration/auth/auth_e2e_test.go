//go:build integration && zitadel

// Package auth_test exercises the full Zitadel-backed authentication and
// authorization pipeline against a live stack started by
// bootstrap/zitadel/bootstrap.sh up.
//
// Run with:
//
//	make zitadel-up
//	make test-integration-auth
//	make zitadel-down
//
// Required environment (sourced from citius-zitadel.env):
//
//	ZITADEL_ISSUER, INTROSPECT_ID, INTROSPECT_SECRET
//	CITIUS_ADDR                  - "host:port" the test client should dial
//	CITIUS_TLS_CA                - path to PEM CA bundle
//	SVC_ADMIN_TOKEN_ENDPOINT     - JWT-grant token URL for the svc-admin user
//	SVC_TESTER_TOKEN_ENDPOINT    - same for svc-tester
//	SVC_READONLY_TOKEN_ENDPOINT  - same for svc-readonly
//	SVC_NOPERM_TOKEN_ENDPOINT    - same for svc-noperm
//
// The build tags ensure plain `go test ./...` never picks these up: the
// suite is opt-in and runs only when both the integration tag and the
// zitadel stack tag are supplied.
package auth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	messagespb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	servicespb "github.com/agile-crypto/citius-server/gen/go/api/services"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// requireEnv aborts the test when env is empty, signalling that the
// caller forgot to source citius-zitadel.env (rather than running an
// untrustworthy test against partial config).
func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("integration env %s not set; run `make zitadel-up` and `source bootstrap/zitadel/citius-zitadel.env`", key)
	}
	return v
}

// dial opens a TLS gRPC connection to the configured CITIUS_ADDR using
// the CA bundle exported by bootstrap.sh. ServerName is taken from
// CITIUS_TLS_SERVER_NAME when set, otherwise from the host portion of
// CITIUS_ADDR — operators who terminate TLS on a name that does not
// match the dial host (e.g. an in-cluster service hostname) must export
// CITIUS_TLS_SERVER_NAME explicitly.
func dial(t *testing.T) *grpc.ClientConn {
	t.Helper()
	addr := requireEnv(t, "CITIUS_ADDR")
	caPath := requireEnv(t, "CITIUS_TLS_CA")

	caPem, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read ca bundle %s: %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPem) {
		t.Fatalf("parse ca bundle %s: no certs", caPath)
	}

	serverName := os.Getenv("CITIUS_TLS_SERVER_NAME")
	if serverName == "" {
		// Strip the port from CITIUS_ADDR. host:port → host.
		// IPv6 literals are wrapped in brackets and fall through to
		// SplitHostPort cleanly.
		if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil && h != "" {
			serverName = h
		} else {
			serverName = addr
		}
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// withToken returns a context carrying the supplied bearer token in the
// "authorization" gRPC metadata header.
func withToken(parent context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(parent, "authorization", "Bearer "+token)
}

// fetchToken acquires a fresh access token from the supplied endpoint.
// The endpoint env vars are written by bootstrap.sh as fully-formed
// "exec curl ..." commands, but for the harness we simply read a static
// token file written next to it. That file is rotated on every
// `bootstrap.sh up`, so it is acceptable for short-running tests.
func fetchToken(t *testing.T, endpointEnv string) string {
	t.Helper()
	path := requireEnv(t, endpointEnv)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read token file %s: %v", path, err)
	}
	return string(b)
}

// TestUnauthenticated_NoTokenIsRejected is the most basic invariant:
// without any bearer token, every protected RPC must return
// Unauthenticated.
func TestUnauthenticated_NoTokenIsRejected(t *testing.T) {
	conn := dial(t)
	cli := servicespb.NewKeyManagementServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := cli.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "any/key"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ReadKey without token: got code=%v err=%v; want Unauthenticated", status.Code(err), err)
	}
}

// TestNoPermissionIsForbidden verifies that a valid token with empty
// permissions is rejected with PermissionDenied (not Unauthenticated).
func TestNoPermissionIsForbidden(t *testing.T) {
	conn := dial(t)
	cli := servicespb.NewKeyManagementServiceClient(conn)
	tok := fetchToken(t, "SVC_NOPERM_TOKEN_FILE")

	ctx, cancel := context.WithTimeout(withToken(context.Background(), tok), 5*time.Second)
	defer cancel()

	_, err := cli.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "any/key"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ReadKey as no-perm user: got code=%v err=%v; want PermissionDenied", status.Code(err), err)
	}
}

// TestReadOnlyCannotCreate verifies the per-method permission gate:
// a token holding only the keys:read permission must be denied
// CreateKey even if its key-name allow-list would permit the resource.
func TestReadOnlyCannotCreate(t *testing.T) {
	conn := dial(t)
	cli := servicespb.NewKeyManagementServiceClient(conn)
	tok := fetchToken(t, "SVC_READONLY_TOKEN_FILE")

	ctx, cancel := context.WithTimeout(withToken(context.Background(), tok), 5*time.Second)
	defer cancel()

	_, err := cli.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   "tenants/tester/k1",
		Policy: "default",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateKey as readonly: got code=%v err=%v; want PermissionDenied", status.Code(err), err)
	}
}

// TestTesterCannotEscapeNamespace verifies the per-resource glob check:
// svc-tester is allow-listed for tenants/tester/* and must be denied an
// out-of-namespace key name even though the per-method permission is
// granted.
func TestTesterCannotEscapeNamespace(t *testing.T) {
	conn := dial(t)
	cli := servicespb.NewKeyManagementServiceClient(conn)
	tok := fetchToken(t, "SVC_TESTER_TOKEN_FILE")

	ctx, cancel := context.WithTimeout(withToken(context.Background(), tok), 5*time.Second)
	defer cancel()

	_, err := cli.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "tenants/other/k1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ReadKey out-of-namespace as tester: got code=%v err=%v; want PermissionDenied", status.Code(err), err)
	}
}

// TestAdminCanCreateAndRead is the happy-path smoke covering both
// authorization layers in the success direction.
func TestAdminCanCreateAndRead(t *testing.T) {
	conn := dial(t)
	kmCli := servicespb.NewKeyManagementServiceClient(conn)
	polCli := servicespb.NewCryptoPolicyServiceClient(conn)
	tok := fetchToken(t, "SVC_ADMIN_TOKEN_FILE")

	ctx, cancel := context.WithTimeout(withToken(context.Background(), tok), 10*time.Second)
	defer cancel()

	keyName := "tenants/admin/integ-" + time.Now().UTC().Format("20060102T150405")

	policyDoc := `{
		"version": "1",
		"allowed_templates": ["ecdsa-p256-sha256-der"],
		"allowed_operations": {
			"key_operations": ["create_key", "read_key", "sign", "verify"]
		}
	}`
	if _, err := polCli.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name:           "default",
		PolicyDocument: policyDoc,
	}); err != nil && status.Code(err) != codes.AlreadyExists {
		t.Fatalf("CreateCryptoPolicy as admin: %v", err)
	}

	createResp, err := kmCli.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   keyName,
		Policy: "default",
		KeySpecification: &messagespb.CreateKeyRequest_TemplateId{
			TemplateId: "ecdsa-p256-sha256-der",
		},
	})
	if err != nil {
		t.Fatalf("CreateKey as admin: %v", err)
	}
	// The server stores keys under a generated PublicId (returned in
	// KeyMetadata.Name); subsequent reads must use that identifier, not
	// the user-supplied display name.
	storedName := createResp.GetKeyMetadata().GetName()
	if _, err := kmCli.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: storedName}); err != nil {
		t.Fatalf("ReadKey as admin: %v", err)
	}
}
