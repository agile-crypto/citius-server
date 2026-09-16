//go:build integration && zitadel

package auth_test

import (
	"context"
	"os"
	"testing"
	"time"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authorizationProbe struct {
	name    string
	allowed bool
	call    func(context.Context) error
}

// TestHumanPersonaAuthorizationMatrix consumes access tokens obtained through
// the hosted PKCE helper. Domain-level NotFound or InvalidArgument responses
// count as authorized: the purpose of each probe is to prove that the request
// crossed both the authentication and authorization interceptors.
func TestHumanPersonaAuthorizationMatrix(t *testing.T) {
	conn := dial(t)
	keys := servicespb.NewKeyManagementServiceClient(conn)
	policies := servicespb.NewCryptoPolicyServiceClient(conn)
	crypto := servicespb.NewCryptoServiceClient(conn)
	discovery := servicespb.NewAlgorithmDiscoveryServiceClient(conn)
	providers := servicespb.NewProviderServiceClient(conn)

	readKey := func(name string) func(context.Context) error {
		return func(ctx context.Context) error {
			_, err := keys.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: name})
			return err
		}
	}
	createKey := func(ctx context.Context) error {
		_, err := keys.CreateKey(ctx, &messagespb.CreateKeyRequest{Name: "demo-auth-probe", Policy: "demo-auth-policy"})
		return err
	}
	rotateKey := func(ctx context.Context) error {
		_, err := keys.RotateKey(ctx, &messagespb.RotateKeyRequest{Name: "demo-auth-probe", Reason: "authorization probe"})
		return err
	}
	updateKeyPolicy := func(ctx context.Context) error {
		_, err := keys.UpdateKeyPolicy(ctx, &messagespb.UpdateKeyPolicyRequest{Name: "demo-auth-probe", NewPolicy: "demo-auth-policy"})
		return err
	}
	readPolicy := func(ctx context.Context) error {
		_, err := policies.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: "demo-auth-policy"})
		return err
	}
	writePolicy := func(ctx context.Context) error {
		_, err := policies.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{Name: "demo-auth-policy", PolicyDocument: "{}"})
		return err
	}
	sign := func(ctx context.Context) error {
		_, err := crypto.Sign(ctx, &messagespb.SignRequest{KeyName: "demo-auth-probe", Input: []byte("probe")})
		return err
	}
	verify := func(ctx context.Context) error {
		_, err := crypto.Verify(ctx, &messagespb.VerifyRequest{KeyName: "demo-auth-probe", Input: []byte("probe"), Signature: []byte("probe")})
		return err
	}
	encrypt := func(ctx context.Context) error {
		_, err := crypto.Encrypt(ctx, &messagespb.EncryptRequest{KeyName: "demo-auth-probe", Plaintext: []byte("probe")})
		return err
	}
	decrypt := func(ctx context.Context) error {
		_, err := crypto.Decrypt(ctx, &messagespb.DecryptRequest{KeyName: "demo-auth-probe", Ciphertext: []byte("probe")})
		return err
	}
	listTemplates := func(ctx context.Context) error {
		_, err := discovery.ListTemplates(ctx, &servicespb.ListTemplatesRequest{})
		return err
	}
	listProviders := func(ctx context.Context) error {
		_, err := providers.ListProviders(ctx, &servicespb.ListProvidersRequest{})
		return err
	}

	personas := []struct {
		name     string
		tokenEnv string
		probes   []authorizationProbe
	}{
		{
			name: "citius-ciso", tokenEnv: "CITIUS_CISO_TOKEN_FILE",
			probes: []authorizationProbe{
				{name: "create key", allowed: true, call: createKey},
				{name: "read key", allowed: true, call: readKey("demo-auth-probe")},
				{name: "rotate key", allowed: true, call: rotateKey},
				{name: "update key policy", allowed: true, call: updateKeyPolicy},
				{name: "read policy", allowed: true, call: readPolicy},
				{name: "write policy", allowed: true, call: writePolicy},
				{name: "list templates", allowed: true, call: listTemplates},
				{name: "list providers", allowed: true, call: listProviders},
				{name: "sign", allowed: false, call: sign},
				{name: "verify", allowed: false, call: verify},
				{name: "encrypt", allowed: false, call: encrypt},
				{name: "decrypt", allowed: false, call: decrypt},
				{name: "restricted demo key", allowed: true, call: readKey("demo-restricted-auth-probe")},
			},
		},
		{
			name: "citius-producer", tokenEnv: "CITIUS_PRODUCER_TOKEN_FILE",
			probes: []authorizationProbe{
				{name: "create key", allowed: true, call: createKey},
				{name: "read key", allowed: true, call: readKey("demo-auth-probe")},
				{name: "read policy", allowed: true, call: readPolicy},
				{name: "list templates", allowed: true, call: listTemplates},
				{name: "list providers", allowed: true, call: listProviders},
				{name: "sign", allowed: true, call: sign},
				{name: "encrypt", allowed: true, call: encrypt},
				{name: "rotate key", allowed: false, call: rotateKey},
				{name: "update key policy", allowed: false, call: updateKeyPolicy},
				{name: "write policy", allowed: false, call: writePolicy},
				{name: "verify", allowed: false, call: verify},
				{name: "decrypt", allowed: false, call: decrypt},
				{name: "restricted demo key", allowed: false, call: readKey("demo-restricted-auth-probe")},
			},
		},
		{
			name: "citius-consumer", tokenEnv: "CITIUS_CONSUMER_TOKEN_FILE",
			probes: []authorizationProbe{
				{name: "read key", allowed: true, call: readKey("demo-auth-probe")},
				{name: "read policy", allowed: true, call: readPolicy},
				{name: "list templates", allowed: true, call: listTemplates},
				{name: "verify", allowed: true, call: verify},
				{name: "decrypt", allowed: true, call: decrypt},
				{name: "create key", allowed: false, call: createKey},
				{name: "write policy", allowed: false, call: writePolicy},
				{name: "sign", allowed: false, call: sign},
				{name: "encrypt", allowed: false, call: encrypt},
				{name: "restricted demo key", allowed: false, call: readKey("demo-restricted-auth-probe")},
			},
		},
	}

	for _, persona := range personas {
		persona := persona
		t.Run(persona.name, func(t *testing.T) {
			token := fetchInteractiveToken(t, persona.tokenEnv)
			for _, probe := range persona.probes {
				probe := probe
				t.Run(probe.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(withToken(context.Background(), token), 5*time.Second)
					defer cancel()
					err := probe.call(ctx)
					code := status.Code(err)
					if probe.allowed && (code == codes.Unauthenticated || code == codes.PermissionDenied) {
						t.Fatalf("authorized probe returned %v: %v", code, err)
					}
					if !probe.allowed && code != codes.PermissionDenied {
						t.Fatalf("denied probe returned %v: %v; want PermissionDenied", code, err)
					}
				})
			}
		})
	}
}

func fetchInteractiveToken(t *testing.T, envKey string) string {
	t.Helper()
	path := os.Getenv(envKey)
	if path == "" {
		t.Skipf("%s is not set; run the hosted login commands documented in test/integration/auth/README.md", envKey)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read interactive token file %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("interactive token file %s is empty", path)
	}
	return string(data)
}
