package service

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/core"
	"github.com/agile-crypto/citius-server/internal/crypto"
	"github.com/agile-crypto/citius-server/internal/key"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/agile-crypto/citius-server/internal/template"
	"github.com/hashicorp/vault/sdk/logical"
)

// capturingSigner wraps the real software provider, recording the last
// SignRequest/DigestSignRequest it receives — including fields (like
// KeyOutput) the provider doesn't act on yet — so tests can verify exactly
// what the orchestrator sends without depending on provider behavior that
// hasn't been wired up.
type capturingSigner struct {
	*software.Provider
	lastSignRequest       *providerpb.SignRequest
	lastDigestSignRequest *providerpb.DigestSignRequest
}

func (c *capturingSigner) Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	c.lastSignRequest = req
	return c.Provider.Sign(ctx, req)
}

func (c *capturingSigner) DigestSign(ctx context.Context, req *providerpb.DigestSignRequest) (*providerpb.DigestSignResponse, error) {
	c.lastDigestSignRequest = req
	return c.Provider.DigestSign(ctx, req)
}

var (
	_ provider.Backend = (*capturingSigner)(nil)
	_ provider.Signer  = (*capturingSigner)(nil)
)

// setupWithCapturingSigner mirrors setupCryptoOrchestratorFull but registers
// a capturingSigner instead of a plain software.Provider, so the test can
// inspect the provider-level requests the orchestrator builds.
func setupWithCapturingSigner(t *testing.T) (CryptoOrchestrator, KeyOrchestrator, *capturingSigner) {
	t.Helper()
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, err := key.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("NewVaultRepository: %v", err)
	}
	reg, err := template.NewVaultRegistry(ctx, storage)
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}
	if err = template.LoadStandardCatalog(ctx, catalogPath(), reg); err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	sig := &capturingSigner{Provider: software.New()}
	provReg := provider.NewRegistry()
	if err = provReg.Register(ctx, sig); err != nil {
		t.Fatalf("Register provider: %v", err)
	}

	policyRepo, err := policy.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("policy.NewVaultRepository: %v", err)
	}
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationSign),
				string(core.OperationDigestSign),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	const policyName = "test-key-output-allow"
	p := policy.NewPolicy("pol_keyoutput", policyName, rulesJSON)
	if _, err = pol.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	keyOrch, err := NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	ops, err := NewCryptoOrchestrator(storage, repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("NewCryptoOrchestrator: %v", err)
	}

	if _, err = keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "key-output-test-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: defaultScopeSpec(t),
	}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	return ops, keyOrch, sig
}

func TestSign_threadsKeyOutputFromStoredGenerateKeyResponse(t *testing.T) {
	ops, _, sig := setupWithCapturingSigner(t)
	ctx := context.Background()

	_, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              "key-output-test-key",
		Payload:              []byte("payload"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if sig.lastSignRequest == nil {
		t.Fatal("provider never received a SignRequest")
	}
	keyOutput := sig.lastSignRequest.GetKeyOutput()
	if keyOutput.GetAlgorithmOutput() == nil {
		t.Fatal("SignRequest.key_output.algorithm_output is nil — GenerateKeyResponse.output was not threaded through")
	}
	// ECDSA: x509.MarshalECPrivateKey (SEC1, RFC 5915) — see provider.go.
	if got := keyOutput.GetEncoding(); got != "sec1" {
		t.Errorf("SignRequest.key_output.encoding = %q, want %q", got, "sec1")
	}
}

func TestDigestSign_threadsKeyOutputFromStoredGenerateKeyResponse(t *testing.T) {
	ops, _, sig := setupWithCapturingSigner(t)
	ctx := context.Background()

	_, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              "key-output-test-key",
		Digest:               make([]byte, 32),
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	if sig.lastDigestSignRequest == nil {
		t.Fatal("provider never received a DigestSignRequest")
	}
	keyOutput := sig.lastDigestSignRequest.GetKeyOutput()
	if keyOutput.GetAlgorithmOutput() == nil {
		t.Fatal("DigestSignRequest.key_output.algorithm_output is nil — GenerateKeyResponse.output was not threaded through")
	}
	if got := keyOutput.GetEncoding(); got != "sec1" {
		t.Errorf("DigestSignRequest.key_output.encoding = %q, want %q", got, "sec1")
	}
}
