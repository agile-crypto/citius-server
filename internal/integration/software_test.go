//go:build vault_plugin

// Package integration_test — software_test.go exercises the software provider
// with real ECDSA-P256 and ML-DSA-65 crypto through the full orchestration
// stack: vault.Service => RequestScope => CryptoOrchestrator => KeyOrchestrator =>
// ProviderRegistry => software.Provider.
//
// Unlike the loopback tests (deterministic echo), these tests validate
// real cryptographic correctness end-to-end.
package integration_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-server/internal/app"
	"github.com/agile-crypto/citius-server/internal/app/vault"
	"github.com/agile-crypto/citius-server/internal/crypto"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/agile-crypto/citius-server/internal/service"
	"github.com/agile-crypto/citius-server/internal/storage"
	"github.com/agile-crypto/citius-server/internal/template"
)

// ============================================================================
// Wiring Helper — Software Provider
// ============================================================================

// wireWithSoftwareProvider builds a fully wired vault.Service backed by the real software
// provider. Templates are loaded from the standard catalog.
func wireWithSoftwareProvider(t *testing.T) *vault.Service {
	t.Helper()
	ctx := context.Background()

	// Shared template registry — loaded once from the standard catalog.
	bootstrapStorage := &logical.InmemStorage{}
	reg, err := template.NewVaultRegistry(ctx, bootstrapStorage)
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}
	err = template.LoadStandardCatalog(context.Background(), catalogPath(), reg)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	// Shared provider registry — software provider only.
	provReg := provider.NewRegistry()
	err = provReg.Register(ctx, software.New())
	if err != nil {
		t.Fatalf("Register software: %v", err)
	}

	// Validate provider capabilities against templates (fail-fast).
	err = app.ValidateAllProviders(ctx, provReg, reg)
	if err != nil {
		t.Fatalf("ValidateAllProviders: %v", err)
	}

	// Factory functions — reuse the extracted builders from loopback_test.go.
	keyFactory := func(s storage.Storage) (service.KeyOrchestrator, error) {
		return buildKeyOrchestrator(ctx, s, reg, provReg)
	}
	cryptoFactory := func(s storage.Storage) (service.CryptoOrchestrator, error) {
		return buildCryptoOrchestrator(ctx, s, reg, provReg)
	}
	policyFactory := func(s storage.Storage) (policy.Engine, error) {
		return buildPolicyEngine(ctx, s)
	}
	instanceFactory := func(_ storage.Storage) (provider.InstanceManager, error) {
		return &noopInstanceManager{}, nil
	}

	svc, err := vault.NewService(
		vault.WithKeyOrchestratorFactory(keyFactory),
		vault.WithCryptoOrchestratorFactory(cryptoFactory),
		vault.WithPolicyEngineFactory(policyFactory),
		vault.WithProviderInstanceManagerFactory(instanceFactory),
		vault.WithTemplateRegistry(reg),
		vault.WithProviderRegistry(provReg),
	)
	if err != nil {
		t.Fatalf("NewService (software): %v", err)
	}
	return svc
}

// ============================================================================
// Integration Tests — Software Provider (Real Crypto)
// ============================================================================

func TestIntegration_Software_ECDSA_RoundTrip(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-ecdsa-allow",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "real-ecdsa-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyName := createdKey.Name
	t.Logf("Created key: %s (primitive: %s)", keyName, createdKey.Primitive)

	payload := []byte("real ECDSA-P256 integration test payload")
	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("ECDSA signature length: %d bytes", len(signResult.Signature))

	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("ECDSA-P256 round-trip FAILED: valid=false")
	}
	t.Log(" ECDSA-P256 real crypto round-trip: PASSED")
}

func TestIntegration_Software_MLDSA_RoundTrip(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-mldsa-allow",
		[]string{"ml-dsa-65"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "real-mldsa-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey ml-dsa-65: %v", err)
	}
	keyName := createdKey.Name

	payload := []byte("real ML-DSA-65 integration test payload")
	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign ml-dsa-65: %v", err)
	}

	// ML-DSA-65 signature is exactly 3309 bytes (NIST FIPS 204).
	if len(signResult.Signature) != 3309 {
		t.Errorf("ML-DSA-65 signature length: got %d, want 3309", len(signResult.Signature))
	}
	t.Logf("ML-DSA-65 signature length: %d bytes", len(signResult.Signature))

	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify ml-dsa-65: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("ML-DSA-65 round-trip FAILED: valid=false")
	}
	t.Log(" ML-DSA-65 real crypto round-trip: PASSED")
}

func TestIntegration_Software_TamperedPayload_ECDSA(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-tamper-payload",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "tamper-payload-ecdsa",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyName := createdKey.Name

	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              []byte("original"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify with tampered payload — should return valid=false, NOT an error.
	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              []byte("tampered"),
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("tampered payload Verify must not error: %v", err)
	}
	if verifyResult.Valid {
		t.Error("tampered ECDSA payload: should return valid=false")
	}
	t.Log(" ECDSA tampered payload → valid=false: PASSED")
}

func TestIntegration_Software_TamperedSignature_ECDSA(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-tamper-sig",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "tamper-sig-ecdsa",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyName := createdKey.Name
	payload := []byte("check tampered signature")

	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Flip a byte in the signature.
	tamperedSig := make([]byte, len(signResult.Signature))
	copy(tamperedSig, signResult.Signature)
	tamperedSig[len(tamperedSig)/2] ^= 0xFF

	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            tamperedSig,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("tampered signature Verify must not error: %v", err)
	}
	if verifyResult.Valid {
		t.Error("tampered ECDSA signature: should return valid=false")
	}
	t.Log(" ECDSA tampered signature → valid=false: PASSED")
}

func TestIntegration_Software_SignatureSizes_Different(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-sig-sizes",
		[]string{"ecdsa-p256-sha256-der", "ml-dsa-65"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign},
	)

	ecdsaKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name: "size-ecdsa", TemplateID: "ecdsa-p256-sha256-der", PolicyID: policyName, ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey ecdsa: %v", err)
	}
	mldsaKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name: "size-mldsa", TemplateID: "ml-dsa-65", PolicyID: policyName, ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey mldsa: %v", err)
	}

	payload := []byte("comparing signature sizes")
	ecdsaSig, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              ecdsaKey.Name,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign ecdsa: %v", err)
	}
	mldsaSig, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              mldsaKey.Name,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign mldsa: %v", err)
	}

	t.Logf("ECDSA-P256 signature size: %d bytes", len(ecdsaSig.Signature))
	t.Logf("ML-DSA-65 signature size:  %d bytes", len(mldsaSig.Signature))

	// ECDSA-P256 DER-encoded (r,s) ≈ 70-72 bytes; ML-DSA-65 is 3309 bytes.
	if len(ecdsaSig.Signature) >= len(mldsaSig.Signature) {
		t.Errorf("expected ML-DSA sig (%d) >> ECDSA sig (%d)",
			len(mldsaSig.Signature), len(ecdsaSig.Signature))
	}
	if bytes.Equal(ecdsaSig.Signature, mldsaSig.Signature) {
		t.Error("ECDSA and ML-DSA signatures should not be equal")
	}
	t.Log(" Signature size comparison: PASSED")
}

func TestIntegration_Software_MultipleSignatures_NotDeterministic(t *testing.T) {
	// ECDSA uses a random nonce (k) — two signatures of the same payload must differ.
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-nonce",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "nonce-test",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyName := createdKey.Name
	payload := []byte("determinism check")

	sig1, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign(1): %v", err)
	}
	sig2, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign(2): %v", err)
	}

	// ECDSA signatures are probabilistic — they must differ (with overwhelming probability).
	if bytes.Equal(sig1.Signature, sig2.Signature) {
		t.Error("ECDSA: two signatures of same payload should differ (probabilistic algorithm)")
	}
	t.Log(" ECDSA non-determinism (two different signatures): PASSED")

	// Both signatures must still be valid.
	for i, sig := range []crypto.SignResult{sig1, sig2} {
		res, verifyErr := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
			KeyName:              keyName,
			KeyVersion:           sig.KeyVersion,
			Payload:              payload,
			Signature:            sig.Signature,
			SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
		})
		if verifyErr != nil || !res.Valid {
			t.Errorf("signature %d not valid: err=%v, valid=%v", i+1, verifyErr, res.Valid)
		}
	}
	t.Log(" Both non-deterministic ECDSA signatures verified: PASSED")
}

func TestIntegration_Software_ReadKey_AfterCreate(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-readkey",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationReadKey},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "persist-test",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Read back using the same scope (same storage).
	retrieved, err := requestScope.Keys().ReadKey(ctx, createdKey.Name, 0)
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if retrieved.KeyID != createdKey.KeyID {
		t.Errorf("ReadKey: got %s, want %s", retrieved.KeyID, createdKey.KeyID)
	}
	if retrieved.Name != "persist-test" {
		t.Errorf("ReadKey name: got %s, want persist-test", retrieved.Name)
	}
	t.Log(" ReadKey after CreateKey: PASSED")
}

func TestIntegration_Software_TransformKey_Sign_Verify(t *testing.T) {
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	// Policy must allow both the original and the target template for
	// CreateKey — TransformKey re-validates via core.OperationCreateKey.
	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"sw-transform-allow",
		[]string{"ecdsa-p256-sha256-der", "ml-dsa-65"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "real-transform-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyName := createdKey.Name

	// Sanity check: v1 (real ECDSA-P256) signs and verifies before transforming.
	payload := []byte("real crypto integration test payload — transform to ML-DSA-65")
	signV1, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign (v1, ECDSA): %v", err)
	}
	verifyV1, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signV1.KeyVersion,
		Payload:              payload,
		Signature:            signV1.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil || !verifyV1.Valid {
		t.Fatalf("Verify (v1, ECDSA) pre-transform sanity check failed: err=%v valid=%v", err, verifyV1.Valid)
	}

	// Transform the key from ecdsa-p256-sha256-der to ml-dsa-65 (post-quantum).
	transformedMeta, err := requestScope.Keys().TransformKey(ctx, service.TransformKeySpec{
		KeyName:    keyName,
		TemplateID: "ml-dsa-65",
	})
	if err != nil {
		t.Fatalf("TransformKey: %v", err)
	}
	if transformedMeta.TemplateID != "ml-dsa-65" {
		t.Errorf("TransformKey: expected template ml-dsa-65, got %s", transformedMeta.TemplateID)
	}
	if transformedMeta.Version != 2 {
		t.Errorf("TransformKey: expected version 2, got %d", transformedMeta.Version)
	}
	t.Logf("Transformed key: %s -> template=%s version=%d", keyName, transformedMeta.TemplateID, transformedMeta.Version)

	// Sign+Verify round-trip on the transformed (current) ML-DSA-65 version.
	signV2, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign (v2, post-transform ML-DSA-65): %v", err)
	}
	if signV2.KeyVersion != 2 {
		t.Fatalf("expected post-transform sign to use version 2, got %d", signV2.KeyVersion)
	}
	if len(signV2.Signature) != 3309 {
		t.Errorf("ML-DSA-65 signature length: got %d, want 3309", len(signV2.Signature))
	}

	verifyV2, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signV2.KeyVersion,
		Payload:              payload,
		Signature:            signV2.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify (v2, post-transform ML-DSA-65): %v", err)
	}
	if !verifyV2.Valid {
		t.Error("TransformKey round-trip FAILED: Sign+Verify on transformed ML-DSA-65 version is not valid")
	}
	t.Log(" TransformKey Sign+Verify round-trip (software, ECDSA->ML-DSA-65): PASSED")
}

// func TestIntegration_Software_TransformKey_withScopeSpecification_Sign_Verify(t *testing.T) {
// 	svc := wireWithSoftwareProvider(t)
// 	ctx := context.Background()
// 	store := &logical.InmemStorage{}

// 	requestScope, err := svc.ForStorage(ctx, store)
// 	if err != nil {
// 		t.Fatalf("ForStorage: %v", err)
// 	}

// 	// Policy must allow both the original and the target template for
// 	// CreateKey — TransformKey re-validates via core.OperationCreateKey.
// 	policyName := seedPolicy(t, ctx, requestScope.Policy(),
// 		"sw-transform-allow",
// 		[]string{"ecdsa-p256-sha256-der", "ml-dsa-65"},
// 		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
// 	)

// 	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
// 		Name:               "real-transform-key",
// 		TemplateID:         "ecdsa-p256-sha256-der",
// 		PolicyID:           policyName,
// 		ScopeSpecification: sigScopeSpec(),
// 	})
// 	if err != nil {
// 		t.Fatalf("CreateKey: %v", err)
// 	}
// 	keyName := createdKey.Name

// 	// Sanity check: v1 (real ECDSA-P256) signs and verifies before transforming.
// 	payload := []byte("real crypto integration test payload — transform to ML-DSA-65")
// 	signV1, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
// 		KeyName:              keyName,
// 		Payload:              payload,
// 		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
// 	})
// 	if err != nil {
// 		t.Fatalf("Sign (v1, ECDSA): %v", err)
// 	}
// 	verifyV1, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
// 		KeyName:              keyName,
// 		KeyVersion:           signV1.KeyVersion,
// 		Payload:              payload,
// 		Signature:            signV1.Signature,
// 		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
// 	})
// 	if err != nil || !verifyV1.Valid {
// 		t.Fatalf("Verify (v1, ECDSA) pre-transform sanity check failed: err=%v valid=%v", err, verifyV1.Valid)
// 	}

// 	// Transform the key from ecdsa-p256-sha256-der to ml-dsa-65 (post-quantum).
// 	transformedMeta, err := requestScope.Keys().TransformKey(ctx, service.TransformKeySpec{
// 		KeyName:            keyName,
// 		TemplateID:         "ml-dsa-65",
// 		ScopeSpecification: sigScopeSpec(),
// 	})
// 	if err != nil {
// 		t.Fatalf("TransformKey: %v", err)
// 	}
// 	if transformedMeta.TemplateID != "ml-dsa-65" {
// 		t.Errorf("TransformKey: expected template ml-dsa-65, got %s", transformedMeta.TemplateID)
// 	}
// 	if transformedMeta.Version != 2 {
// 		t.Errorf("TransformKey: expected version 2, got %d", transformedMeta.Version)
// 	}
// 	t.Logf("Transformed key: %s -> template=%s version=%d", keyName, transformedMeta.TemplateID, transformedMeta.Version)

// 	// Sign+Verify round-trip on the transformed (current) ML-DSA-65 version.
// 	signV2, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
// 		KeyName:              keyName,
// 		Payload:              payload,
// 		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
// 	})
// 	if err != nil {
// 		t.Fatalf("Sign (v2, post-transform ML-DSA-65): %v", err)
// 	}
// 	if signV2.KeyVersion != 2 {
// 		t.Fatalf("expected post-transform sign to use version 2, got %d", signV2.KeyVersion)
// 	}
// 	if len(signV2.Signature) != 3309 {
// 		t.Errorf("ML-DSA-65 signature length: got %d, want 3309", len(signV2.Signature))
// 	}

// 	verifyV2, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
// 		KeyName:              keyName,
// 		KeyVersion:           signV2.KeyVersion,
// 		Payload:              payload,
// 		Signature:            signV2.Signature,
// 		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
// 	})
// 	if err != nil {
// 		t.Fatalf("Verify (v2, post-transform ML-DSA-65): %v", err)
// 	}
// 	if !verifyV2.Valid {
// 		t.Error("TransformKey round-trip FAILED: Sign+Verify on transformed ML-DSA-65 version is not valid")
// 	}
// 	t.Log(" TransformKey Sign+Verify round-trip (software, ECDSA->ML-DSA-65): PASSED")
// }
