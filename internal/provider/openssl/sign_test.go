package openssl_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
)

func signRequestNoContext() *providerpb.SignRequest_NoContext {
	return &providerpb.SignRequest_NoContext{NoContext: &types.NoParams{}}
}

func verifyRequestNoContext() *providerpb.VerifyRequest_NoContext {
	return &providerpb.VerifyRequest_NoContext{NoContext: &types.NoParams{}}
}

func signRequestDomainContext(context []byte) *providerpb.SignRequest_DomainContext {
	return &providerpb.SignRequest_DomainContext{DomainContext: &types.SignatureDomainContext{Context: context}}
}

func verifyRequestDomainContext(context []byte) *providerpb.VerifyRequest_DomainContext {
	return &providerpb.VerifyRequest_DomainContext{DomainContext: &types.SignatureDomainContext{Context: context}}
}

// TestSign_notImplemented probes Sign's dispatch default case: every real
// algorithm arm now has a case (ECDSA, RSA-PSS, RSA-PKCS1v15, Ed25519,
// ML-DSA), so an AlgorithmDetails whose oneof is present but empty is the
// only shape left that still reaches default.
func TestSign_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.Sign(context.Background(), &providerpb.SignRequest{
		Algorithm:   &types.AlgorithmDetails{},
		KeyMaterial: []byte("placeholder"),
		Input:       []byte("message"),
		ScopeParams: signRequestNoContext(),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestSign_validatesBeforeStub is the negative control for the
// validate-then-dispatch shape: a request missing Algorithm entirely must
// fail with CodeInvalidArgument, not CodeNotImplemented — proving
// validateRequest genuinely runs first.
func TestSign_validatesBeforeStub(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.Sign(context.Background(), &providerpb.SignRequest{})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for missing algorithm, got: %v", err)
	}
}
