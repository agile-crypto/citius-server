package provider

import (
	"context"

	messages "github.ibm.com/citius/citius-server/gen/go/messages"
	types "github.ibm.com/citius/citius-server/gen/go/types"
)

type GenerateKeyRequest struct {
	KeyID     string
	Algorithm *types.AlgorithmDetails
}

type GenerateKeyResult struct {
	PrivateKeyBytes []byte // opaque key material (proto: key_material); provider-interpreted
	PublicKeyBytes  []byte // DER-encoded SubjectPublicKeyInfo (asymmetric only; proto: public_key_bytes)
}

// SignRequest carries the inputs for a provider Sign call.
type SignRequest struct {
	KeyID     string                  // for audit/logging (not used for key lookup)
	KeyBytes  []byte                  // opaque key material (private key bytes)
	Input     []byte                  // data to sign (raw, unhashed — provider hashes internally)
	Algorithm *types.AlgorithmDetails // typed algorithm for dispatch (from template)

	// Scope-based context for domain separation — exactly one must be non-nil.
	// Passed through unchanged from the orchestrator (which received it from the API request).
	NoContext     *types.NoParams               // ECDSA, RSA-PSS, DSA
	DomainContext *types.SignatureDomainContext // EdDSA, ML-DSA, SLH-DSA
	VendorContext *types.VendorSignatureContext // vendor/custom
}

// SignResult carries the outputs of a provider Sign call.
// Output: provider MUST set algorithm_output oneof (NoAlgorithmOutput for signing)
// plus encoding format. Unset Output is treated as a provider bug — core rejects.
type SignResult struct {
	Signature []byte
	Algorithm *types.AlgorithmDetails  // echo back for verification context
	Output    *messages.ProviderOutput // NoAlgorithmOutput + encoding
}

type VerifyRequest struct {
	KeyID     string // for audit/logging
	KeyBytes  []byte // opaque key material (public key bytes)
	Input     []byte // original message (unhashed)
	Signature []byte
	Algorithm *types.AlgorithmDetails // typed algorithm for dispatch (from template)

	// Scope must match the scope used during signing.
	NoContext     *types.NoParams
	DomainContext *types.SignatureDomainContext
	VendorContext *types.VendorSignatureContext
}

type VerifyResult struct {
	Valid     bool
	Algorithm *types.AlgorithmDetails
	Output    *messages.ProviderOutput // provider-generated output
}

// Backend is the Go interface that every crypto backend must implement.
// It is the core-side abstraction over the provider gRPC services
// (KeyOrchestrationService + CryptoService from the proto definitions).
//
// Proto mapping:
//
//	GenerateKey    → KeyOrchestrationService.GenerateKey
//	DestroyKey     → KeyOrchestrationService.DestroyKey
//	ExportPublicKey → KeyOrchestrationService.ExportPublicKey
//	Sign           → CryptoService.Sign (full-message, provider hashes internally)
//	Verify         → CryptoService.Verify
//
// TODO: DigestSign, DigestVerify, Encrypt, Decrypt
// are proto-defined but not yet on the Go Backend.
type Backend interface {
	Name() string
	Type() string
	GenerateKey(ctx context.Context, req GenerateKeyRequest) (GenerateKeyResult, error)
	DestroyKey(ctx context.Context, keyID string) error
	ExportPublicKey(ctx context.Context, keyID string) ([]byte, error)
	Sign(ctx context.Context, req SignRequest) (SignResult, error)
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

// AlgorithmCapabilityProvider is an optional interface that provider implementations
// can implement to expose their supported algorithm IDs.
//
// Providers that do NOT implement AlgorithmCapabilityProvider are gracefully skipped
// during template-based matching.
type AlgorithmCapabilityProvider interface {
	SupportedAlgorithms() []string
}
