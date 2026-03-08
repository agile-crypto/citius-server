package crypto

import (
	"context"

	messages "github.ibm.com/citius/citius-server/gen/go/messages"
	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/key"
)

// SignRequest carries the inputs for a Sign operation at the orchestrator level.
// The orchestrator resolves key material and passes scope_params through to the provider.
type SignRequest struct {
	KeyPublicID string // identifies which key to use (proto: key_name)
	Payload     []byte // data to sign (proto: input)

	// Scope-based context for domain separation — exactly one must be non-nil.
	// Maps to the scope_params oneof in caas.crypto.v1.SignRequest.
	// The gRPC handler copies the user's scope choice as-is.
	NoContext     *types.NoParams               // ECDSA, RSA-PSS, DSA (no context needed)
	DomainContext *types.SignatureDomainContext // EdDSA, ML-DSA, SLH-DSA (0-255 byte context)
	VendorContext *types.VendorSignatureContext // vendor/custom scope
}

// SignResult carries the outputs of a Sign operation.
// Output carries NoAlgorithmOutput + encoding (signing has no system-generated params).
type SignResult struct {
	Signature    []byte
	KeyPublicID  string                   // echo back for caller context
	KeyVersionID string                   // version that was used
	Algorithm    string                   // template ID (e.g., "ecdsa-p256-sha256")
	ProviderName string                   // which provider performed the operation
	Output       *messages.ProviderOutput // from provider (NoAlgorithmOutput + encoding)
}

type VerifyRequest struct {
	KeyPublicID string
	Payload     []byte // original data that was signed
	Signature   []byte

	// Scope must match the scope used during signing.
	NoContext     *types.NoParams
	DomainContext *types.SignatureDomainContext
	VendorContext *types.VendorSignatureContext
}

// VerifyResult carries the outputs of a Verify operation.
// Invalid signature is NOT an error — it returns Valid=false.
type VerifyResult struct {
	Valid        bool
	KeyPublicID  string
	Algorithm    string
	ProviderName string
	Output       *messages.ProviderOutput // from provider
}

type EncryptRequest struct {
	KeyID     string
	Plaintext []byte

	// Scope-based operation parameters — exactly one must be non-nil.
	// Maps to the scope_params oneof in caas.crypto.v1.EncryptRequest.
	NoParams         *types.NoParams                // AES-CBC, AES-CTR, ChaCha20, 3DES
	AeadParams       *types.AeadEncryptParams       // AES-GCM, AES-CCM, ChaCha20-Poly1305 (carries AAD)
	XtsParams        *types.XtsEncryptParams        // AES-XTS (carries tweak)
	AsymmetricParams *types.AsymmetricEncryptParams // RSA-OAEP (carries label)
	VendorParams     *types.VendorEncryptionParams  // vendor/custom scope
}

type EncryptResult struct {
	Ciphertext   []byte
	Output       *messages.ProviderOutput // IV/nonce, tag, encoding — from provider
	Algorithm    string
	ProviderName string
}

type DecryptRequest struct {
	KeyID      string
	Ciphertext []byte
	Output     *messages.ProviderOutput // stored ProviderOutput from EncryptResult (carries IV/nonce)

	// Scope-based operation parameters — must match encryption.
	NoParams         *types.NoParams
	AeadParams       *types.AeadEncryptParams       // AAD must match for AEAD authentication
	XtsParams        *types.XtsEncryptParams        // tweak must match
	AsymmetricParams *types.AsymmetricEncryptParams // label must match for OAEP
	VendorParams     *types.VendorEncryptionParams
}

type DecryptResult struct {
	Plaintext    []byte
	Algorithm    string
	ProviderName string
	Output       *messages.ProviderOutput // from provider (encoding)
}

// WrapKeyRequest carries the inputs for a WrapKey operation.
// TODO: add wrapping scope_params (NoParams, AeadParams, VendorWrapParams)
// matching caas.crypto.v1.WrapKeyRequest.
type WrapKeyRequest struct {
	WrappingKeyID string
	KeyToWrapID   string
}

// WrapKeyResult carries the outputs of a WrapKey operation.
// TODO: add Output *messages.ProviderOutput (carries IV/nonce for wrapping modes).
type WrapKeyResult struct {
	WrappedKeyBytes []byte
	Algorithm       string
}

// UnwrapKeyRequest carries the inputs for an UnwrapKey operation.
// TODO: add wrapping scope_params matching caas.crypto.v1.UnwrapKeyRequest.
type UnwrapKeyRequest struct {
	WrappingKeyID   string
	WrappedKeyBytes []byte
}

// UnwrapKeyResult carries the outputs of an UnwrapKey operation.
type UnwrapKeyResult struct {
	UnwrappedKey *key.Key
}

// DeriveKeyRequest carries the inputs for a DeriveKey operation.
// TODO: add KDF scope_params (HkdfParams, Pbkdf2Params, Argon2Params, EcdhParams, etc.)
// matching caas.crypto.v1.DeriveKeyRequest.
type DeriveKeyRequest struct {
	BaseKeyID string
	Info      []byte
}

// MacRequest carries the inputs for a GenerateMAC operation.
// TODO: add MAC scope_params (NoParams, VendorMacParams)
// matching caas.crypto.v1.GenerateMacRequest.
type MacRequest struct {
	KeyID string
	Data  []byte
}

// MacResult carries the outputs of a GenerateMAC operation.
// TODO: add Output *messages.ProviderOutput (NoAlgorithmOutput + encoding).
type MacResult struct {
	MAC       []byte
	Algorithm string
}

// VerifyMacRequest carries the inputs for a VerifyMAC operation.
// TODO: add MAC scope_params matching caas.crypto.v1.VerifyMacRequest.
type VerifyMacRequest struct {
	KeyID string
	Data  []byte
	MAC   []byte
}

// VerifyMacResult carries the outputs of a VerifyMAC operation.
type VerifyMacResult struct {
	Valid     bool
	Algorithm string
}

// DigestRequest carries the inputs for a Digest (hash) operation.
// TODO: add digest scope_params matching caas.crypto.v1.DigestRequest.
type DigestRequest struct {
	Data      []byte
	Algorithm string // e.g., "SHA-256"; empty = provider default
}

// DigestResult carries the outputs of a Digest operation.
type DigestResult struct {
	Digest    []byte
	Algorithm string
}

// ============================================================================
// Orchestrator interface
// ============================================================================

// Orchestrator performs cryptographic operations using stored keys.
// Implementations coordinate key retrieval, policy validation, and provider dispatch.
type Orchestrator interface {
	Sign(ctx context.Context, req SignRequest) (SignResult, error)
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
	Encrypt(ctx context.Context, req EncryptRequest) (EncryptResult, error)
	Decrypt(ctx context.Context, req DecryptRequest) (DecryptResult, error)
	WrapKey(ctx context.Context, req WrapKeyRequest) (WrapKeyResult, error)
	UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (UnwrapKeyResult, error)
	DeriveKey(ctx context.Context, req DeriveKeyRequest) (*key.Key, error)
	GenerateMAC(ctx context.Context, req MacRequest) (MacResult, error)
	VerifyMAC(ctx context.Context, req VerifyMacRequest) (VerifyMacResult, error)
	Digest(ctx context.Context, req DigestRequest) (DigestResult, error)
	GenerateRandom(ctx context.Context, length int) ([]byte, error)
}
