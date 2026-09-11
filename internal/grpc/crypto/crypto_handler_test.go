// Tests replicated from the monolithic internal/grpc handler suite, so that
// each service handler is covered where it now lives. The assertions are
// unchanged; only the wiring differs — the handler is built from a factory
// closure over the mock instead of a ServiceGateway/scope pair.

package cryptogrpc_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-server/internal/provider"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/internal/crypto"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	cryptogrpc "github.com/agile-crypto/citius-server/internal/grpc/crypto"
	"github.com/agile-crypto/citius-server/internal/key"
	"github.com/agile-crypto/citius-server/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockCryptoOps stubs CryptoOrchestrator for tests.
// Only signFn, verifyFn, encryptFn, decryptFn, digestSignFn, and
// digestVerifyFn are wired; all other methods panic.
type mockCryptoOps struct {
	signFn         func(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error)
	verifyFn       func(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error)
	encryptFn      func(ctx context.Context, req crypto.EncryptRequest) (crypto.EncryptResult, error)
	decryptFn      func(ctx context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error)
	digestSignFn   func(ctx context.Context, req crypto.DigestSignRequest) (crypto.SignResult, error)
	digestVerifyFn func(ctx context.Context, req crypto.DigestVerifyRequest) (crypto.VerifyResult, error)
}

func (m *mockCryptoOps) Sign(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	panic("mockCryptoOps.Sign: not implemented")
}

func (m *mockCryptoOps) Verify(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req)
	}
	panic("mockCryptoOps.Verify: not implemented")
}

// Stub the rest of the interface.
func (m *mockCryptoOps) DigestSign(ctx context.Context, req crypto.DigestSignRequest) (crypto.SignResult, error) {
	if m.digestSignFn != nil {
		return m.digestSignFn(ctx, req)
	}
	panic("mockCryptoOps.DigestSign: not implemented")
}
func (m *mockCryptoOps) DigestVerify(ctx context.Context, req crypto.DigestVerifyRequest) (crypto.VerifyResult, error) {
	if m.digestVerifyFn != nil {
		return m.digestVerifyFn(ctx, req)
	}
	panic("mockCryptoOps.DigestVerify: not implemented")
}
func (m *mockCryptoOps) Encrypt(ctx context.Context, req crypto.EncryptRequest) (crypto.EncryptResult, error) {
	if m.encryptFn != nil {
		return m.encryptFn(ctx, req)
	}
	panic("mockCryptoOps.Encrypt: not implemented")
}
func (m *mockCryptoOps) Decrypt(ctx context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req)
	}
	panic("mockCryptoOps.Decrypt: not implemented")
}
func (m *mockCryptoOps) WrapKey(_ context.Context, _ crypto.WrapKeyRequest) (crypto.WrapKeyResult, error) {
	panic("mockCryptoOps.WrapKey: not implemented")
}
func (m *mockCryptoOps) UnwrapKey(_ context.Context, _ crypto.UnwrapKeyRequest) (crypto.UnwrapKeyResult, error) {
	panic("mockCryptoOps.UnwrapKey: not implemented")
}
func (m *mockCryptoOps) DeriveKey(_ context.Context, _ crypto.DeriveKeyRequest) (*key.Key, error) {
	panic("mockCryptoOps.DeriveKey: not implemented")
}
func (m *mockCryptoOps) GenerateMAC(_ context.Context, _ crypto.MacRequest) (crypto.MacResult, error) {
	panic("mockCryptoOps.GenerateMAC: not implemented")
}
func (m *mockCryptoOps) VerifyMAC(_ context.Context, _ crypto.VerifyMacRequest) (crypto.VerifyMacResult, error) {
	panic("mockCryptoOps.VerifyMAC: not implemented")
}
func (m *mockCryptoOps) Digest(_ context.Context, _ crypto.DigestRequest) (crypto.DigestResult, error) {
	panic("mockCryptoOps.Digest: not implemented")
}
func (m *mockCryptoOps) GenerateRandom(_ context.Context, _ int) ([]byte, error) {
	panic("mockCryptoOps.GenerateRandom: not implemented")
}

// wireCrypto builds the handler under test over a fixed orchestrator.
func wireCrypto(t *testing.T, ops service.CryptoOrchestrator) *cryptogrpc.CryptoHandler {
	t.Helper()
	newCrypto := service.CryptoOrchestratorFactory(func(_ context.Context) (service.CryptoOrchestrator, error) {
		return ops, nil
	})
	authFn := func(ctx context.Context, op engerr.Op, name string) error {
		return nil
	}
	h, err := cryptogrpc.New(context.Background(), newCrypto, authFn)
	if err != nil {
		t.Fatalf("cryptogrpc.New: %v", err)
	}
	return h
}

func TestCryptoHandler_Sign_Success(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{
			NoOutput: &messagespb.NoAlgorithmOutput{},
		},
		Encoding: "raw",
	}
	cr := &mockCryptoOps{
		signFn: func(_ context.Context, req crypto.SignRequest) (crypto.SignResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA sign")
			}
			return crypto.SignResult{
				Signature:    []byte("fake-sig"),
				KeyName:      req.KeyName,
				Algorithm:    "ecdsa-p256-sha256-der",
				ProviderName: "software",
				Output:       providerOutput,
			}, nil
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.Sign(ctx, &messagespb.SignRequest{
		KeyName: "key_123",
		Input:   []byte("hello"),
		ScopeParams: &messagespb.SignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Sign handler: %v", err)
	}
	if len(resp.GetSignature()) == 0 {
		t.Error("Sign response: empty signature")
	}
	if resp.GetMetadata() == nil {
		t.Fatal("Sign response: Metadata must not be nil")
	}
	if resp.GetMetadata().GetProviderOutput() == nil {
		t.Error("Sign response: Metadata.ProviderOutput must not be nil")
	}
}

func TestCryptoHandler_Verify_InvalidSig_ReturnsValidFalse(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		verifyFn: func(_ context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA verify")
			}
			return crypto.VerifyResult{Valid: false}, nil // invalid sig — not an error
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.Verify(ctx, &messagespb.VerifyRequest{
		KeyName:   "key_123",
		Input:     []byte("hello"),
		Signature: []byte("bad-sig"),
		ScopeParams: &messagespb.VerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Verify handler should not error for invalid sig: %v", err)
	}
	if resp.GetValid() {
		t.Error("Verify response: expected valid=false")
	}
}

func TestCryptoHandler_Encrypt_Success(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{
			NoOutput: &messagespb.NoAlgorithmOutput{},
		},
		Encoding: "raw",
	}
	cr := &mockCryptoOps{
		encryptFn: func(_ context.Context, req crypto.EncryptRequest) (crypto.EncryptResult, error) {
			if req.AeadParams == nil {
				t.Error("expected AeadParams to be set for AES-GCM encrypt")
			}
			return crypto.EncryptResult{
				Ciphertext:   []byte("fake-ciphertext"),
				KeyVersion:   3,
				Algorithm:    "aes-256-gcm-128-96",
				ProviderName: "software",
				Output:       providerOutput,
			}, nil
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName:   "key_123",
		Plaintext: []byte("hello"),
		ScopeParams: &messagespb.EncryptRequest_AeadParams{
			AeadParams: &typespb.AeadEncryptParams{},
		},
	})
	if err != nil {
		t.Fatalf("Encrypt handler: %v", err)
	}
	if len(resp.GetCiphertext()) == 0 {
		t.Error("Encrypt response: empty ciphertext")
	}
	if resp.GetMetadata() == nil {
		t.Fatal("Encrypt response: Metadata must not be nil")
	}
	if resp.GetMetadata().GetKeyVersion() != 3 {
		t.Errorf("Encrypt response: expected KeyVersion 3, got %d", resp.GetMetadata().GetKeyVersion())
	}
	if resp.GetMetadata().GetProviderOutput() == nil {
		t.Error("Encrypt response: Metadata.ProviderOutput must not be nil")
	}
}

func TestCryptoHandler_Encrypt_ScopeParamsVariants(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{NoOutput: &messagespb.NoAlgorithmOutput{}},
		Encoding:        "raw",
	}

	tests := []struct {
		name     string
		buildReq func() *messagespb.EncryptRequest
		check    func(t *testing.T, req crypto.EncryptRequest)
	}{
		{
			name: "NoParams",
			buildReq: func() *messagespb.EncryptRequest {
				return &messagespb.EncryptRequest{
					KeyName: "key_123", Plaintext: []byte("hello"),
					ScopeParams: &messagespb.EncryptRequest_NoParams{NoParams: &typespb.NoParams{}},
				}
			},
			check: func(t *testing.T, req crypto.EncryptRequest) {
				if req.NoParams == nil {
					t.Error("expected NoParams to be set")
				}
			},
		},
		{
			name: "AeadParams",
			buildReq: func() *messagespb.EncryptRequest {
				return &messagespb.EncryptRequest{
					KeyName: "key_123", Plaintext: []byte("hello"),
					ScopeParams: &messagespb.EncryptRequest_AeadParams{AeadParams: &typespb.AeadEncryptParams{Aad: []byte("aad")}},
				}
			},
			check: func(t *testing.T, req crypto.EncryptRequest) {
				if req.AeadParams == nil || string(req.AeadParams.GetAad()) != "aad" {
					t.Error("expected AeadParams with AAD to be set")
				}
			},
		},
		{
			name: "XtsParams",
			buildReq: func() *messagespb.EncryptRequest {
				return &messagespb.EncryptRequest{
					KeyName: "key_123", Plaintext: []byte("hello"),
					ScopeParams: &messagespb.EncryptRequest_XtsParams{XtsParams: &typespb.XtsEncryptParams{Tweak: []byte("tweak-16-bytes--")}},
				}
			},
			check: func(t *testing.T, req crypto.EncryptRequest) {
				if req.XtsParams == nil {
					t.Error("expected XtsParams to be set")
				}
			},
		},
		{
			name: "AsymmetricParams",
			buildReq: func() *messagespb.EncryptRequest {
				return &messagespb.EncryptRequest{
					KeyName: "key_123", Plaintext: []byte("hello"),
					ScopeParams: &messagespb.EncryptRequest_AsymmetricParams{AsymmetricParams: &typespb.AsymmetricEncryptParams{Label: []byte("label")}},
				}
			},
			check: func(t *testing.T, req crypto.EncryptRequest) {
				if req.AsymmetricParams == nil {
					t.Error("expected AsymmetricParams to be set")
				}
			},
		},
		{
			name: "VendorParams",
			buildReq: func() *messagespb.EncryptRequest {
				return &messagespb.EncryptRequest{
					KeyName: "key_123", Plaintext: []byte("hello"),
					ScopeParams: &messagespb.EncryptRequest_VendorParams{VendorParams: &typespb.VendorEncryptionParams{}},
				}
			},
			check: func(t *testing.T, req crypto.EncryptRequest) {
				if req.VendorParams == nil {
					t.Error("expected VendorParams to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured crypto.EncryptRequest
			cr := &mockCryptoOps{
				encryptFn: func(_ context.Context, req crypto.EncryptRequest) (crypto.EncryptResult, error) {
					captured = req
					return crypto.EncryptResult{Ciphertext: []byte("ct"), Output: providerOutput}, nil
				},
			}
			h := wireCrypto(t, cr)

			if _, err := h.Encrypt(ctx, tt.buildReq()); err != nil {
				t.Fatalf("Encrypt handler: %v", err)
			}
			tt.check(t, captured)
		})
	}
}

func TestCryptoHandler_Encrypt_OrchestratorError_MapsToStatus(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		encryptFn: func(ctx context.Context, _ crypto.EncryptRequest) (crypto.EncryptResult, error) {
			return crypto.EncryptResult{}, engerr.New(ctx, "test", engerr.CodeNotImplemented, "provider does not support encryption")
		},
	}
	h := wireCrypto(t, cr)

	_, err := h.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName:   "key_123",
		Plaintext: []byte("hello"),
		ScopeParams: &messagespb.EncryptRequest_NoParams{
			NoParams: &typespb.NoParams{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %s", st.Code())
	}
}

func TestCryptoHandler_Decrypt_Success(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{
			NoOutput: &messagespb.NoAlgorithmOutput{},
		},
		Encoding: "raw",
	}
	cr := &mockCryptoOps{
		decryptFn: func(_ context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error) {
			if req.KeyVersion != 3 {
				t.Errorf("expected KeyVersion 3 from metadata.key_version, got %d", req.KeyVersion)
			}
			if req.Output == nil {
				t.Error("expected Output to be set from metadata.provider_output")
			}
			if req.AeadParams == nil {
				t.Error("expected AeadParams to be set for AES-GCM decrypt")
			}
			return crypto.DecryptResult{
				Plaintext:    []byte("hello"),
				Algorithm:    "aes-256-gcm-128-96",
				ProviderName: "software",
				Output:       providerOutput,
			}, nil
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName:    "key_123",
		Ciphertext: []byte("fake-ciphertext"),
		Metadata: &messagespb.OperationMetadata{
			KeyVersion:     3,
			ProviderOutput: providerOutput,
		},
		ScopeParams: &messagespb.DecryptRequest_AeadParams{
			AeadParams: &typespb.AeadEncryptParams{},
		},
	})
	if err != nil {
		t.Fatalf("Decrypt handler: %v", err)
	}
	if string(resp.GetPlaintext()) != "hello" {
		t.Errorf("Decrypt response: expected plaintext %q, got %q", "hello", resp.GetPlaintext())
	}
	if resp.GetMetadata() == nil {
		t.Fatal("Decrypt response: Metadata must not be nil")
	}
	if resp.GetMetadata().GetProviderOutput() == nil {
		t.Error("Decrypt response: Metadata.ProviderOutput must not be nil")
	}
}

func TestCryptoHandler_Decrypt_ScopeParamsVariants(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{NoOutput: &messagespb.NoAlgorithmOutput{}},
		Encoding:        "raw",
	}
	metadata := &messagespb.OperationMetadata{ProviderOutput: providerOutput}

	tests := []struct {
		name     string
		buildReq func() *messagespb.DecryptRequest
		check    func(t *testing.T, req crypto.DecryptRequest)
	}{
		{
			name: "NoParams",
			buildReq: func() *messagespb.DecryptRequest {
				return &messagespb.DecryptRequest{
					KeyName: "key_123", Ciphertext: []byte("ct"), Metadata: metadata,
					ScopeParams: &messagespb.DecryptRequest_NoParams{NoParams: &typespb.NoParams{}},
				}
			},
			check: func(t *testing.T, req crypto.DecryptRequest) {
				if req.NoParams == nil {
					t.Error("expected NoParams to be set")
				}
			},
		},
		{
			name: "AeadParams",
			buildReq: func() *messagespb.DecryptRequest {
				return &messagespb.DecryptRequest{
					KeyName: "key_123", Ciphertext: []byte("ct"), Metadata: metadata,
					ScopeParams: &messagespb.DecryptRequest_AeadParams{AeadParams: &typespb.AeadEncryptParams{Aad: []byte("aad")}},
				}
			},
			check: func(t *testing.T, req crypto.DecryptRequest) {
				if req.AeadParams == nil || string(req.AeadParams.GetAad()) != "aad" {
					t.Error("expected AeadParams with AAD to be set")
				}
			},
		},
		{
			name: "XtsParams",
			buildReq: func() *messagespb.DecryptRequest {
				return &messagespb.DecryptRequest{
					KeyName: "key_123", Ciphertext: []byte("ct"), Metadata: metadata,
					ScopeParams: &messagespb.DecryptRequest_XtsParams{XtsParams: &typespb.XtsEncryptParams{Tweak: []byte("tweak-16-bytes--")}},
				}
			},
			check: func(t *testing.T, req crypto.DecryptRequest) {
				if req.XtsParams == nil {
					t.Error("expected XtsParams to be set")
				}
			},
		},
		{
			name: "AsymmetricParams",
			buildReq: func() *messagespb.DecryptRequest {
				return &messagespb.DecryptRequest{
					KeyName: "key_123", Ciphertext: []byte("ct"), Metadata: metadata,
					ScopeParams: &messagespb.DecryptRequest_AsymmetricParams{AsymmetricParams: &typespb.AsymmetricEncryptParams{Label: []byte("label")}},
				}
			},
			check: func(t *testing.T, req crypto.DecryptRequest) {
				if req.AsymmetricParams == nil {
					t.Error("expected AsymmetricParams to be set")
				}
			},
		},
		{
			name: "VendorParams",
			buildReq: func() *messagespb.DecryptRequest {
				return &messagespb.DecryptRequest{
					KeyName: "key_123", Ciphertext: []byte("ct"), Metadata: metadata,
					ScopeParams: &messagespb.DecryptRequest_VendorParams{VendorParams: &typespb.VendorEncryptionParams{}},
				}
			},
			check: func(t *testing.T, req crypto.DecryptRequest) {
				if req.VendorParams == nil {
					t.Error("expected VendorParams to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured crypto.DecryptRequest
			cr := &mockCryptoOps{
				decryptFn: func(_ context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error) {
					captured = req
					return crypto.DecryptResult{Plaintext: []byte("pt"), Output: providerOutput}, nil
				},
			}
			h := wireCrypto(t, cr)

			if _, err := h.Decrypt(ctx, tt.buildReq()); err != nil {
				t.Fatalf("Decrypt handler: %v", err)
			}
			tt.check(t, captured)
		})
	}
}

// TestHandler_Decrypt_MissingMetadata_ReturnsInvalidArgument proves the handler
// does not nil-deref when metadata is omitted (proto getters are nil-safe) and
// that the orchestrator's own nil-Output rejection reaches the caller as
// InvalidArgument rather than surfacing as an unrelated or opaque error.

func TestCryptoHandler_Decrypt_MissingMetadata_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		decryptFn: func(ctx context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error) {
			if req.Output != nil {
				t.Fatal("expected Output to be nil when metadata is omitted")
			}
			return crypto.DecryptResult{}, engerr.New(ctx, "test", engerr.CodeInvalidArgument, "Output must not be nil")
		},
	}
	h := wireCrypto(t, cr)

	_, err := h.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName:    "key_123",
		Ciphertext: []byte("ct"),
		ScopeParams: &messagespb.DecryptRequest_NoParams{
			NoParams: &typespb.NoParams{},
		},
		// Metadata intentionally omitted.
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestCryptoHandler_Decrypt_OrchestratorError_MapsToStatus(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		decryptFn: func(ctx context.Context, _ crypto.DecryptRequest) (crypto.DecryptResult, error) {
			return crypto.DecryptResult{}, engerr.New(ctx, "test", engerr.CodeNotImplemented, "provider does not support decryption")
		},
	}
	h := wireCrypto(t, cr)

	_, err := h.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName:    "key_123",
		Ciphertext: []byte("ct"),
		Metadata:   &messagespb.OperationMetadata{},
		ScopeParams: &messagespb.DecryptRequest_NoParams{
			NoParams: &typespb.NoParams{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %s", st.Code())
	}
}

func TestCryptoHandler_DigestSign_Success(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{
			NoOutput: &messagespb.NoAlgorithmOutput{},
		},
		Encoding: "raw",
	}
	digest := make([]byte, 32) // SHA-256 output size
	cr := &mockCryptoOps{
		digestSignFn: func(_ context.Context, req crypto.DigestSignRequest) (crypto.SignResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA digest sign")
			}
			if req.HashAlgorithm != typespb.HashAlgorithm_HASH_ALGORITHM_SHA256 {
				t.Errorf("expected HashAlgorithm SHA256, got %s", req.HashAlgorithm)
			}
			if req.HashAlgorithmOID != "1.2.3" {
				t.Errorf("expected HashAlgorithmOID 1.2.3, got %q", req.HashAlgorithmOID)
			}
			if len(req.Digest) != len(digest) {
				t.Errorf("expected digest of length %d, got %d", len(digest), len(req.Digest))
			}
			return crypto.SignResult{
				Signature:    []byte("fake-sig"),
				KeyVersion:   2,
				Algorithm:    "ecdsa-p256-sha256-der",
				ProviderName: "software",
				Output:       providerOutput,
			}, nil
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.DigestSign(ctx, &messagespb.DigestSignRequest{
		KeyName:          "key_123",
		Digest:           digest,
		HashAlgorithm:    typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		HashAlgorithmOid: "1.2.3",
		ScopeParams: &messagespb.DigestSignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("DigestSign handler: %v", err)
	}
	if len(resp.GetSignature()) == 0 {
		t.Error("DigestSign response: empty signature")
	}
	if resp.GetMetadata() == nil {
		t.Fatal("DigestSign response: Metadata must not be nil")
	}
	if resp.GetMetadata().GetKeyVersion() != 2 {
		t.Errorf("DigestSign response: expected KeyVersion 2, got %d", resp.GetMetadata().GetKeyVersion())
	}
	if resp.GetMetadata().GetProviderOutput() == nil {
		t.Error("DigestSign response: Metadata.ProviderOutput must not be nil")
	}
}

// TestHandler_DigestSign_DigestLengthMismatch_Rejected proves hash_algorithm
// actually reaches the orchestrator rather than being silently dropped: the
// mock replicates the real length check every provider performs (a digest's
// byte length must match its declared hash algorithm's fixed output size —
// see provider.DigestLengthForHash) and this test supplies a digest whose
// length contradicts the declared SHA-256 algorithm.

func TestCryptoHandler_DigestSign_DigestLengthMismatch_Rejected(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		digestSignFn: func(ctx context.Context, req crypto.DigestSignRequest) (crypto.SignResult, error) {
			wantLen, ok := provider.DigestLengthForHash(req.HashAlgorithm)
			if ok && len(req.Digest) != wantLen {
				return crypto.SignResult{}, engerr.New(ctx, "test", engerr.CodeInvalidArgument,
					"digest length does not match declared hash algorithm")
			}
			t.Fatal("expected digest length mismatch to be detected")
			return crypto.SignResult{}, nil
		},
	}
	h := wireCrypto(t, cr)

	_, err := h.DigestSign(ctx, &messagespb.DigestSignRequest{
		KeyName:       "key_123",
		Digest:        make([]byte, 16), // wrong length: SHA-256 digests are 32 bytes
		HashAlgorithm: typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		ScopeParams: &messagespb.DigestSignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestCryptoHandler_DigestSign_OrchestratorError_MapsToStatus(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		digestSignFn: func(ctx context.Context, _ crypto.DigestSignRequest) (crypto.SignResult, error) {
			return crypto.SignResult{}, engerr.New(ctx, "test", engerr.CodeNotImplemented, "provider does not support signing")
		},
	}
	h := wireCrypto(t, cr)

	_, err := h.DigestSign(ctx, &messagespb.DigestSignRequest{
		KeyName:       "key_123",
		Digest:        make([]byte, 32),
		HashAlgorithm: typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		ScopeParams: &messagespb.DigestSignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %s", st.Code())
	}
}

func TestCryptoHandler_DigestVerify_Valid(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{NoOutput: &messagespb.NoAlgorithmOutput{}},
		Encoding:        "raw",
	}
	digest := make([]byte, 32)
	cr := &mockCryptoOps{
		digestVerifyFn: func(_ context.Context, req crypto.DigestVerifyRequest) (crypto.VerifyResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA digest verify")
			}
			if req.KeyVersion != 2 {
				t.Errorf("expected KeyVersion 2 from metadata.key_version, got %d", req.KeyVersion)
			}
			if req.Output == nil {
				t.Error("expected Output to be set from metadata.provider_output")
			}
			if req.HashAlgorithm != typespb.HashAlgorithm_HASH_ALGORITHM_SHA256 {
				t.Errorf("expected HashAlgorithm SHA256, got %s", req.HashAlgorithm)
			}
			return crypto.VerifyResult{Valid: true, Output: providerOutput}, nil
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.DigestVerify(ctx, &messagespb.DigestVerifyRequest{
		KeyName:   "key_123",
		Digest:    digest,
		Signature: []byte("fake-sig"),
		Metadata: &messagespb.OperationMetadata{
			KeyVersion:     2,
			ProviderOutput: providerOutput,
		},
		HashAlgorithm: typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		ScopeParams: &messagespb.DigestVerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("DigestVerify handler: %v", err)
	}
	if !resp.GetValid() {
		t.Error("DigestVerify response: expected valid=true")
	}
	if resp.GetMetadata().GetProviderOutput() == nil {
		t.Error("DigestVerify response: Metadata.ProviderOutput must not be nil")
	}
}

func TestCryptoHandler_DigestVerify_InvalidSig_ReturnsValidFalse(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		digestVerifyFn: func(_ context.Context, req crypto.DigestVerifyRequest) (crypto.VerifyResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA digest verify")
			}
			return crypto.VerifyResult{Valid: false}, nil // invalid sig — not an error
		},
	}
	h := wireCrypto(t, cr)

	resp, err := h.DigestVerify(ctx, &messagespb.DigestVerifyRequest{
		KeyName:   "key_123",
		Digest:    make([]byte, 32),
		Signature: []byte("bad-sig"),
		Metadata:  &messagespb.OperationMetadata{},
		ScopeParams: &messagespb.DigestVerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("DigestVerify handler should not error for invalid sig: %v", err)
	}
	if resp.GetValid() {
		t.Error("DigestVerify response: expected valid=false")
	}
}

func TestCryptoHandler_DigestVerify_OrchestratorError_MapsToStatus(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		digestVerifyFn: func(ctx context.Context, _ crypto.DigestVerifyRequest) (crypto.VerifyResult, error) {
			return crypto.VerifyResult{}, engerr.New(ctx, "test", engerr.CodeNotImplemented, "provider does not support signing")
		},
	}
	h := wireCrypto(t, cr)

	_, err := h.DigestVerify(ctx, &messagespb.DigestVerifyRequest{
		KeyName:   "key_123",
		Digest:    make([]byte, 32),
		Signature: []byte("sig"),
		Metadata:  &messagespb.OperationMetadata{},
		ScopeParams: &messagespb.DigestVerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %s", st.Code())
	}
}
