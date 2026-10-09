package crypto_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// The tests in this file check that responses carry every field the server
// has a source for, and nothing it has none for (see "Response Fields and
// Presence" in the API design philosophy): through the real handlers, store,
// catalog and providers.

// TestSmoke_ResponseFields_signatureKey creates an ML-DSA-65 key by intent
// (quantum-safe signature, nothing else stated) and reads what CreateKey,
// ReadKey, ListKeys, Sign and Verify report about it.
func TestSmoke_ResponseFields_signatureKey(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "pqc", []string{"ml-dsa-65"}, []string{"create_key", "read_key", "sign", "verify"})

	created, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   "pqc-key",
		Policy: pol,
		ScopeSpec: signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD,
			&typespb.UniversalSecurityProperties{QuantumSafe: proto.Bool(true)}),
	})
	require.NoError(t, err)
	require.True(t, created.GetSuccess())
	require.Equal(t, "created version 1 with template ml-dsa-65 on software", created.GetMessage())
	require.True(t, created.GetSecurityGuarantees().GetPractical().GetAuthenticity(),
		"CreateKey reports the template's guarantees for the scope: %v", created.GetSecurityGuarantees())
	require.Equal(t, "go", created.GetImplementationProperties().GetImplementationLanguage())

	read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "pqc-key"})
	require.NoError(t, err)
	listed, err := h.KeysHandler.ListKeys(ctx, &messagespb.ListKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listed.GetKeys(), 1)

	for name, md := range map[string]*messagespb.KeyMetadata{
		"CreateKey": created.GetKeyMetadata(),
		"ReadKey":   read.GetKeyMetadata(),
		"ListKeys":  listed.GetKeys()[0],
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, uint32(1), md.GetVersion())
			require.Equal(t, "ml-dsa-65", md.GetTemplateId())
			require.Equal(t, "software", md.GetProvider())
			require.NotNil(t, md.GetCreatedTime())
			require.NotNil(t, md.GetUpdatedTime())
			require.Equal(t, typespb.KeyOrigin_KEY_ORIGIN_GENERATED, md.GetOrigin())
			require.Equal(t, "go", md.GetImplementationProperties().GetImplementationLanguage())
			require.NotEmpty(t, md.GetPublicKeyBytes())
			require.NotNil(t, md.PublicKeyFormat, "an asymmetric key states its public key format")

			// What was requested: only quantum_safe was stated.
			requested := md.GetScopeSpec().GetSignature().GetSecurity()
			require.True(t, requested.GetQuantumSafe())
			require.Nil(t, requested.FipsApproved, "fips_approved was not stated, so it must not read as false")
			require.Zero(t, requested.GetSecurityStrengthBits())

			// What was chosen: the template states its 192-bit strength.
			require.Equal(t, "ml-dsa-65", md.GetTemplateInfo().GetTemplateId())
			var strength uint32
			for _, c := range md.GetTemplateInfo().GetScopedCapabilities() {
				if s := c.GetScope().GetSignature(); s.GetScope() == typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD {
					strength = s.GetSecurity().GetSecurityStrengthBits()
				}
			}
			require.Equal(t, uint32(192), strength)
		})
	}

	payload := []byte("response fields")
	userContext := map[string]string{"request_id": "abc-123"}
	signed, err := h.CryptoHandler.Sign(ctx, &messagespb.SignRequest{
		KeyName: "pqc-key", Input: payload, UserContext: userContext,
		ScopeParams: &messagespb.SignRequest_NoContext{NoContext: &typespb.NoParams{}},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), signed.GetMetadata().GetKeyVersion())
	require.Equal(t, userContext, signed.GetMetadata().GetUserContext())

	for name, md := range map[string]*messagespb.OperationMetadata{
		"with the signature's metadata": signed.GetMetadata(),
		"without metadata":              nil,
	} {
		t.Run("Verify "+name, func(t *testing.T) {
			verified, err := h.CryptoHandler.Verify(ctx, &messagespb.VerifyRequest{
				KeyName: "pqc-key", Input: payload, Signature: signed.GetSignature(), Metadata: md,
				UserContext: userContext,
				ScopeParams: &messagespb.VerifyRequest_NoContext{NoContext: &typespb.NoParams{}},
			})
			require.NoError(t, err)
			require.True(t, verified.GetValid())
			require.Equal(t, uint32(1), verified.GetMetadata().GetKeyVersion(),
				"Verify names the version it checked against, also when the request names none")
			require.Equal(t, userContext, verified.GetMetadata().GetUserContext())
		})
	}
}

// TestSmoke_ResponseFields_symmetricKey checks a symmetric key states no
// public key, and that Decrypt reports the version it decrypted with.
func TestSmoke_ResponseFields_symmetricKey(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "aead", []string{aeadTemplate}, []string{"create_key", "read_key", "encrypt", "decrypt"})
	keyName := createAEADKey(t, ctx, h, "aead-key", pol)

	read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: keyName})
	require.NoError(t, err)
	md := read.GetKeyMetadata()
	require.Equal(t, typespb.KeyOrigin_KEY_ORIGIN_GENERATED, md.GetOrigin())
	require.NotNil(t, md.GetCreatedTime())
	require.Equal(t, aeadTemplate, md.GetTemplateInfo().GetTemplateId())
	require.Nil(t, md.PublicKeyBytes, "a symmetric key has no public key")
	require.Nil(t, md.PublicKeyFormat)

	params := &typespb.AeadEncryptParams{}
	enc, err := h.CryptoHandler.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName: keyName, Plaintext: []byte("secret"),
		ScopeParams: &messagespb.EncryptRequest_AeadParams{AeadParams: params},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), enc.GetMetadata().GetKeyVersion())
	require.Nil(t, enc.GetMetadata().GetUserContext(), "no user context was given")

	dec, err := h.CryptoHandler.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName: keyName, Ciphertext: enc.GetCiphertext(), Metadata: enc.GetMetadata(),
		ScopeParams: &messagespb.DecryptRequest_AeadParams{AeadParams: params},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), dec.GetMetadata().GetKeyVersion())
}

// TestSmoke_ResponseFields_policyVersions checks a policy's version and
// times, and that expected_version guards an update.
func TestSmoke_ResponseFields_policyVersions(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	doc := providerRulePolicy(t, []string{aeadTemplate}, []string{"create_key"}, nil)

	created, err := h.PolicyHandler.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{Name: "p", PolicyDocument: doc})
	require.NoError(t, err)
	require.Equal(t, int64(1), created.GetVersion())

	first, err := h.PolicyHandler.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: "p"})
	require.NoError(t, err)
	require.Equal(t, "json", first.GetFormat())
	require.Equal(t, int64(1), first.GetVersion())
	require.NotNil(t, first.GetCreatedAt())
	require.True(t, proto.Equal(first.GetCreatedAt(), first.GetUpdatedAt()))

	_, err = h.PolicyHandler.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: "p", PolicyDocument: doc, ExpectedVersion: 2,
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "a stale expected_version is refused")

	updated, err := h.PolicyHandler.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: "p", PolicyDocument: doc, ExpectedVersion: 1,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), updated.GetVersion())

	second, err := h.PolicyHandler.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: "p"})
	require.NoError(t, err)
	require.Equal(t, int64(2), second.GetVersion())
	require.True(t, proto.Equal(first.GetCreatedAt(), second.GetCreatedAt()), "an update keeps the create time")
	require.False(t, second.GetUpdatedAt().AsTime().Before(first.GetUpdatedAt().AsTime()))
}

// TestSmoke_ResponseFields_providers checks the provider descriptions the
// real backends give, and what ValidateKeyOperation derives from them.
func TestSmoke_ResponseFields_providers(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	for _, id := range []string{"software", "openssl"} {
		resp, err := h.ProviderHandler.GetProvider(ctx, &servicespb.GetProviderRequest{ProviderId: id})
		require.NoError(t, err)
		info := resp.GetProvider()
		require.NotEqual(t, id, info.GetDisplayName(), "%s has a human-readable name", id)
		require.NotEmpty(t, info.GetDescription(), id)
		require.Equal(t, typespb.ProviderType_PROVIDER_TYPE_SOFTWARE, info.GetProviderType(), id)
		require.NotEmpty(t, info.GetDefaultImplementation().GetImplementationLanguage(), id)
	}

	pol := seedPolicy(t, ctx, h, "validate", []string{aeadTemplate}, []string{"create_key", "read_key"})
	keyName := createAEADKey(t, ctx, h, "validate-key", pol)
	resp, err := h.KeysHandler.ValidateKeyOperation(ctx, &messagespb.ValidateKeyOperationRequest{
		Name: keyName,
		Intent: &messagespb.ValidateKeyOperationRequest_Migrate{Migrate: &messagespb.ValidateMigrateIntent{
			Target: &messagespb.ValidateMigrateIntent_TargetInstanceId{TargetInstanceId: "openssl"},
		}},
	})
	require.NoError(t, err)
	require.Equal(t, typespb.ProviderType_PROVIDER_TYPE_SOFTWARE, resp.GetCurrentState().GetProviderType())
	for _, o := range resp.GetOptions() {
		require.True(t, o.GetComplexityLevel() >= 1 && o.GetComplexityLevel() <= 5,
			"%s: complexity %d outside 1..5", o.GetStrategy(), o.GetComplexityLevel())
	}
}
