package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/service"
	"github.com/stretchr/testify/require"
)

// seedRetainPolicy allows key creation and the given crypto operations for
// templateIDs, so that both the source and target of a retain-mode transform
// are permitted.
func seedRetainPolicy(t *testing.T, ctx context.Context, pol policy.Engine, name string, templateIDs []string, ops ...core.Operation) {
	t.Helper()
	keyOps := []string{string(core.OperationCreateKey)}
	for _, op := range ops {
		keyOps = append(keyOps, string(op))
	}
	rulesJSON, err := json.Marshal(&policy.Rules{
		Version:           "1",
		AllowedTemplates:  templateIDs,
		AllowedOperations: &policy.OperationRule{KeyOperations: keyOps},
	})
	require.NoError(t, err)
	_, err = pol.CreatePolicy(ctx, policy.NewPolicy("pol_"+name, name, rulesJSON))
	require.NoError(t, err)
}

// TestTransformKey_retainBytes_ECDSA proves that retain mode stores the
// version-1 payload byte-for-byte under the target template and scope, and
// leaves version 1 untouched.
func TestTransformKey_retainBytes_ECDSA(t *testing.T) {
	ctx := context.Background()
	keyOrch, keys, _, pol, _ := setupOrchestratorFull(t)
	const (
		source = "ecdsa-p256-sha256-der"
		target = "ecdsa-p256-prehashed-der"
	)
	seedRetainPolicy(t, ctx, pol, "retain-ecdsa", []string{source, target})

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "retain-ecdsa",
		TemplateID:         source,
		PolicyID:           "retain-ecdsa",
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
	})
	require.NoError(t, err)
	v1Before, err := keys.GetVersion(ctx, created.KeyID, 1)
	require.NoError(t, err)

	md, err := keyOrch.TransformKey(ctx, service.TransformKeySpec{
		KeyName:            created.Name,
		TemplateID:         target,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed),
		RetainBytes:        true,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), md.Version)
	require.Equal(t, target, md.TemplateID)
	require.Equal(t, created.Provider, md.Provider)
	require.Equal(t, created.KeyID, md.KeyID)
	require.Equal(t, created.Primitive, md.Primitive)
	require.Equal(t, core.ScopeSignaturePrehashed, md.ScopeSpec.Scope)

	v1, err := keys.GetVersion(ctx, created.KeyID, 1)
	require.NoError(t, err)
	v2, err := keys.GetVersion(ctx, created.KeyID, 2)
	require.NoError(t, err)
	require.Equal(t, v1Before.GetKeyMaterial(), v2.GetKeyMaterial(), "retained payload must be byte-for-byte identical")
	require.Equal(t, v1Before.GetKeyMaterial(), v1.GetKeyMaterial())
	require.Equal(t, source, v1.GetTemplateId())
	require.Equal(t, v1Before.GetScopeSpecification(), v1.GetScopeSpecification())
}

// TestTransformKey_retainBytes_ECDSADigestSign proves that the retained
// prehashed version is usable for digest operations and shares the key pair
// with version 1: a version-1 full-message ECDSA-P256-SHA256 signature
// verifies as a digest signature over SHA-256(message) under version 2.
func TestTransformKey_retainBytes_ECDSADigestSign(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	const (
		source = "ecdsa-p256-sha256-der"
		target = "ecdsa-p256-prehashed-der"
	)
	seedRetainPolicy(t, ctx, pol, "retain-ecdsa-digest", []string{source, target},
		core.OperationSign, core.OperationVerify, core.OperationDigestSign, core.OperationDigestVerify)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "retain-ecdsa-digest",
		TemplateID:         source,
		PolicyID:           "retain-ecdsa-digest",
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
	})
	require.NoError(t, err)

	message := []byte("signed before transformation")
	digest := sha256.Sum256(message)
	noContext := crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
	v1Sig, err := ops.Sign(ctx, crypto.SignRequest{KeyName: created.Name, Payload: message, SignatureScopeFields: noContext})
	require.NoError(t, err)
	require.Equal(t, uint32(1), v1Sig.KeyVersion)

	_, err = keyOrch.TransformKey(ctx, service.TransformKeySpec{
		KeyName:            created.Name,
		TemplateID:         target,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed),
		RetainBytes:        true,
	})
	require.NoError(t, err)

	digestVerify := func(sig crypto.SignResult, version uint32) bool {
		t.Helper()
		result, verifyErr := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
			KeyName:              created.Name,
			KeyVersion:           version,
			Digest:               digest[:],
			Signature:            sig.Signature,
			HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			Output:               sig.Output,
			SignatureScopeFields: noContext,
		})
		require.NoError(t, verifyErr)
		return result.Valid
	}

	require.True(t, digestVerify(v1Sig, 2), "version-1 signature must verify under the retained version-2 key")

	v2Sig, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              created.Name,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: noContext,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), v2Sig.KeyVersion)
	require.True(t, digestVerify(v2Sig, 2))

	// Version 1 keeps its original template and scope: full-message Verify
	// works, and digest operations are refused for its standard scope.
	verified, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              created.Name,
		KeyVersion:           1,
		Payload:              message,
		Signature:            v2Sig.Signature,
		Output:               v2Sig.Output,
		SignatureScopeFields: noContext,
	})
	require.NoError(t, err)
	require.True(t, verified.Valid, "version-2 digest signature must verify as a full-message signature under version 1")

	_, err = ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
		KeyName:              created.Name,
		KeyVersion:           1,
		Digest:               digest[:],
		Signature:            v1Sig.Signature,
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Output:               v1Sig.Output,
		SignatureScopeFields: noContext,
	})
	require.True(t, errors.IsInvalidArgument(err), "digest ops on a standard-scoped version must be refused: %v", err)
}

// TestTransformKey_retainBytes_RSA proves that a retained RSA-2048 key signs
// under the target PKCS#1 v1.5 template, while version 1 still verifies its
// RSA-PSS signature.
func TestTransformKey_retainBytes_RSA(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	const (
		source = "rsa-pss-sha256-mgf1-32-2048"
		target = "rsa-pkcs1v15-sha256-2048"
	)
	seedRetainPolicy(t, ctx, pol, "retain-rsa", []string{source, target},
		core.OperationSign, core.OperationVerify)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "retain-rsa",
		TemplateID:         source,
		PolicyID:           "retain-rsa",
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
	})
	require.NoError(t, err)

	message := []byte("signed across RSA schemes")
	noContext := crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
	v1Sig, err := ops.Sign(ctx, crypto.SignRequest{KeyName: created.Name, Payload: message, SignatureScopeFields: noContext})
	require.NoError(t, err)
	require.Equal(t, uint32(1), v1Sig.KeyVersion)

	md, err := keyOrch.TransformKey(ctx, service.TransformKeySpec{
		KeyName:            created.Name,
		TemplateID:         target,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
		RetainBytes:        true,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), md.Version)
	require.Equal(t, target, md.TemplateID)

	v2Sig, err := ops.Sign(ctx, crypto.SignRequest{KeyName: created.Name, Payload: message, SignatureScopeFields: noContext})
	require.NoError(t, err)
	require.Equal(t, uint32(2), v2Sig.KeyVersion)
	require.Equal(t, target, v2Sig.Algorithm)

	for _, sig := range []crypto.SignResult{v1Sig, v2Sig} {
		verified, verifyErr := ops.Verify(ctx, crypto.VerifyRequest{
			KeyName:              created.Name,
			KeyVersion:           sig.KeyVersion,
			Payload:              message,
			Signature:            sig.Signature,
			Output:               sig.Output,
			SignatureScopeFields: noContext,
		})
		require.NoError(t, verifyErr)
		require.True(t, verified.Valid, "version %d signature must verify", sig.KeyVersion)
	}
}

// TestTransformKey_retainBytes_AES proves that an AES-256-GCM key can be
// retained as AES-256-CBC: both versions decrypt their own ciphertexts.
func TestTransformKey_retainBytes_AES(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	const (
		source = "aes-256-gcm-128-96"
		target = "aes-256-cbc-pkcs7-128"
	)
	seedRetainPolicy(t, ctx, pol, "retain-aes", []string{source, target},
		core.OperationEncrypt, core.OperationDecrypt)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "retain-aes",
		TemplateID:         source,
		PolicyID:           "retain-aes",
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeAeadStandard),
	})
	require.NoError(t, err)

	aead := crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}}
	block := crypto.EncryptionScopeFields{NoParams: &types.NoParams{}}
	v1Plain := []byte("encrypted before transformation")
	v1Enc, err := ops.Encrypt(ctx, crypto.EncryptRequest{KeyName: created.Name, Plaintext: v1Plain, EncryptionScopeFields: aead})
	require.NoError(t, err)

	md, err := keyOrch.TransformKey(ctx, service.TransformKeySpec{
		KeyName:            created.Name,
		TemplateID:         target,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSymmetricCipherBlock),
		RetainBytes:        true,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), md.Version)
	require.Equal(t, target, md.TemplateID)

	v2Plain := []byte("encrypted after transformation")
	v2Enc, err := ops.Encrypt(ctx, crypto.EncryptRequest{KeyName: created.Name, Plaintext: v2Plain, EncryptionScopeFields: block})
	require.NoError(t, err)
	require.Equal(t, uint32(2), v2Enc.KeyVersion)
	v2Dec, err := ops.Decrypt(ctx, crypto.DecryptRequest{
		KeyName: created.Name, KeyVersion: 2, Ciphertext: v2Enc.Ciphertext,
		Output: v2Enc.Output, EncryptionScopeFields: block,
	})
	require.NoError(t, err)
	require.Equal(t, v2Plain, v2Dec.Plaintext)

	v1Dec, err := ops.Decrypt(ctx, crypto.DecryptRequest{
		KeyName: created.Name, KeyVersion: 1, Ciphertext: v1Enc.Ciphertext,
		Output: v1Enc.Output, EncryptionScopeFields: aead,
	})
	require.NoError(t, err)
	require.Equal(t, v1Plain, v1Dec.Plaintext)
}

func TestTransformKey_retainBytes_rejectsIncompatibleMaterial(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		sourceScope core.Scope
		target      string
		targetScope core.Scope
	}{
		{"ECDSA P-256 to P-384", "ecdsa-p256-sha256-der", core.ScopeSignatureStandard, "ecdsa-p384-sha384-der", core.ScopeSignatureStandard},
		{"ECDSA to RSA", "ecdsa-p256-sha256-der", core.ScopeSignatureStandard, "rsa-pss-sha256-mgf1-32-2048", core.ScopeSignatureStandard},
		{"AES-128 to AES-256", "aes-128-gcm-128-96", core.ScopeAeadStandard, "aes-256-gcm-128-96", core.ScopeAeadStandard},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, keyOrch, pol := setupCryptoOrchestratorFull(t)
			seedRetainPolicy(t, ctx, pol, "retain-reject", []string{tt.source, tt.target})
			created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
				Name:               "retain-reject",
				TemplateID:         tt.source,
				PolicyID:           "retain-reject",
				ScopeSpecification: scopeSpecWithScope(t, tt.sourceScope),
			})
			require.NoError(t, err)

			_, err = keyOrch.TransformKey(ctx, service.TransformKeySpec{
				KeyName:            created.Name,
				TemplateID:         tt.target,
				ScopeSpecification: scopeSpecWithScope(t, tt.targetScope),
				RetainBytes:        true,
			})
			require.Error(t, err)
			var coreErr *errors.Error
			require.True(t, errors.As(err, &coreErr))
			require.Equal(t, errors.CodeFailedPrecondition, coreErr.Code, err.Error())

			current, err := keyOrch.ReadKey(ctx, created.Name, 0)
			require.NoError(t, err)
			require.Equal(t, uint32(1), current.Version, "rejected transform must not add a version")
		})
	}
}
