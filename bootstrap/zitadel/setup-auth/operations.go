package main

import "github.com/agile-crypto/zitadel-grpc-auth/admin"

// methodPrefix is the gRPC FQN prefix for all Citius services. It must
// match the proto package name in proto/services/*.proto exactly — the
// reflective completeness test in internal/auth verifies this against
// the generated *_grpc.pb.go FullMethodName constants at build time.
const methodPrefix = "/caas.crypto.v1."

// Permission keys. Mirrored verbatim in internal/auth/permissions.go;
// the two are kept in sync by hand and asserted equal by an integration test.
//
// Key lifecycle is intentionally split across three permissions:
//
//   - permKeysCreate       — create / delete / import (slot management)
//   - permKeysRotate       — rotate / transform / migrate (key material)
//   - permKeysUpdatePolicy — rebind a key to a different crypto policy
//
// Read, encrypt, decrypt, sign, verify, policy-CRUD, discovery, and
// provider operations are each their own permission.
const (
	permKeysCreate       = "citius:keys:create"
	permKeysRotate       = "citius:keys:rotate"
	permKeysUpdatePolicy = "citius:keys:update-policy"
	permKeysRead         = "citius:keys:read"

	permCryptoEncrypt = "citius:crypto:encrypt"
	permCryptoDecrypt = "citius:crypto:decrypt"
	permCryptoSign    = "citius:crypto:sign"
	permCryptoVerify  = "citius:crypto:verify"
	permCryptoMisc    = "citius:crypto:misc" // digest / random / MAC / wrap / KDF / KEM

	permPolicyRead  = "citius:policy:read"
	permPolicyWrite = "citius:policy:write"

	permDiscoveryRead = "citius:discovery:read"

	permProviderRead  = "citius:provider:read"
	permProviderWrite = "citius:provider:write"
)

// citiusOperations returns one admin.Operation per Citius gRPC RPC.
// The list is the source of truth for the Zitadel project-role catalog.
// Adding an RPC to proto/services/*.proto requires adding an entry here
// AND a corresponding entry in internal/auth/policies.go.
// TestOperationsMatchServerPolicy checks that both list the same method
// paths with the same permission.
func citiusOperations() []admin.Operation {
	op := func(svc, method, perm, display string) admin.Operation {
		return admin.Operation{
			Method:      methodPrefix + svc + "/" + method,
			Permission:  perm,
			DisplayName: display,
		}
	}
	const keys = "KeyManagementService"
	const policy = "CryptoPolicyService"
	const crypto = "CryptoService"
	const streaming = "StreamingCryptoService"
	const establishment = "KeyEstablishmentService"
	const discovery = "AlgorithmDiscoveryService"
	const provider = "ProviderService"

	return []admin.Operation{
		// ---- KeyManagementService ----------------------------------------
		op(keys, "CreateKey", permKeysCreate, "Create key"),
		op(keys, "DeleteKey", permKeysCreate, "Delete key"),
		op(keys, "ImportKey", permKeysCreate, "Import key"),
		op(keys, "RotateKey", permKeysRotate, "Rotate key material"),
		op(keys, "TransformKey", permKeysRotate, "Transform key"),
		op(keys, "UpdateKeyState", permKeysRotate, "Update key state"),
		op(keys, "MigrateKey", permKeysRotate, "Migrate key to new provider"),
		op(keys, "UpdateKeyPolicy", permKeysUpdatePolicy, "Rebind key to a different crypto policy"),
		op(keys, "ReadKey", permKeysRead, "Read key metadata"),
		op(keys, "ListKeys", permKeysRead, "List keys"),
		op(keys, "ValidateKeyOperation", permKeysRead, "Validate key operation"),
		op(keys, "ExportKey", permKeysRead, "Export key (subject to policy)"),

		// ---- CryptoPolicyService -----------------------------------------
		op(policy, "CreateCryptoPolicy", permPolicyWrite, "Create crypto policy"),
		op(policy, "ReadCryptoPolicy", permPolicyRead, "Read crypto policy"),
		op(policy, "DeleteCryptoPolicy", permPolicyWrite, "Delete crypto policy"),
		op(policy, "UpdateCryptoPolicy", permPolicyWrite, "Update crypto policy"),
		op(policy, "ListCryptoPolicies", permPolicyRead, "List crypto policies"),
		op(policy, "EvaluatePolicy", permPolicyRead, "Evaluate crypto policy"),
		op(policy, "BatchEvaluatePolicy", permPolicyRead, "Evaluate crypto policy (batch)"),

		// ---- CryptoService -----------------------------------------------
		op(crypto, "Encrypt", permCryptoEncrypt, "Encrypt (one-shot)"),
		op(crypto, "Decrypt", permCryptoDecrypt, "Decrypt (one-shot)"),
		op(crypto, "Sign", permCryptoSign, "Sign (one-shot)"),
		op(crypto, "Verify", permCryptoVerify, "Verify (one-shot)"),
		op(crypto, "Digest", permCryptoMisc, "Digest"),
		op(crypto, "Xof", permCryptoMisc, "XOF"),
		op(crypto, "DigestSign", permCryptoSign, "Digest-and-sign"),
		op(crypto, "DigestVerify", permCryptoVerify, "Digest-and-verify"),
		op(crypto, "GenerateRandom", permCryptoMisc, "Generate random"),
		op(crypto, "SeedRandom", permCryptoMisc, "Seed random"),
		op(crypto, "GenerateMAC", permCryptoMisc, "Generate MAC"),
		op(crypto, "VerifyMAC", permCryptoMisc, "Verify MAC"),

		// ---- StreamingCryptoService --------------------------------------
		op(streaming, "EncryptInit", permCryptoEncrypt, "Encrypt (multi-part init)"),
		op(streaming, "EncryptUpdate", permCryptoEncrypt, "Encrypt (multi-part update)"),
		op(streaming, "EncryptFinal", permCryptoEncrypt, "Encrypt (multi-part final)"),
		op(streaming, "EncryptMessage", permCryptoEncrypt, "Encrypt message"),
		op(streaming, "EncryptMessageInit", permCryptoEncrypt, "Encrypt message (init)"),
		op(streaming, "EncryptMessageBegin", permCryptoEncrypt, "Encrypt message (begin)"),
		op(streaming, "EncryptMessageNext", permCryptoEncrypt, "Encrypt message (next)"),
		op(streaming, "EncryptMessageFinal", permCryptoEncrypt, "Encrypt message (final)"),
		op(streaming, "DecryptInit", permCryptoDecrypt, "Decrypt (multi-part init)"),
		op(streaming, "DecryptUpdate", permCryptoDecrypt, "Decrypt (multi-part update)"),
		op(streaming, "DecryptFinal", permCryptoDecrypt, "Decrypt (multi-part final)"),
		op(streaming, "DecryptMessage", permCryptoDecrypt, "Decrypt message"),
		op(streaming, "DecryptMessageInit", permCryptoDecrypt, "Decrypt message (init)"),
		op(streaming, "DecryptMessageBegin", permCryptoDecrypt, "Decrypt message (begin)"),
		op(streaming, "DecryptMessageNext", permCryptoDecrypt, "Decrypt message (next)"),
		op(streaming, "DecryptMessageFinal", permCryptoDecrypt, "Decrypt message (final)"),
		op(streaming, "SignInit", permCryptoSign, "Sign (multi-part init)"),
		op(streaming, "SignUpdate", permCryptoSign, "Sign (multi-part update)"),
		op(streaming, "SignFinal", permCryptoSign, "Sign (multi-part final)"),
		op(streaming, "SignMessage", permCryptoSign, "Sign message"),
		op(streaming, "SignMessageInit", permCryptoSign, "Sign message (init)"),
		op(streaming, "SignMessageBegin", permCryptoSign, "Sign message (begin)"),
		op(streaming, "SignMessageNext", permCryptoSign, "Sign message (next)"),
		op(streaming, "SignMessageFinal", permCryptoSign, "Sign message (final)"),
		op(streaming, "VerifyInit", permCryptoVerify, "Verify (multi-part init)"),
		op(streaming, "VerifyUpdate", permCryptoVerify, "Verify (multi-part update)"),
		op(streaming, "VerifyFinal", permCryptoVerify, "Verify (multi-part final)"),
		op(streaming, "VerifyMessage", permCryptoVerify, "Verify message"),
		op(streaming, "VerifyMessageInit", permCryptoVerify, "Verify message (init)"),
		op(streaming, "VerifyMessageBegin", permCryptoVerify, "Verify message (begin)"),
		op(streaming, "VerifyMessageNext", permCryptoVerify, "Verify message (next)"),
		op(streaming, "VerifyMessageFinal", permCryptoVerify, "Verify message (final)"),
		op(streaming, "DigestInit", permCryptoMisc, "Digest (init)"),
		op(streaming, "DigestUpdate", permCryptoMisc, "Digest (update)"),
		op(streaming, "DigestFinal", permCryptoMisc, "Digest (final)"),
		op(streaming, "DigestKey", permCryptoMisc, "Digest key"),
		op(streaming, "GenerateMACInit", permCryptoMisc, "Generate MAC (init)"),
		op(streaming, "GenerateMACUpdate", permCryptoMisc, "Generate MAC (update)"),
		op(streaming, "GenerateMACFinal", permCryptoMisc, "Generate MAC (final)"),
		op(streaming, "VerifyMACInit", permCryptoMisc, "Verify MAC (init)"),
		op(streaming, "VerifyMACUpdate", permCryptoMisc, "Verify MAC (update)"),
		op(streaming, "VerifyMACFinal", permCryptoMisc, "Verify MAC (final)"),
		op(streaming, "XofInit", permCryptoMisc, "XOF (init)"),
		op(streaming, "XofUpdate", permCryptoMisc, "XOF (update)"),
		op(streaming, "XofFinal", permCryptoMisc, "XOF (final)"),
		op(streaming, "DigestEncryptUpdate", permCryptoMisc, "Digest-encrypt update"),
		op(streaming, "DecryptDigestUpdate", permCryptoMisc, "Decrypt-digest update"),
		op(streaming, "SignEncryptUpdate", permCryptoMisc, "Sign-encrypt update"),
		op(streaming, "DecryptVerifyUpdate", permCryptoMisc, "Decrypt-verify update"),
		op(streaming, "CancelOperation", permCryptoMisc, "Cancel streaming operation"),

		// ---- KeyEstablishmentService -------------------------------------
		op(establishment, "WrapKey", permCryptoMisc, "Wrap key"),
		op(establishment, "UnwrapKey", permCryptoMisc, "Unwrap key"),
		op(establishment, "DeriveKey", permCryptoMisc, "Derive key"),
		op(establishment, "KeyAgreement", permCryptoMisc, "Key agreement"),
		op(establishment, "EncapsulateKey", permCryptoMisc, "Encapsulate key (KEM)"),
		op(establishment, "DecapsulateKey", permCryptoMisc, "Decapsulate key (KEM)"),

		// ---- AlgorithmDiscoveryService -----------------------------------
		op(discovery, "ListTemplates", permDiscoveryRead, "List algorithm templates"),
		op(discovery, "GetTemplate", permDiscoveryRead, "Get algorithm template"),
		op(discovery, "ListScopes", permDiscoveryRead, "List algorithm scopes"),

		// ---- ProviderService ---------------------------------------------
		op(provider, "ListProviders", permProviderRead, "List providers"),
		op(provider, "GetProvider", permProviderRead, "Get provider"),
		op(provider, "MatchProviders", permProviderRead, "Match providers to a template"),
		op(provider, "ListProviderInstances", permProviderRead, "List provider instances"),
		op(provider, "GetProviderInstance", permProviderRead, "Get provider instance"),
		op(provider, "RegisterProviderInstance", permProviderWrite, "Register provider instance"),
		op(provider, "UpdateProviderInstance", permProviderWrite, "Update provider instance"),
		op(provider, "DeleteProviderInstance", permProviderWrite, "Delete provider instance"),
	}
}

// allCitiusPermissions returns every permission key in the catalog,
// deduplicated. It is the grant list for the svc-admin seed user.
func allCitiusPermissions() []string {
	return []string{
		permKeysCreate, permKeysRotate, permKeysUpdatePolicy, permKeysRead,
		permCryptoEncrypt, permCryptoDecrypt, permCryptoSign, permCryptoVerify, permCryptoMisc,
		permPolicyRead, permPolicyWrite,
		permDiscoveryRead,
		permProviderRead, permProviderWrite,
	}
}
