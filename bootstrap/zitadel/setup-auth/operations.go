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
func citiusOperations() []admin.Operation {
	op := func(svc, method, perm, display string) admin.Operation {
		return admin.Operation{
			Method:      methodPrefix + svc + "/" + method,
			Permission:  perm,
			DisplayName: display,
		}
	}
	const crypto = "CryptoService"
	const discovery = "AlgorithmDiscoveryService"
	const provider = "ProviderService"

	return []admin.Operation{
		// ---- CryptoService: key lifecycle ---------------------------------
		op(crypto, "CreateKey", permKeysCreate, "Create key"),
		op(crypto, "DeleteKey", permKeysCreate, "Delete key"),
		op(crypto, "ImportKey", permKeysCreate, "Import key"),
		op(crypto, "RotateKey", permKeysRotate, "Rotate key material"),
		op(crypto, "TransformKey", permKeysRotate, "Transform key"),
		op(crypto, "MigrateKey", permKeysRotate, "Migrate key to new provider"),
		op(crypto, "UpdateKeyPolicy", permKeysUpdatePolicy, "Rebind key to a different crypto policy"),
		op(crypto, "ReadKey", permKeysRead, "Read key metadata"),
		op(crypto, "ListKeys", permKeysRead, "List keys"),
		op(crypto, "ValidateKeyOperation", permKeysRead, "Validate key operation"),
		op(crypto, "ExportKey", permKeysRead, "Export key (subject to policy)"),

		// ---- CryptoService: crypto-policy lifecycle -----------------------
		op(crypto, "CreateCryptoPolicy", permPolicyWrite, "Create crypto policy"),
		op(crypto, "ReadCryptoPolicy", permPolicyRead, "Read crypto policy"),
		op(crypto, "DeleteCryptoPolicy", permPolicyWrite, "Delete crypto policy"),
		op(crypto, "UpdateCryptoPolicy", permPolicyWrite, "Update crypto policy"),
		op(crypto, "ListCryptoPolicies", permPolicyRead, "List crypto policies"),
		op(crypto, "EvaluatePolicy", permPolicyRead, "Evaluate crypto policy"),
		op(crypto, "BatchEvaluatePolicy", permPolicyRead, "Evaluate crypto policy (batch)"),

		// ---- CryptoService: encrypt --------------------------------------
		op(crypto, "Encrypt", permCryptoEncrypt, "Encrypt (one-shot)"),
		op(crypto, "EncryptInit", permCryptoEncrypt, "Encrypt (multi-part init)"),
		op(crypto, "EncryptUpdate", permCryptoEncrypt, "Encrypt (multi-part update)"),
		op(crypto, "EncryptFinal", permCryptoEncrypt, "Encrypt (multi-part final)"),
		op(crypto, "EncryptMessage", permCryptoEncrypt, "Encrypt message"),
		op(crypto, "EncryptMessageInit", permCryptoEncrypt, "Encrypt message (init)"),
		op(crypto, "EncryptMessageBegin", permCryptoEncrypt, "Encrypt message (begin)"),
		op(crypto, "EncryptMessageNext", permCryptoEncrypt, "Encrypt message (next)"),
		op(crypto, "EncryptMessageFinal", permCryptoEncrypt, "Encrypt message (final)"),

		// ---- CryptoService: decrypt --------------------------------------
		op(crypto, "Decrypt", permCryptoDecrypt, "Decrypt (one-shot)"),
		op(crypto, "DecryptInit", permCryptoDecrypt, "Decrypt (multi-part init)"),
		op(crypto, "DecryptUpdate", permCryptoDecrypt, "Decrypt (multi-part update)"),
		op(crypto, "DecryptFinal", permCryptoDecrypt, "Decrypt (multi-part final)"),
		op(crypto, "DecryptMessage", permCryptoDecrypt, "Decrypt message"),
		op(crypto, "DecryptMessageInit", permCryptoDecrypt, "Decrypt message (init)"),
		op(crypto, "DecryptMessageBegin", permCryptoDecrypt, "Decrypt message (begin)"),
		op(crypto, "DecryptMessageNext", permCryptoDecrypt, "Decrypt message (next)"),
		op(crypto, "DecryptMessageFinal", permCryptoDecrypt, "Decrypt message (final)"),

		// ---- CryptoService: sign -----------------------------------------
		op(crypto, "Sign", permCryptoSign, "Sign (one-shot)"),
		op(crypto, "DigestSign", permCryptoSign, "Digest-and-sign"),
		op(crypto, "SignInit", permCryptoSign, "Sign (multi-part init)"),
		op(crypto, "SignUpdate", permCryptoSign, "Sign (multi-part update)"),
		op(crypto, "SignFinal", permCryptoSign, "Sign (multi-part final)"),
		op(crypto, "SignMessage", permCryptoSign, "Sign message"),
		op(crypto, "SignMessageInit", permCryptoSign, "Sign message (init)"),
		op(crypto, "SignMessageBegin", permCryptoSign, "Sign message (begin)"),
		op(crypto, "SignMessageNext", permCryptoSign, "Sign message (next)"),
		op(crypto, "SignMessageFinal", permCryptoSign, "Sign message (final)"),

		// ---- CryptoService: verify ---------------------------------------
		op(crypto, "Verify", permCryptoVerify, "Verify (one-shot)"),
		op(crypto, "DigestVerify", permCryptoVerify, "Digest-and-verify"),
		op(crypto, "VerifyInit", permCryptoVerify, "Verify (multi-part init)"),
		op(crypto, "VerifyUpdate", permCryptoVerify, "Verify (multi-part update)"),
		op(crypto, "VerifyFinal", permCryptoVerify, "Verify (multi-part final)"),
		op(crypto, "VerifyMessage", permCryptoVerify, "Verify message"),
		op(crypto, "VerifyMessageInit", permCryptoVerify, "Verify message (init)"),
		op(crypto, "VerifyMessageBegin", permCryptoVerify, "Verify message (begin)"),
		op(crypto, "VerifyMessageNext", permCryptoVerify, "Verify message (next)"),
		op(crypto, "VerifyMessageFinal", permCryptoVerify, "Verify message (final)"),

		// ---- CryptoService: digest / xof / mac / random / wrap / kdf -----
		op(crypto, "Digest", permCryptoMisc, "Digest"),
		op(crypto, "DigestInit", permCryptoMisc, "Digest (init)"),
		op(crypto, "DigestUpdate", permCryptoMisc, "Digest (update)"),
		op(crypto, "DigestFinal", permCryptoMisc, "Digest (final)"),
		op(crypto, "DigestKey", permCryptoMisc, "Digest key"),
		op(crypto, "Xof", permCryptoMisc, "XOF"),
		op(crypto, "XofInit", permCryptoMisc, "XOF (init)"),
		op(crypto, "XofUpdate", permCryptoMisc, "XOF (update)"),
		op(crypto, "XofFinal", permCryptoMisc, "XOF (final)"),
		op(crypto, "DigestEncryptUpdate", permCryptoMisc, "Digest-encrypt update"),
		op(crypto, "DecryptDigestUpdate", permCryptoMisc, "Decrypt-digest update"),
		op(crypto, "SignEncryptUpdate", permCryptoMisc, "Sign-encrypt update"),
		op(crypto, "DecryptVerifyUpdate", permCryptoMisc, "Decrypt-verify update"),
		op(crypto, "WrapKey", permCryptoMisc, "Wrap key"),
		op(crypto, "UnwrapKey", permCryptoMisc, "Unwrap key"),
		op(crypto, "DeriveKey", permCryptoMisc, "Derive key"),
		op(crypto, "KeyAgreement", permCryptoMisc, "Key agreement"),
		op(crypto, "EncapsulateKey", permCryptoMisc, "Encapsulate key (KEM)"),
		op(crypto, "DecapsulateKey", permCryptoMisc, "Decapsulate key (KEM)"),
		op(crypto, "GenerateRandom", permCryptoMisc, "Generate random"),
		op(crypto, "SeedRandom", permCryptoMisc, "Seed random"),
		op(crypto, "GenerateMAC", permCryptoMisc, "Generate MAC"),
		op(crypto, "VerifyMAC", permCryptoMisc, "Verify MAC"),

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
