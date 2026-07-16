package auth

import (
	"context"

	zauth "github.com/agile-crypto/zitadel-grpc-auth"
)

// PolicyFunc re-exports the upstream type so handlers and tests do not
// need to import the third-party module directly.
type PolicyFunc = zauth.PolicyFunc

// RegisteredMethods returns the sorted list of fully-qualified gRPC
// methods that have an entry in the policy registry. It exists for the
// reflection-based completeness test in registry_test.go and for tools
// that need to enumerate the protected surface (e.g. docs generation).
func RegisteredMethods() []string {
	reg := policyRegistry()
	out := make([]string, 0, len(reg))
	for m := range reg {
		out = append(out, m)
	}
	return out
}

// requirePerm builds a PolicyFunc that asserts permission p is present
// in the urn:citius:permissions claim. It is the building block of every
// entry in policyRegistry.
func requirePerm(p string) PolicyFunc {
	return func(_ context.Context, _ string, c *zauth.Claims) error {
		if c == nil || !c.HasStringInSlice(ClaimPermissions, p) {
			return zauth.Forbidden("missing permission %q", p)
		}
		return nil
	}
}

// policyRegistry returns the per-method policy map fed to
// server.Config.Policies. It is **default-deny**: any RPC not present
// here is rejected by the upstream interceptor (unless explicitly listed
// in PublicMethods, which Citius leaves empty today).
//
// A reflection test asserts every method on every registered gRPC service
// has an entry — adding a new RPC in proto/services/*.proto without
// adding a row here is a build-time test failure, not a runtime hole.
//
// Authorization decomposes into two layers:
//
//  1. Per-method permission gate (this map).
//  2. Per-resource glob scoping (AuthorizeKey / AuthorizePolicy, called
//     from internal/grpc/handler.go).
//
// The two layers compose: a caller granted citius:crypto:encrypt but
// scoped to "itest-*" keys passes layer 1 for any Encrypt call but is
// rejected at layer 2 for "prod-*" keys.
func policyRegistry() map[string][]PolicyFunc {
	keysCreate := []PolicyFunc{requirePerm(PermKeysCreate)}
	keysRotate := []PolicyFunc{requirePerm(PermKeysRotate)}
	keysUpdatePolicy := []PolicyFunc{requirePerm(PermKeysUpdatePolicy)}
	keysRead := []PolicyFunc{requirePerm(PermKeysRead)}

	cryptoEncrypt := []PolicyFunc{requirePerm(PermCryptoEncrypt)}
	cryptoDecrypt := []PolicyFunc{requirePerm(PermCryptoDecrypt)}
	cryptoSign := []PolicyFunc{requirePerm(PermCryptoSign)}
	cryptoVerify := []PolicyFunc{requirePerm(PermCryptoVerify)}
	cryptoMisc := []PolicyFunc{requirePerm(PermCryptoMisc)}

	policyRead := []PolicyFunc{requirePerm(PermPolicyRead)}
	policyWrite := []PolicyFunc{requirePerm(PermPolicyWrite)}

	discoveryRead := []PolicyFunc{requirePerm(PermDiscoveryRead)}

	providerRead := []PolicyFunc{requirePerm(PermProviderRead)}
	providerWrite := []PolicyFunc{requirePerm(PermProviderWrite)}

	return map[string][]PolicyFunc{
		// KeyManagementService — key lifecycle.
		MethodCreateKey:            keysCreate,
		MethodDeleteKey:            keysCreate,
		MethodImportKey:            keysCreate,
		MethodRotateKey:            keysRotate,
		MethodTransformKey:         keysRotate,
		MethodMigrateKey:           keysRotate,
		MethodUpdateKeyPolicy:      keysUpdatePolicy,
		MethodReadKey:              keysRead,
		MethodListKeys:             keysRead,
		MethodValidateKeyOperation: keysRead,
		MethodExportKey:            keysRead,

		// CryptoPolicyService — crypto-policy lifecycle.
		MethodCreateCryptoPolicy:  policyWrite,
		MethodReadCryptoPolicy:    policyRead,
		MethodDeleteCryptoPolicy:  policyWrite,
		MethodUpdateCryptoPolicy:  policyWrite,
		MethodListCryptoPolicies:  policyRead,
		MethodEvaluatePolicy:      policyRead,
		MethodBatchEvaluatePolicy: policyRead,

		// Encrypt operations.
		MethodEncrypt:             cryptoEncrypt,
		MethodEncryptInit:         cryptoEncrypt,
		MethodEncryptUpdate:       cryptoEncrypt,
		MethodEncryptFinal:        cryptoEncrypt,
		MethodEncryptMessage:      cryptoEncrypt,
		MethodEncryptMessageInit:  cryptoEncrypt,
		MethodEncryptMessageBegin: cryptoEncrypt,
		MethodEncryptMessageNext:  cryptoEncrypt,
		MethodEncryptMessageFinal: cryptoEncrypt,

		// Decrypt operations.
		MethodDecrypt:             cryptoDecrypt,
		MethodDecryptInit:         cryptoDecrypt,
		MethodDecryptUpdate:       cryptoDecrypt,
		MethodDecryptFinal:        cryptoDecrypt,
		MethodDecryptMessage:      cryptoDecrypt,
		MethodDecryptMessageInit:  cryptoDecrypt,
		MethodDecryptMessageBegin: cryptoDecrypt,
		MethodDecryptMessageNext:  cryptoDecrypt,
		MethodDecryptMessageFinal: cryptoDecrypt,

		// Sign operations.
		MethodSign:             cryptoSign,
		MethodDigestSign:       cryptoSign,
		MethodSignInit:         cryptoSign,
		MethodSignUpdate:       cryptoSign,
		MethodSignFinal:        cryptoSign,
		MethodSignMessage:      cryptoSign,
		MethodSignMessageInit:  cryptoSign,
		MethodSignMessageBegin: cryptoSign,
		MethodSignMessageNext:  cryptoSign,
		MethodSignMessageFinal: cryptoSign,

		// Verify operations.
		MethodVerify:             cryptoVerify,
		MethodDigestVerify:       cryptoVerify,
		MethodVerifyInit:         cryptoVerify,
		MethodVerifyUpdate:       cryptoVerify,
		MethodVerifyFinal:        cryptoVerify,
		MethodVerifyMessage:      cryptoVerify,
		MethodVerifyMessageInit:  cryptoVerify,
		MethodVerifyMessageBegin: cryptoVerify,
		MethodVerifyMessageNext:  cryptoVerify,
		MethodVerifyMessageFinal: cryptoVerify,

		// Other crypto-related operations that don't fit the above buckets.
		MethodDigest:              cryptoMisc,
		MethodDigestInit:          cryptoMisc,
		MethodDigestUpdate:        cryptoMisc,
		MethodDigestFinal:         cryptoMisc,
		MethodDigestKey:           cryptoMisc,
		MethodXof:                 cryptoMisc,
		MethodXofInit:             cryptoMisc,
		MethodXofUpdate:           cryptoMisc,
		MethodXofFinal:            cryptoMisc,
		MethodDigestEncryptUpdate: cryptoMisc,
		MethodDecryptDigestUpdate: cryptoMisc,
		MethodSignEncryptUpdate:   cryptoMisc,
		MethodDecryptVerifyUpdate: cryptoMisc,
		MethodGenerateRandom:      cryptoMisc,
		MethodSeedRandom:          cryptoMisc,
		MethodGenerateMAC:         cryptoMisc,
		MethodVerifyMAC:           cryptoMisc,

		// KeyEstablishmentService — wrap / unwrap / derive etc.
		MethodWrapKey:        cryptoMisc,
		MethodUnwrapKey:      cryptoMisc,
		MethodDeriveKey:      cryptoMisc,
		MethodKeyAgreement:   cryptoMisc,
		MethodEncapsulateKey: cryptoMisc,
		MethodDecapsulateKey: cryptoMisc,

		// AlgorithmDiscoveryService.
		MethodListTemplates: discoveryRead,
		MethodGetTemplate:   discoveryRead,
		MethodListScopes:    discoveryRead,

		// ProviderService.
		MethodListProviders:            providerRead,
		MethodGetProvider:              providerRead,
		MethodMatchProviders:           providerRead,
		MethodListProviderInstances:    providerRead,
		MethodGetProviderInstance:      providerRead,
		MethodRegisterProviderInstance: providerWrite,
		MethodUpdateProviderInstance:   providerWrite,
		MethodDeleteProviderInstance:   providerWrite,
	}
}
