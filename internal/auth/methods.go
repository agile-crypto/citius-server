package auth

// methodPrefix is the gRPC FQN prefix for all Citius services. It must
// match the proto package name in proto/services/*.proto. The reflective
// completeness test in policies_test.go verifies every registered method
// in this prefix exists in the policy map.
const methodPrefix = "/caas.crypto.v1."

// Fully-qualified method names. Kept as constants (rather than referenced
// directly from the generated pb.go FullMethodName variables) so that
// adding a new RPC in proto/services/*.proto without registering a
// permission here is caught by the reflective completeness test, not by
// silent default-deny at runtime.
//
// KeyManagementService — key lifecycle.
const (
	MethodCreateKey            = methodPrefix + "KeyManagementService/CreateKey"
	MethodDeleteKey            = methodPrefix + "KeyManagementService/DeleteKey"
	MethodImportKey            = methodPrefix + "KeyManagementService/ImportKey"
	MethodRotateKey            = methodPrefix + "KeyManagementService/RotateKey"
	MethodTransformKey         = methodPrefix + "KeyManagementService/TransformKey"
	MethodMigrateKey           = methodPrefix + "KeyManagementService/MigrateKey"
	MethodUpdateKeyPolicy      = methodPrefix + "KeyManagementService/UpdateKeyPolicy"
	MethodReadKey              = methodPrefix + "KeyManagementService/ReadKey"
	MethodListKeys             = methodPrefix + "KeyManagementService/ListKeys"
	MethodValidateKeyOperation = methodPrefix + "KeyManagementService/ValidateKeyOperation"
	MethodExportKey            = methodPrefix + "KeyManagementService/ExportKey"
)

// CryptoPolicyService — crypto-policy lifecycle.
const (
	MethodCreateCryptoPolicy  = methodPrefix + "CryptoPolicyService/CreateCryptoPolicy"
	MethodReadCryptoPolicy    = methodPrefix + "CryptoPolicyService/ReadCryptoPolicy"
	MethodDeleteCryptoPolicy  = methodPrefix + "CryptoPolicyService/DeleteCryptoPolicy"
	MethodUpdateCryptoPolicy  = methodPrefix + "CryptoPolicyService/UpdateCryptoPolicy"
	MethodListCryptoPolicies  = methodPrefix + "CryptoPolicyService/ListCryptoPolicies"
	MethodEvaluatePolicy      = methodPrefix + "CryptoPolicyService/EvaluatePolicy"
	MethodBatchEvaluatePolicy = methodPrefix + "CryptoPolicyService/BatchEvaluatePolicy"
)

// CryptoService — encrypt / decrypt / sign / verify (one-shot only).

const (
	MethodEncrypt        = methodPrefix + "CryptoService/Encrypt"
	MethodDecrypt        = methodPrefix + "CryptoService/Decrypt"
	MethodSign           = methodPrefix + "CryptoService/Sign"
	MethodVerify         = methodPrefix + "CryptoService/Verify"
	MethodDigest         = methodPrefix + "CryptoService/Digest"
	MethodXof            = methodPrefix + "CryptoService/Xof"
	MethodDigestSign     = methodPrefix + "CryptoService/DigestSign"
	MethodDigestVerify   = methodPrefix + "CryptoService/DigestVerify"
	MethodGenerateRandom = methodPrefix + "CryptoService/GenerateRandom"
	MethodSeedRandom     = methodPrefix + "CryptoService/SeedRandom"
	MethodGenerateMAC    = methodPrefix + "CryptoService/GenerateMAC"
	MethodVerifyMAC      = methodPrefix + "CryptoService/VerifyMAC"
)

// StreamingCryptoService — streaming encrypt / decrypt / sign / verify.
const (
	MethodEncryptInit         = methodPrefix + "StreamingCryptoService/EncryptInit"
	MethodEncryptUpdate       = methodPrefix + "StreamingCryptoService/EncryptUpdate"
	MethodEncryptFinal        = methodPrefix + "StreamingCryptoService/EncryptFinal"
	MethodEncryptMessage      = methodPrefix + "StreamingCryptoService/EncryptMessage"
	MethodEncryptMessageInit  = methodPrefix + "StreamingCryptoService/EncryptMessageInit"
	MethodEncryptMessageBegin = methodPrefix + "StreamingCryptoService/EncryptMessageBegin"
	MethodEncryptMessageNext  = methodPrefix + "StreamingCryptoService/EncryptMessageNext"
	MethodEncryptMessageFinal = methodPrefix + "StreamingCryptoService/EncryptMessageFinal"

	MethodDecryptInit         = methodPrefix + "StreamingCryptoService/DecryptInit"
	MethodDecryptUpdate       = methodPrefix + "StreamingCryptoService/DecryptUpdate"
	MethodDecryptFinal        = methodPrefix + "StreamingCryptoService/DecryptFinal"
	MethodDecryptMessage      = methodPrefix + "StreamingCryptoService/DecryptMessage"
	MethodDecryptMessageInit  = methodPrefix + "StreamingCryptoService/DecryptMessageInit"
	MethodDecryptMessageBegin = methodPrefix + "StreamingCryptoService/DecryptMessageBegin"
	MethodDecryptMessageNext  = methodPrefix + "StreamingCryptoService/DecryptMessageNext"
	MethodDecryptMessageFinal = methodPrefix + "StreamingCryptoService/DecryptMessageFinal"

	MethodSignInit         = methodPrefix + "StreamingCryptoService/SignInit"
	MethodSignUpdate       = methodPrefix + "StreamingCryptoService/SignUpdate"
	MethodSignFinal        = methodPrefix + "StreamingCryptoService/SignFinal"
	MethodSignMessage      = methodPrefix + "StreamingCryptoService/SignMessage"
	MethodSignMessageInit  = methodPrefix + "StreamingCryptoService/SignMessageInit"
	MethodSignMessageBegin = methodPrefix + "StreamingCryptoService/SignMessageBegin"
	MethodSignMessageNext  = methodPrefix + "StreamingCryptoService/SignMessageNext"
	MethodSignMessageFinal = methodPrefix + "StreamingCryptoService/SignMessageFinal"

	MethodVerifyInit         = methodPrefix + "StreamingCryptoService/VerifyInit"
	MethodVerifyUpdate       = methodPrefix + "StreamingCryptoService/VerifyUpdate"
	MethodVerifyFinal        = methodPrefix + "StreamingCryptoService/VerifyFinal"
	MethodVerifyMessage      = methodPrefix + "StreamingCryptoService/VerifyMessage"
	MethodVerifyMessageInit  = methodPrefix + "StreamingCryptoService/VerifyMessageInit"
	MethodVerifyMessageBegin = methodPrefix + "StreamingCryptoService/VerifyMessageBegin"
	MethodVerifyMessageNext  = methodPrefix + "StreamingCryptoService/VerifyMessageNext"
	MethodVerifyMessageFinal = methodPrefix + "StreamingCryptoService/VerifyMessageFinal"

	MethodDigestInit   = methodPrefix + "StreamingCryptoService/DigestInit"
	MethodDigestUpdate = methodPrefix + "StreamingCryptoService/DigestUpdate"
	MethodDigestFinal  = methodPrefix + "StreamingCryptoService/DigestFinal"
	MethodDigestKey    = methodPrefix + "StreamingCryptoService/DigestKey"

	MethodXofInit             = methodPrefix + "StreamingCryptoService/XofInit"
	MethodXofUpdate           = methodPrefix + "StreamingCryptoService/XofUpdate"
	MethodXofFinal            = methodPrefix + "StreamingCryptoService/XofFinal"
	MethodDigestEncryptUpdate = methodPrefix + "StreamingCryptoService/DigestEncryptUpdate"
	MethodDecryptDigestUpdate = methodPrefix + "StreamingCryptoService/DecryptDigestUpdate"
	MethodSignEncryptUpdate   = methodPrefix + "StreamingCryptoService/SignEncryptUpdate"
	MethodDecryptVerifyUpdate = methodPrefix + "StreamingCryptoService/DecryptVerifyUpdate"
)

// KeyEstablishmentService
const (
	MethodWrapKey        = methodPrefix + "KeyEstablishmentService/WrapKey"
	MethodUnwrapKey      = methodPrefix + "KeyEstablishmentService/UnwrapKey"
	MethodDeriveKey      = methodPrefix + "KeyEstablishmentService/DeriveKey"
	MethodKeyAgreement   = methodPrefix + "KeyEstablishmentService/KeyAgreement"
	MethodEncapsulateKey = methodPrefix + "KeyEstablishmentService/EncapsulateKey"
	MethodDecapsulateKey = methodPrefix + "KeyEstablishmentService/DecapsulateKey"
)

// AlgorithmDiscoveryService.
const (
	MethodListTemplates = methodPrefix + "AlgorithmDiscoveryService/ListTemplates"
	MethodGetTemplate   = methodPrefix + "AlgorithmDiscoveryService/GetTemplate"
	MethodListScopes    = methodPrefix + "AlgorithmDiscoveryService/ListScopes"
)

// ProviderService.
const (
	MethodListProviders            = methodPrefix + "ProviderService/ListProviders"
	MethodGetProvider              = methodPrefix + "ProviderService/GetProvider"
	MethodMatchProviders           = methodPrefix + "ProviderService/MatchProviders"
	MethodListProviderInstances    = methodPrefix + "ProviderService/ListProviderInstances"
	MethodGetProviderInstance      = methodPrefix + "ProviderService/GetProviderInstance"
	MethodRegisterProviderInstance = methodPrefix + "ProviderService/RegisterProviderInstance"
	MethodUpdateProviderInstance   = methodPrefix + "ProviderService/UpdateProviderInstance"
	MethodDeleteProviderInstance   = methodPrefix + "ProviderService/DeleteProviderInstance"
)
