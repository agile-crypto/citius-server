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
// CryptoService — key lifecycle.
const (
	MethodCreateKey            = methodPrefix + "CryptoService/CreateKey"
	MethodDeleteKey            = methodPrefix + "CryptoService/DeleteKey"
	MethodImportKey            = methodPrefix + "CryptoService/ImportKey"
	MethodRotateKey            = methodPrefix + "CryptoService/RotateKey"
	MethodTransformKey         = methodPrefix + "CryptoService/TransformKey"
	MethodMigrateKey           = methodPrefix + "CryptoService/MigrateKey"
	MethodUpdateKeyPolicy      = methodPrefix + "CryptoService/UpdateKeyPolicy"
	MethodReadKey              = methodPrefix + "CryptoService/ReadKey"
	MethodListKeys             = methodPrefix + "CryptoService/ListKeys"
	MethodValidateKeyOperation = methodPrefix + "CryptoService/ValidateKeyOperation"
	MethodExportKey            = methodPrefix + "CryptoService/ExportKey"
)

// CryptoService — crypto-policy lifecycle.
const (
	MethodCreateCryptoPolicy  = methodPrefix + "CryptoService/CreateCryptoPolicy"
	MethodReadCryptoPolicy    = methodPrefix + "CryptoService/ReadCryptoPolicy"
	MethodDeleteCryptoPolicy  = methodPrefix + "CryptoService/DeleteCryptoPolicy"
	MethodUpdateCryptoPolicy  = methodPrefix + "CryptoService/UpdateCryptoPolicy"
	MethodListCryptoPolicies  = methodPrefix + "CryptoService/ListCryptoPolicies"
	MethodEvaluatePolicy      = methodPrefix + "CryptoService/EvaluatePolicy"
	MethodBatchEvaluatePolicy = methodPrefix + "CryptoService/BatchEvaluatePolicy"
)

// CryptoService — encrypt / decrypt / sign / verify (one-shot + multi-part).
const (
	MethodEncrypt             = methodPrefix + "CryptoService/Encrypt"
	MethodEncryptInit         = methodPrefix + "CryptoService/EncryptInit"
	MethodEncryptUpdate       = methodPrefix + "CryptoService/EncryptUpdate"
	MethodEncryptFinal        = methodPrefix + "CryptoService/EncryptFinal"
	MethodEncryptMessage      = methodPrefix + "CryptoService/EncryptMessage"
	MethodEncryptMessageInit  = methodPrefix + "CryptoService/EncryptMessageInit"
	MethodEncryptMessageBegin = methodPrefix + "CryptoService/EncryptMessageBegin"
	MethodEncryptMessageNext  = methodPrefix + "CryptoService/EncryptMessageNext"
	MethodEncryptMessageFinal = methodPrefix + "CryptoService/EncryptMessageFinal"

	MethodDecrypt             = methodPrefix + "CryptoService/Decrypt"
	MethodDecryptInit         = methodPrefix + "CryptoService/DecryptInit"
	MethodDecryptUpdate       = methodPrefix + "CryptoService/DecryptUpdate"
	MethodDecryptFinal        = methodPrefix + "CryptoService/DecryptFinal"
	MethodDecryptMessage      = methodPrefix + "CryptoService/DecryptMessage"
	MethodDecryptMessageInit  = methodPrefix + "CryptoService/DecryptMessageInit"
	MethodDecryptMessageBegin = methodPrefix + "CryptoService/DecryptMessageBegin"
	MethodDecryptMessageNext  = methodPrefix + "CryptoService/DecryptMessageNext"
	MethodDecryptMessageFinal = methodPrefix + "CryptoService/DecryptMessageFinal"

	MethodSign             = methodPrefix + "CryptoService/Sign"
	MethodDigestSign       = methodPrefix + "CryptoService/DigestSign"
	MethodSignInit         = methodPrefix + "CryptoService/SignInit"
	MethodSignUpdate       = methodPrefix + "CryptoService/SignUpdate"
	MethodSignFinal        = methodPrefix + "CryptoService/SignFinal"
	MethodSignMessage      = methodPrefix + "CryptoService/SignMessage"
	MethodSignMessageInit  = methodPrefix + "CryptoService/SignMessageInit"
	MethodSignMessageBegin = methodPrefix + "CryptoService/SignMessageBegin"
	MethodSignMessageNext  = methodPrefix + "CryptoService/SignMessageNext"
	MethodSignMessageFinal = methodPrefix + "CryptoService/SignMessageFinal"

	MethodVerify             = methodPrefix + "CryptoService/Verify"
	MethodDigestVerify       = methodPrefix + "CryptoService/DigestVerify"
	MethodVerifyInit         = methodPrefix + "CryptoService/VerifyInit"
	MethodVerifyUpdate       = methodPrefix + "CryptoService/VerifyUpdate"
	MethodVerifyFinal        = methodPrefix + "CryptoService/VerifyFinal"
	MethodVerifyMessage      = methodPrefix + "CryptoService/VerifyMessage"
	MethodVerifyMessageInit  = methodPrefix + "CryptoService/VerifyMessageInit"
	MethodVerifyMessageBegin = methodPrefix + "CryptoService/VerifyMessageBegin"
	MethodVerifyMessageNext  = methodPrefix + "CryptoService/VerifyMessageNext"
	MethodVerifyMessageFinal = methodPrefix + "CryptoService/VerifyMessageFinal"
)

// CryptoService — digest / xof / mac / random / wrap / kdf / kem.
const (
	MethodDigest              = methodPrefix + "CryptoService/Digest"
	MethodDigestInit          = methodPrefix + "CryptoService/DigestInit"
	MethodDigestUpdate        = methodPrefix + "CryptoService/DigestUpdate"
	MethodDigestFinal         = methodPrefix + "CryptoService/DigestFinal"
	MethodDigestKey           = methodPrefix + "CryptoService/DigestKey"
	MethodXof                 = methodPrefix + "CryptoService/Xof"
	MethodXofInit             = methodPrefix + "CryptoService/XofInit"
	MethodXofUpdate           = methodPrefix + "CryptoService/XofUpdate"
	MethodXofFinal            = methodPrefix + "CryptoService/XofFinal"
	MethodDigestEncryptUpdate = methodPrefix + "CryptoService/DigestEncryptUpdate"
	MethodDecryptDigestUpdate = methodPrefix + "CryptoService/DecryptDigestUpdate"
	MethodSignEncryptUpdate   = methodPrefix + "CryptoService/SignEncryptUpdate"
	MethodDecryptVerifyUpdate = methodPrefix + "CryptoService/DecryptVerifyUpdate"
	MethodWrapKey             = methodPrefix + "CryptoService/WrapKey"
	MethodUnwrapKey           = methodPrefix + "CryptoService/UnwrapKey"
	MethodDeriveKey           = methodPrefix + "CryptoService/DeriveKey"
	MethodKeyAgreement        = methodPrefix + "CryptoService/KeyAgreement"
	MethodEncapsulateKey      = methodPrefix + "CryptoService/EncapsulateKey"
	MethodDecapsulateKey      = methodPrefix + "CryptoService/DecapsulateKey"
	MethodGenerateRandom      = methodPrefix + "CryptoService/GenerateRandom"
	MethodSeedRandom          = methodPrefix + "CryptoService/SeedRandom"
	MethodGenerateMAC         = methodPrefix + "CryptoService/GenerateMAC"
	MethodVerifyMAC           = methodPrefix + "CryptoService/VerifyMAC"
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
