package core

// Operation string constants for cryptographic operations.
// Used in PolicyEngine.ValidateOperation(ctx, policyName, operation, templateID, providerID)
// where `operation` is a plain string. Untyped constants convert to string without cast.
const (
	OperationCreateKey = "create_key"
	OperationReadKey   = "read_key"
	OperationDeleteKey = "delete_key"
	OperationSign      = "sign"
	OperationVerify    = "verify"
	OperationEncrypt   = "encrypt"
	OperationDecrypt   = "decrypt"
	OperationWrap      = "wrap"
	OperationUnwrap    = "unwrap"
	OperationDeriveKey = "derive_key"
	OperationRotateKey = "rotate_key"
)

// KeyCreationSpec carries the inputs for a CreateKey call across package boundaries.
// It is NOT a proto type — it holds Go-native values resolved from the gRPC request.
// Also referenced by UnwrapKeyRequest.TargetKeySpec and DeriveKeyRequest.Spec
type KeyCreationSpec struct {
	Name               string
	TemplateID         string // set when key_specification=template_id
	Scope              []byte // serialised ScopeSpecification, set when key_specification=scope
	PolicyID           string
	ProviderInstanceID string // optional: if empty, use default provider
	Labels             map[string]string
}

// KeyMaterial holds the raw bytes of a key as returned by GetKeyWithMaterial.
// PrivateKeyBytes may be empty for public-key-only operations.
type KeyMaterial struct {
	PublicKeyBytes  []byte
	PrivateKeyBytes []byte // nil for public-key-only operations
	Algorithm       string
}
