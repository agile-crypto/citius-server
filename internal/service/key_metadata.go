package service

import (
	types "github.ibm.com/citius/citius-server/gen/go/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// KeyMetadata holds the metadata of a key as returned by CreateKey, ReadKey,
// RotateKey, TransformKey or ListKeys.
//
// It is an application-layer read model assembled from the key.Key aggregate,
// its current key.Version, and the associated template.Template. It lives in
// the service package because it is produced by KeyOrchestrator and consumed
// by the gRPC handler — both of which already depend on internal/service.
type KeyMetadata struct {
	Name       string
	Version    uint32
	KeyID      string
	Primitive  string // e.g. "signature", "encryption" — derived from ScopeSpec
	TemplateID string
	// The scope specification used to create this key.
	ScopeSpec        *types.ScopeSpecification
	Provider         string
	CreatedTime      *timestamppb.Timestamp
	UpdatedTime      *timestamppb.Timestamp
	Policy           string
	Labels           map[string]string
	ProviderMetadata map[string]string

	TemplateInfo *types.TemplateInfo

	// Whether the key material can be extracted from its provider.
	// False for non-extractable HSM keys.
	// Determines feasibility of EXTRACT_AND_IMPORT migration strategy.
	Extractable bool

	// Lifecycle state of the key (NIST SP 800-57, KMIP state machine).
	LifecycleState  types.KeyLifecycleState
	PublicKeyBytes  []byte           // Public-key material for asymmetric keys
	PublicKeyFormat *types.KeyFormat // Format of public key material (e.g., RAW, PKCS8, JWK)
}
