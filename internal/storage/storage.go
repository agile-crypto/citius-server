package storage

import (
	"github.ibm.com/citius/citius-server/internal/crypto"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
)

// Storage composes all aggregate repository interfaces.
// Implementations must be goroutine-safe.
type Storage interface {
	key.Repository
	policy.Repository
	provider.InstanceRepository
	crypto.SessionRepository
}
