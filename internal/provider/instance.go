package provider

import (
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"google.golang.org/protobuf/proto"
)

// Instance is the domain representation of a registered crypto provider instance.
type Instance struct {
	stored *storepb.StoredProviderInstance
}

// NewInstance wraps a StoredProviderInstance.
func NewInstance(stored *storepb.StoredProviderInstance) *Instance {
	if stored == nil {
		stored = &storepb.StoredProviderInstance{}
	}
	return &Instance{stored: stored}
}

// StoredProviderInstance returns the embedded proto.
func (pi *Instance) StoredProviderInstance() *storepb.StoredProviderInstance {
	return pi.stored
}

func (pi *Instance) Clone() *Instance {
	return &Instance{
		stored: proto.Clone(pi.stored).(*storepb.StoredProviderInstance),
	}
}
