package core

import types "github.ibm.com/citius/citius-server/gen/go/api/types"

type SecurityProperties struct {
	SecurityStrength uint32
	SecurityLevel    types.NistSecurityLevel
	QuantumSafe      bool
	NistStatus       types.NistStatus
	FipsApproved     bool
}

func (s *SecurityProperties) ToProto() *types.UniversalSecurityProperties {
	if s == nil {
		return nil
	}
	return &types.UniversalSecurityProperties{
		SecurityStrengthBits: s.SecurityStrength,
		NistSecurityLevel:    s.SecurityLevel,
		QuantumSafe:          &s.QuantumSafe,
		NistStatus:           s.NistStatus,
		FipsApproved:         &s.FipsApproved,
	}
}

func SecurityPropertiesFromProto(s *types.UniversalSecurityProperties) *SecurityProperties {
	if s == nil {
		return nil
	}
	return &SecurityProperties{
		SecurityStrength: s.SecurityStrengthBits,
		SecurityLevel:    s.NistSecurityLevel,
		QuantumSafe:      *s.QuantumSafe,
		NistStatus:       s.NistStatus,
		FipsApproved:     *s.FipsApproved,
	}
}
