package auth

// Permission keys.
//
// Mirrored verbatim in bootstrap/zitadel/setup-auth/operations.go. The two
// must stay in sync; an integration test asserts the policy registry's
// permission set is a subset of the bootstrap catalog.
//
// Key lifecycle is intentionally split across three permissions:
//
//   - PermKeysCreate       — create / delete / import (slot management).
//   - PermKeysRotate       — rotate / transform / migrate (key material).
//   - PermKeysUpdatePolicy — rebind a key to a different crypto policy.
//
// These three axes are independently destructive (creation, material
// rotation, policy binding) and grant separately.
const (
	PermKeysCreate       = "citius:keys:create"
	PermKeysRotate       = "citius:keys:rotate"
	PermKeysUpdatePolicy = "citius:keys:update-policy"
	PermKeysRead         = "citius:keys:read"

	PermCryptoEncrypt = "citius:crypto:encrypt"
	PermCryptoDecrypt = "citius:crypto:decrypt"
	PermCryptoSign    = "citius:crypto:sign"
	PermCryptoVerify  = "citius:crypto:verify"
	PermCryptoMisc    = "citius:crypto:misc"

	PermPolicyRead  = "citius:policy:read"
	PermPolicyWrite = "citius:policy:write"

	PermDiscoveryRead = "citius:discovery:read"

	PermProviderRead  = "citius:provider:read"
	PermProviderWrite = "citius:provider:write"
)

// AllPermissions returns every permission key in declaration order with
// no duplicates. Useful for tests and for the svc-admin grant list.
func AllPermissions() []string {
	return []string{
		PermKeysCreate, PermKeysRotate, PermKeysUpdatePolicy, PermKeysRead,
		PermCryptoEncrypt, PermCryptoDecrypt, PermCryptoSign, PermCryptoVerify, PermCryptoMisc,
		PermPolicyRead, PermPolicyWrite,
		PermDiscoveryRead,
		PermProviderRead, PermProviderWrite,
	}
}
