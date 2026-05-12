package main

import "github.ibm.com/citius/zitadel-grpc-auth/admin"

// citiusUsers returns the seed service users provisioned by setup-sdk.
//
// Four users cover the integration matrix:
//
//   - svc-admin     — full grant; * key/policy access. Catch-all for ops.
//   - svc-tester    — integration-test rig; scoped to itest-* keys/policies.
//   - svc-readonly  — observers; read-only across all read permissions.
//   - svc-noperm    — negative-path control; no permissions, no grants.
//
// All four are machine users (no human credentials). Their client_id /
// client_secret pairs are written to ../generated-config.json by main.go
// and sliced into ../citius-zitadel.env by ../bootstrap.sh.
func citiusUsers() []admin.OnboardInput {
	return []admin.OnboardInput{
		{
			Username:    "svc-admin",
			DisplayName: "Citius admin (full grant)",
			Permissions: allCitiusPermissions(),
			KeyAccess: admin.KeyAccess{
				AllowedKeyPatterns: []string{"*"},
			},
			PolicyAccess: admin.PolicyAccess{
				AllowedPolicyPatterns: []string{"*"},
			},
		},
		{
			Username:    "svc-tester",
			DisplayName: "Citius integration tester",
			Permissions: []string{
				permKeysCreate, permKeysRotate, permKeysUpdatePolicy, permKeysRead,
				permCryptoEncrypt, permCryptoDecrypt, permCryptoSign, permCryptoVerify,
				permPolicyRead,
			},
			KeyAccess: admin.KeyAccess{
				AllowedKeyPatterns: []string{"itest-*"},
			},
			PolicyAccess: admin.PolicyAccess{
				AllowedPolicyPatterns: []string{"itest-*"},
			},
		},
		{
			Username:    "svc-readonly",
			DisplayName: "Citius read-only consumer",
			Permissions: []string{
				permKeysRead, permPolicyRead, permDiscoveryRead, permProviderRead,
			},
		},
		{
			Username:    "svc-noperm",
			DisplayName: "Citius negative-path user (no permissions)",
			// Intentionally empty. Used by the integration suite to verify
			// that an authenticated-but-unauthorized caller is rejected
			// with PermissionDenied (not Unauthenticated).
		},
	}
}
