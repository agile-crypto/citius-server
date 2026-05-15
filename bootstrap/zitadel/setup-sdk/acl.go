package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"

	"github.ibm.com/citius/zitadel-grpc-auth/admin"
	"gopkg.in/yaml.v3"
)

// aclFile is the on-disk shape of bootstrap/zitadel/acl.yaml.
//
// The catalog of valid permission keys (and which RPC each one guards) is
// defined in operations.go and intentionally NOT in this file: that mapping
// is a compile-time invariant verified against the generated *_grpc.pb.go
// method constants by an integration test, and a YAML typo would silently
// open a hole in the gRPC authz layer.
//
// What lives here is purely declarative: which users to provision, what
// permission keys to grant them, and which key/policy name patterns they
// may operate on.
type aclFile struct {
	Version int       `yaml:"version"`
	Users   []aclUser `yaml:"users"`
}

type aclUser struct {
	Username     string          `yaml:"username"`
	DisplayName  string          `yaml:"display_name"`
	Permissions  []string        `yaml:"permissions"`
	KeyAccess    *aclAccessBlock `yaml:"key_access,omitempty"`
	PolicyAccess *aclAccessBlock `yaml:"policy_access,omitempty"`
}

type aclAccessBlock struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// loadACL parses and validates the YAML at path. On success it returns
// admin.OnboardInput values ready to feed to admin.Client.Onboard.
//
// The function expands `permissions: ["*"]` to the full permission set,
// rejects unknown permission keys (a typo in the ACL must not silently
// strip a permission), and rejects duplicate usernames.
func loadACL(path string) ([]admin.OnboardInput, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Strict decoding so a typo'd field (e.g. `permision:`) is a parse
	// error rather than a silent default. Same posture as kubectl --strict.
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f aclFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if f.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d (want 1)", path, f.Version)
	}
	if len(f.Users) == 0 {
		return nil, fmt.Errorf("%s: no users defined", path)
	}

	known := knownPermissionSet()
	seenUsers := make(map[string]struct{}, len(f.Users))
	out := make([]admin.OnboardInput, 0, len(f.Users))

	for i, u := range f.Users {
		if u.Username == "" {
			return nil, fmt.Errorf("%s: users[%d]: username is required", path, i)
		}
		if _, dup := seenUsers[u.Username]; dup {
			return nil, fmt.Errorf("%s: users[%d]: duplicate username %q", path, i, u.Username)
		}
		seenUsers[u.Username] = struct{}{}

		perms, err := expandPermissions(u.Permissions, known)
		if err != nil {
			return nil, fmt.Errorf("%s: user %q: %w", path, u.Username, err)
		}

		in := admin.OnboardInput{
			Username:    u.Username,
			DisplayName: u.DisplayName,
			Permissions: perms,
		}
		if u.KeyAccess != nil {
			in.KeyAccess = admin.KeyAccess{
				AllowedKeyPatterns: u.KeyAccess.Allow,
				DenyKeyPatterns:    u.KeyAccess.Deny,
			}
		}
		if u.PolicyAccess != nil {
			in.PolicyAccess = admin.PolicyAccess{
				AllowedPolicyPatterns: u.PolicyAccess.Allow,
				DenyPolicyPatterns:    u.PolicyAccess.Deny,
			}
		}
		out = append(out, in)
	}

	return out, nil
}

// expandPermissions resolves wildcards and validates membership. A single
// "*" entry expands to every known permission, sorted for determinism.
// Any other entry must appear in `known` or the call fails — typos in
// the ACL are loud, never silent.
func expandPermissions(in []string, known map[string]struct{}) ([]string, error) {
	if len(in) == 1 && in[0] == "*" {
		out := make([]string, 0, len(known))
		for p := range known {
			out = append(out, p)
		}
		sort.Strings(out)
		return out, nil
	}
	for _, p := range in {
		if p == "*" {
			return nil, fmt.Errorf(`permission "*" must be the only entry when used`)
		}
		if _, ok := known[p]; !ok {
			return nil, fmt.Errorf("unknown permission %q (see operations.go for the catalog)", p)
		}
	}
	// Defensive copy — callers shouldn't be able to mutate the parsed YAML.
	cp := make([]string, len(in))
	copy(cp, in)
	return cp, nil
}

// knownPermissionSet returns the canonical permission catalog as a set,
// derived from operations.go so the two cannot drift.
func knownPermissionSet() map[string]struct{} {
	all := allCitiusPermissions()
	out := make(map[string]struct{}, len(all))
	for _, p := range all {
		out[p] = struct{}{}
	}
	return out
}
