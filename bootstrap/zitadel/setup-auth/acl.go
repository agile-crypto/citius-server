package main

import (
	"bytes"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/agile-crypto/zitadel-grpc-auth/admin"
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
	Version        int                `yaml:"version"`
	WebApplication *aclWebApplication `yaml:"web_application,omitempty"`
	Users          []aclUser          `yaml:"users"`
}

type aclUser struct {
	Username               string          `yaml:"username"`
	UserType               string          `yaml:"user_type,omitempty"`
	DisplayName            string          `yaml:"display_name"`
	GivenName              string          `yaml:"given_name,omitempty"`
	FamilyName             string          `yaml:"family_name,omitempty"`
	Email                  string          `yaml:"email,omitempty"`
	EmailVerified          *bool           `yaml:"email_verified,omitempty"`
	PasswordEnv            string          `yaml:"password_env,omitempty"`
	PasswordChangeRequired *bool           `yaml:"password_change_required,omitempty"`
	Permissions            []string        `yaml:"permissions"`
	KeyAccess              *aclAccessBlock `yaml:"key_access,omitempty"`
	PolicyAccess           *aclAccessBlock `yaml:"policy_access,omitempty"`
}

type aclWebApplication struct {
	Name                   string   `yaml:"name"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris,omitempty"`
	EnableRefreshTokens    bool     `yaml:"enable_refresh_tokens,omitempty"`
	DevMode                bool     `yaml:"dev_mode,omitempty"`
}

type aclAccessBlock struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type parsedACL struct {
	WebApplication *aclWebApplication
	MachineUsers   []admin.OnboardInput
	HumanUsers     []aclHumanUser
}

type aclHumanUser struct {
	Username               string
	DisplayName            string
	GivenName              string
	FamilyName             string
	Email                  string
	EmailVerified          bool
	PasswordEnv            string
	PasswordChangeRequired bool
	Permissions            []string
	KeyAccess              admin.KeyAccess
	PolicyAccess           admin.PolicyAccess
}

const (
	userTypeMachine = "machine"
	userTypeHuman   = "human"
)

var environmentVariableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// loadACL parses and structurally validates the YAML at path. It never resolves
// password environment variables, so validate remains a secret-free operation.
//
// The function expands `permissions: ["*"]` to the full permission set,
// rejects unknown permission keys (a typo in the ACL must not silently
// strip a permission), and rejects duplicate usernames.
func loadACL(path string) (*parsedACL, error) {
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

	if f.WebApplication != nil {
		if err := validateWebApplication(*f.WebApplication); err != nil {
			return nil, fmt.Errorf("%s: web_application: %w", path, err)
		}
	}

	seenUsers := make(map[string]struct{}, len(f.Users))
	seenEmails := make(map[string]struct{}, len(f.Users))
	out := &parsedACL{WebApplication: f.WebApplication}
	known := knownPermissionSet()

	for i, u := range f.Users {
		if u.Username == "" {
			return nil, fmt.Errorf("%s: users[%d]: username is required", path, i)
		}
		if _, dup := seenUsers[u.Username]; dup {
			return nil, fmt.Errorf("%s: users[%d]: duplicate username %q", path, i, u.Username)
		}
		seenUsers[u.Username] = struct{}{}

		if err := appendACLUser(out, u, f.WebApplication, seenEmails, known); err != nil {
			return nil, fmt.Errorf("%s: user %q: %w", path, u.Username, err)
		}
	}

	return out, nil
}

func appendACLUser(
	out *parsedACL,
	u aclUser,
	web *aclWebApplication,
	seenEmails, knownPermissions map[string]struct{},
) error {
	permissions, err := expandPermissions(u.Permissions, knownPermissions)
	if err != nil {
		return err
	}
	userType := u.UserType
	if userType == "" {
		userType = userTypeMachine
	}
	switch userType {
	case userTypeMachine:
		if err := validateMachineUser(u); err != nil {
			return err
		}
		out.MachineUsers = append(out.MachineUsers, machineOnboardInput(u, permissions))
	case userTypeHuman:
		if err := validateHumanUser(u, web, seenEmails); err != nil {
			return err
		}
		out.HumanUsers = append(out.HumanUsers, humanACLInput(u, permissions))
	default:
		return fmt.Errorf("user_type must be %q or %q", userTypeMachine, userTypeHuman)
	}
	return nil
}

func (a *parsedACL) usersForMachineProvisioning() ([]admin.OnboardInput, error) {
	if len(a.HumanUsers) != 0 || a.WebApplication != nil {
		return nil, fmt.Errorf("ACL contains human login configuration; this command only provisions machine users")
	}
	return a.MachineUsers, nil
}

func (a *parsedACL) userCount() int {
	return len(a.MachineUsers) + len(a.HumanUsers)
}

func validateMachineUser(u aclUser) error {
	if u.GivenName != "" || u.FamilyName != "" || u.Email != "" || u.EmailVerified != nil ||
		u.PasswordEnv != "" || u.PasswordChangeRequired != nil {
		return fmt.Errorf("machine users must not set human profile or password fields")
	}
	return nil
}

func validateHumanUser(u aclUser, web *aclWebApplication, seenEmails map[string]struct{}) error {
	if strings.TrimSpace(u.Username) == "" {
		return fmt.Errorf("username is required for human users")
	}
	if u.Username != strings.TrimSpace(u.Username) {
		return fmt.Errorf("username must not contain surrounding whitespace")
	}
	required := []struct {
		name  string
		value string
	}{
		{name: "given_name", value: u.GivenName},
		{name: "family_name", value: u.FamilyName},
		{name: "email", value: u.Email},
		{name: "password_env", value: u.PasswordEnv},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required for human users", field.name)
		}
		if field.value != strings.TrimSpace(field.value) {
			return fmt.Errorf("%s must not contain surrounding whitespace", field.name)
		}
	}

	address, err := mail.ParseAddress(u.Email)
	if err != nil || address.Address != u.Email {
		return fmt.Errorf("email must be a valid address")
	}
	emailKey := strings.ToLower(u.Email)
	if _, duplicate := seenEmails[emailKey]; duplicate {
		return fmt.Errorf("duplicate email %q", u.Email)
	}
	seenEmails[emailKey] = struct{}{}

	if !environmentVariableName.MatchString(u.PasswordEnv) {
		return fmt.Errorf("password_env must name an environment variable")
	}
	if usesDemoIdentityFlags(u) && (web == nil || !web.DevMode) {
		return fmt.Errorf("email_verified=true or password_change_required=false requires web_application.dev_mode=true")
	}
	return nil
}

func usesDemoIdentityFlags(u aclUser) bool {
	return u.EmailVerified != nil && *u.EmailVerified ||
		u.PasswordChangeRequired != nil && !*u.PasswordChangeRequired
}

func machineOnboardInput(u aclUser, permissions []string) admin.OnboardInput {
	return admin.OnboardInput{
		Username:     u.Username,
		DisplayName:  u.DisplayName,
		Permissions:  permissions,
		KeyAccess:    keyAccess(u.KeyAccess),
		PolicyAccess: policyAccess(u.PolicyAccess),
	}
}

func humanACLInput(u aclUser, permissions []string) aclHumanUser {
	passwordChangeRequired := true
	if u.PasswordChangeRequired != nil {
		passwordChangeRequired = *u.PasswordChangeRequired
	}
	return aclHumanUser{
		Username:               u.Username,
		DisplayName:            u.DisplayName,
		GivenName:              u.GivenName,
		FamilyName:             u.FamilyName,
		Email:                  u.Email,
		EmailVerified:          u.EmailVerified != nil && *u.EmailVerified,
		PasswordEnv:            u.PasswordEnv,
		PasswordChangeRequired: passwordChangeRequired,
		Permissions:            permissions,
		KeyAccess:              keyAccess(u.KeyAccess),
		PolicyAccess:           policyAccess(u.PolicyAccess),
	}
}

func keyAccess(block *aclAccessBlock) admin.KeyAccess {
	if block == nil {
		return admin.KeyAccess{}
	}
	return admin.KeyAccess{
		AllowedKeyPatterns: append([]string(nil), block.Allow...),
		DenyKeyPatterns:    append([]string(nil), block.Deny...),
	}
}

func policyAccess(block *aclAccessBlock) admin.PolicyAccess {
	if block == nil {
		return admin.PolicyAccess{}
	}
	return admin.PolicyAccess{
		AllowedPolicyPatterns: append([]string(nil), block.Allow...),
		DenyPolicyPatterns:    append([]string(nil), block.Deny...),
	}
}

func validateWebApplication(app aclWebApplication) error {
	if strings.TrimSpace(app.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if app.Name != strings.TrimSpace(app.Name) {
		return fmt.Errorf("name must not contain surrounding whitespace")
	}
	if len(app.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect_uri is required")
	}
	if err := validateWebURISet("redirect_uris", app.RedirectURIs, app.DevMode); err != nil {
		return err
	}
	return validateWebURISet("post_logout_redirect_uris", app.PostLogoutRedirectURIs, app.DevMode)
}

func validateWebURISet(field string, values []string, devMode bool) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized, err := normalizeWebURI(value, devMode)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("%s contains duplicate URI %q", field, normalized)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

func normalizeWebURI(value string, devMode bool) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("URI must be non-empty and contain no surrounding whitespace")
	}
	lower := strings.ToLower(value)
	if strings.Contains(value, "*") || strings.Contains(lower, "%2a") {
		return "", fmt.Errorf("URI %q must not contain wildcards", value)
	}
	if strings.Contains(value, "#") {
		return "", fmt.Errorf("URI %q must not contain a fragment", value)
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("URI %q is invalid: %w", value, err)
	}
	return normalizeParsedWebURI(parsed, value, devMode)
}

func normalizeParsedWebURI(parsed *url.URL, value string, devMode bool) (string, error) {
	if !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("URI %q must be absolute and include a host", value)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URI %q must not contain user information", value)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("URI %q must include a host", value)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !devMode || !isLoopbackHost(hostname) {
			return "", fmt.Errorf("URI %q must use HTTPS; development HTTP is limited to loopback hosts", value)
		}
	}
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
