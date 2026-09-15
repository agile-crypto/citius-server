package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validHumanACL = `version: 1
web_application:
  name: citius-ui
  redirect_uris:
    - https://ui.example.test/auth/callback
  post_logout_redirect_uris:
    - https://ui.example.test/
  enable_refresh_tokens: true
  dev_mode: true
users:
  - username: alice
    user_type: human
    display_name: Alice Producer
    given_name: Alice
    family_name: Producer
    email: alice@example.test
    email_verified: true
    password_env: ALICE_INITIAL_PASSWORD
    password_change_required: false
    permissions:
      - citius:discovery:read
    key_access:
      allow: ["demo-*"]
    policy_access:
      deny: ["demo-restricted-*"]
`

func TestLoadACLRetainsLegacyMachineUserBehavior(t *testing.T) {
	acl, err := loadACL("../acl.yaml")
	if err != nil {
		t.Fatalf("load repository ACL: %v", err)
	}
	if got := len(acl.MachineUsers); got != 4 {
		t.Fatalf("machine users = %d, want 4", got)
	}
	if got := len(acl.HumanUsers); got != 0 {
		t.Fatalf("human users = %d, want 0", got)
	}
	if acl.WebApplication != nil {
		t.Fatal("legacy ACL unexpectedly contains a Web application")
	}
	if web := acl.webApplicationInput(); web != nil {
		t.Fatalf("legacy ACL unexpectedly produced Web application input: %#v", web)
	}
}

func TestLoadACLParsesHumanUserAndWebApplication(t *testing.T) {
	t.Setenv("ALICE_INITIAL_PASSWORD", "")
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load human ACL without resolving password environment: %v", err)
	}

	if acl.WebApplication == nil {
		t.Fatal("Web application is nil")
	}
	if acl.WebApplication.Name != "citius-ui" || !acl.WebApplication.EnableRefreshTokens {
		t.Fatalf("unexpected Web application: %#v", acl.WebApplication)
	}
	if got := len(acl.MachineUsers); got != 0 {
		t.Fatalf("machine users = %d, want 0", got)
	}
	if got := len(acl.HumanUsers); got != 1 {
		t.Fatalf("human users = %d, want 1", got)
	}
	human := acl.HumanUsers[0]
	if human.Username != "alice" || human.GivenName != "Alice" || human.FamilyName != "Producer" {
		t.Fatalf("unexpected human identity: %#v", human)
	}
	if !human.EmailVerified || human.PasswordChangeRequired {
		t.Fatalf("unexpected demo identity flags: %#v", human)
	}
	if human.PasswordEnv != "ALICE_INITIAL_PASSWORD" {
		t.Fatalf("password env = %q", human.PasswordEnv)
	}
	if got := human.KeyAccess.AllowedKeyPatterns; len(got) != 1 || got[0] != "demo-*" {
		t.Fatalf("key allow patterns = %v", got)
	}
	if got := human.PolicyAccess.DenyPolicyPatterns; len(got) != 1 || got[0] != "demo-restricted-*" {
		t.Fatalf("policy deny patterns = %v", got)
	}
}

func TestLoadACLUsesSecureHumanFlagDefaults(t *testing.T) {
	yaml := `version: 1
users:
  - username: alice
    user_type: human
    given_name: Alice
    family_name: Producer
    email: alice@example.test
    password_env: ALICE_INITIAL_PASSWORD
    permissions: []
`
	acl, err := loadACLText(t, yaml)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	human := acl.HumanUsers[0]
	if human.EmailVerified {
		t.Fatal("email_verified defaulted to true")
	}
	if !human.PasswordChangeRequired {
		t.Fatal("password_change_required defaulted to false")
	}
}

func TestLoadACLRejectsInvalidHumanAndWebConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "unknown user type",
			yaml:    strings.Replace(validHumanACL, "user_type: human", "user_type: robot", 1),
			wantErr: "user_type must be",
		},
		{
			name:    "missing human given name",
			yaml:    strings.Replace(validHumanACL, "    given_name: Alice\n", "", 1),
			wantErr: "given_name is required",
		},
		{
			name:    "missing human family name",
			yaml:    strings.Replace(validHumanACL, "    family_name: Producer\n", "", 1),
			wantErr: "family_name is required",
		},
		{
			name:    "missing human email",
			yaml:    strings.Replace(validHumanACL, "    email: alice@example.test\n", "", 1),
			wantErr: "email is required",
		},
		{
			name:    "missing human password environment",
			yaml:    strings.Replace(validHumanACL, "    password_env: ALICE_INITIAL_PASSWORD\n", "", 1),
			wantErr: "password_env is required",
		},
		{
			name:    "human username with surrounding whitespace",
			yaml:    strings.Replace(validHumanACL, "username: alice", "username: ' alice'", 1),
			wantErr: "username must not contain surrounding whitespace",
		},
		{
			name:    "invalid human email",
			yaml:    strings.Replace(validHumanACL, "alice@example.test", "not-an-email", 1),
			wantErr: "valid address",
		},
		{
			name:    "invalid password environment name",
			yaml:    strings.Replace(validHumanACL, "ALICE_INITIAL_PASSWORD", "literal-password", 1),
			wantErr: "must name an environment variable",
		},
		{
			name: "machine user with human field",
			yaml: `version: 1
users:
  - username: service
    user_type: machine
    given_name: Service
    permissions: []
`,
			wantErr: "must not set human profile",
		},
		{
			name: "duplicate username",
			yaml: validHumanACL + `  - username: alice
    permissions: []
`,
			wantErr: "duplicate username",
		},
		{
			name: "duplicate human email",
			yaml: validHumanACL + `  - username: alice-two
    user_type: human
    given_name: Alice
    family_name: Two
    email: ALICE@example.test
    password_env: ALICE_TWO_PASSWORD
    permissions: []
`,
			wantErr: "duplicate email",
		},
		{
			name:    "demo identity flags without development mode",
			yaml:    strings.Replace(validHumanACL, "  dev_mode: true", "  dev_mode: false", 1),
			wantErr: "requires web_application.dev_mode=true",
		},
		{
			name:    "wildcard redirect URI",
			yaml:    strings.Replace(validHumanACL, "ui.example.test", "*.example.test", 1),
			wantErr: "must not contain wildcards",
		},
		{
			name: "missing redirect URI",
			yaml: strings.Replace(validHumanACL,
				"  redirect_uris:\n    - https://ui.example.test/auth/callback\n", "", 1),
			wantErr: "at least one redirect_uri is required",
		},
		{
			name:    "fragment redirect URI",
			yaml:    strings.Replace(validHumanACL, "/auth/callback", "/auth/callback#fragment", 1),
			wantErr: "must not contain a fragment",
		},
		{
			name:    "non-loopback HTTP redirect URI",
			yaml:    strings.Replace(validHumanACL, "https://ui.example.test/auth/callback", "http://ui.example.test/auth/callback", 1),
			wantErr: "must use HTTPS",
		},
		{
			name: "duplicate redirect URI",
			yaml: strings.Replace(validHumanACL,
				"    - https://ui.example.test/auth/callback",
				"    - https://ui.example.test/auth/callback\n    - https://UI.EXAMPLE.TEST/auth/callback", 1),
			wantErr: "duplicate URI",
		},
		{
			name:    "unknown YAML field",
			yaml:    strings.Replace(validHumanACL, "    family_name: Producer", "    family_name: Producer\n    passwrod: secret", 1),
			wantErr: "field passwrod not found",
		},
		{
			name:    "unknown permission",
			yaml:    strings.Replace(validHumanACL, "citius:discovery:read", "citius:unknown", 1),
			wantErr: "unknown permission",
		},
		{
			name:    "unsupported ACL version",
			yaml:    strings.Replace(validHumanACL, "version: 1", "version: 2", 1),
			wantErr: "unsupported version 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadACLText(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("loadACL() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadACLAllowsDevelopmentHTTPOnlyOnLoopback(t *testing.T) {
	yaml := strings.Replace(
		validHumanACL,
		"https://ui.example.test/auth/callback",
		"http://127.0.0.1:7861/auth/callback",
		1,
	)
	if _, err := loadACLText(t, yaml); err != nil {
		t.Fatalf("load loopback development redirect: %v", err)
	}
}

func TestHumanConfigurationConvertsToAdminInputs(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	web := acl.webApplicationInput()
	if web == nil || web.Name != "citius-ui" || len(web.RedirectURIs) != 1 {
		t.Fatalf("unexpected Web application input: %#v", web)
	}
	human := acl.HumanUsers[0].onboardInput("initial-secret")
	if human.Username != "alice" || human.InitialPassword != "initial-secret" {
		t.Fatalf("unexpected human onboard input: %#v", human)
	}
	if !human.EmailVerified || human.PasswordChangeRequired {
		t.Fatalf("unexpected human flags: %#v", human)
	}
}

func loadACLText(t *testing.T, contents string) (*parsedACL, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write ACL fixture: %v", err)
	}
	return loadACL(path)
}
