package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agile-crypto/zitadel-grpc-auth/admin"
)

func TestReconcileIdentityResources(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	acl.MachineUsers = []admin.OnboardInput{{Username: "service"}}
	t.Setenv("ALICE_INITIAL_PASSWORD", "initial-secret")

	client := &fakeIdentityAdmin{}
	got, err := reconcileIdentityResources(context.Background(), client, acl)
	if err != nil {
		t.Fatalf("reconcile identities: %v", err)
	}
	if len(client.calls) != 3 || strings.Join(client.calls, ",") != "web:citius-ui,machine:service,human:alice" {
		t.Fatalf("calls = %v", client.calls)
	}
	if client.humanPassword != "initial-secret" {
		t.Fatalf("human password = %q", client.humanPassword)
	}
	if got.WebApplication == nil || got.WebApplication.ClientID != "web-client" {
		t.Fatalf("Web application result = %#v", got.WebApplication)
	}
	if got.MachineUsers["service"].ClientID != "machine-client" {
		t.Fatalf("machine result = %#v", got.MachineUsers)
	}
	if got.HumanUsers["alice"].LoginName != "alice@example.test" {
		t.Fatalf("human result = %#v", got.HumanUsers)
	}
}

func TestReconcileIdentityResourcesRetainsMachineOnlyFlow(t *testing.T) {
	acl, err := loadACLText(t, validMachineACL)
	if err != nil {
		t.Fatalf("load legacy ACL: %v", err)
	}

	client := &fakeIdentityAdmin{}
	got, err := reconcileIdentityResources(context.Background(), client, acl)
	if err != nil {
		t.Fatalf("reconcile identities: %v", err)
	}
	if len(client.calls) != len(acl.MachineUsers) {
		t.Fatalf("calls = %v, want one per machine user", client.calls)
	}
	if got.WebApplication != nil || len(got.HumanUsers) != 0 {
		t.Fatalf("machine-only result contains human login resources: %#v", got)
	}
	if len(got.MachineUsers) != len(acl.MachineUsers) {
		t.Fatalf("machine results = %d, want %d", len(got.MachineUsers), len(acl.MachineUsers))
	}
}

func TestReconcileIdentityResourcesRequiresHumanPassword(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	t.Setenv("ALICE_INITIAL_PASSWORD", "")

	client := &fakeIdentityAdmin{}
	_, err = reconcileIdentityResources(context.Background(), client, acl)
	if err == nil || !strings.Contains(err.Error(), "ALICE_INITIAL_PASSWORD") {
		t.Fatalf("reconcile error = %v, want missing password environment", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls before password failure = %v, want none", client.calls)
	}
}

func TestReconcileIdentityResourcesStopsOnFailure(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	acl.MachineUsers = []admin.OnboardInput{{Username: "service"}}
	t.Setenv("ALICE_INITIAL_PASSWORD", "initial-secret")

	client := &fakeIdentityAdmin{machineErr: errors.New("grant failed")}
	_, err = reconcileIdentityResources(context.Background(), client, acl)
	if err == nil || !strings.Contains(err.Error(), `onboard machine user "service"`) {
		t.Fatalf("reconcile error = %v", err)
	}
	if strings.Join(client.calls, ",") != "web:citius-ui,machine:service" {
		t.Fatalf("calls = %v", client.calls)
	}
}

func TestVerifyIdentityResourcesUsesNonSecretACLConfiguration(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	client := &fakeIdentityVerifier{
		result: &admin.HumanAuthConfigurationResult{ProjectID: "project-1", Current: true},
	}

	got, err := verifyIdentityResources(context.Background(), client, acl)
	if err != nil {
		t.Fatalf("verify identities: %v", err)
	}
	if !got.Current || got.ProjectID != "project-1" {
		t.Fatalf("verification result = %#v", got)
	}
	if client.input.ClaimNamespace != claimNamespace || client.input.WebApplication.Name != "citius-ui" {
		t.Fatalf("verification input = %#v", client.input)
	}
	if len(client.input.Humans) != 1 || client.input.Humans[0].Username != "alice" {
		t.Fatalf("verification humans = %#v", client.input.Humans)
	}
}

func TestBuildUIAuthConfigExcludesBootstrapSecrets(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	generated := generatedConfig{
		ProjectID: "project-1",
		APIApp: admin.AppCredentials{
			ClientID: "introspection-client", ClientSecret: "introspection-secret",
		},
		WebApplication: &admin.WebApplicationResult{ApplicationID: "web-app", ClientID: "public-client"},
		Users: map[string]admin.OnboardResult{
			"service": {ClientID: "machine-client", ClientSecret: "machine-secret"},
		},
		HumanUsers: map[string]admin.HumanOnboardResult{
			"alice": {UserID: "human-1", LoginName: "alice@example.test"},
		},
	}

	got, err := buildUIAuthConfig(generated, acl, "https://issuer.example.test/")
	if err != nil {
		t.Fatalf("build UI auth configuration: %v", err)
	}
	if got.Issuer != "https://issuer.example.test" || got.WebApp.ClientID != "public-client" {
		t.Fatalf("UI auth configuration = %#v", got)
	}
	if got.Audience != "urn:zitadel:iam:org:project:id:project-1:aud" {
		t.Fatalf("audience = %q", got.Audience)
	}
	if got.DemoUsers["alice"].UserID != "human-1" || got.DemoUsers["alice"].DisplayName != "Alice Producer" {
		t.Fatalf("demo users = %#v", got.DemoUsers)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal UI auth configuration: %v", err)
	}
	for _, forbidden := range []string{
		"introspection-secret", "machine-secret", `"password":`,
		`"access_token":`, `"refresh_token":`, `"id_token":`,
	} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("UI auth configuration contains forbidden value %q: %s", forbidden, raw)
		}
	}
}

func TestBuildUIAuthConfigRejectsIncompleteGeneratedState(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	valid := generatedConfig{
		ProjectID:      "project-1",
		WebApplication: &admin.WebApplicationResult{ClientID: "public-client"},
		HumanUsers: map[string]admin.HumanOnboardResult{
			"alice": {UserID: "human-1"},
		},
	}
	missingProject := valid
	missingProject.ProjectID = ""
	missingWebClient := valid
	missingWebClient.WebApplication = nil
	missingHuman := valid
	missingHuman.HumanUsers = nil
	tests := []struct {
		name      string
		generated generatedConfig
		issuer    string
		wantErr   string
	}{
		{name: "missing project", generated: missingProject, issuer: "https://issuer.example.test", wantErr: "project_id"},
		{name: "missing Web client", generated: missingWebClient, issuer: "https://issuer.example.test", wantErr: "client_id"},
		{name: "missing human", generated: missingHuman, issuer: "https://issuer.example.test", wantErr: "user_id"},
		{name: "issuer without scheme", generated: valid, issuer: "issuer.example.test", wantErr: "invalid issuer"},
		{name: "issuer with credentials", generated: valid, issuer: "https://user:secret@issuer.example.test", wantErr: "invalid issuer"},
		{name: "issuer with query", generated: valid, issuer: "https://issuer.example.test?token=secret", wantErr: "invalid issuer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildUIAuthConfig(tt.generated, acl, tt.issuer)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("buildUIAuthConfig() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestIssuerFromEnvironment(t *testing.T) {
	t.Setenv("ZITADEL_ISSUER", "")
	if got := issuerFromEnvironment("citius-auth.localhost", "443", false); got != "https://citius-auth.localhost" {
		t.Fatalf("default TLS issuer = %q", got)
	}
	if got := issuerFromEnvironment("citius-auth.localhost", "8080", true); got != "http://citius-auth.localhost:8080" {
		t.Fatalf("insecure issuer = %q", got)
	}
	t.Setenv("ZITADEL_ISSUER", " https://identity.example.test/ ")
	if got := issuerFromEnvironment("ignored", "443", false); got != "https://identity.example.test/" {
		t.Fatalf("configured issuer = %q", got)
	}
}

type fakeIdentityAdmin struct {
	calls         []string
	humanPassword string
	machineErr    error
}

type fakeIdentityVerifier struct {
	input  admin.HumanAuthConfigurationInput
	result *admin.HumanAuthConfigurationResult
	err    error
}

func (f *fakeIdentityVerifier) VerifyHumanAuthConfiguration(_ context.Context, input admin.HumanAuthConfigurationInput) (*admin.HumanAuthConfigurationResult, error) {
	f.input = input
	return f.result, f.err
}

func (f *fakeIdentityAdmin) EnsureWebApplication(_ context.Context, in admin.WebApplicationInput) (*admin.WebApplicationResult, error) {
	f.calls = append(f.calls, "web:"+in.Name)
	return &admin.WebApplicationResult{ApplicationID: "web-app", ClientID: "web-client"}, nil
}

func (f *fakeIdentityAdmin) Onboard(_ context.Context, in admin.OnboardInput) (*admin.OnboardResult, error) {
	f.calls = append(f.calls, "machine:"+in.Username)
	if f.machineErr != nil {
		return nil, f.machineErr
	}
	return &admin.OnboardResult{UserID: "machine-user", ClientID: "machine-client"}, nil
}

func (f *fakeIdentityAdmin) OnboardHuman(_ context.Context, in admin.HumanOnboardInput) (*admin.HumanOnboardResult, error) {
	f.calls = append(f.calls, "human:"+in.Username)
	f.humanPassword = in.InitialPassword
	return &admin.HumanOnboardResult{UserID: "human-user", LoginName: "alice@example.test"}, nil
}

func TestPreserveKnownSecrets(t *testing.T) {
	previous := &generatedConfig{
		APIApp: admin.AppCredentials{ClientID: "api", ClientSecret: "api-secret"},
		Users: map[string]admin.OnboardResult{
			"kept":    {UserID: "1", ClientID: "kept", ClientSecret: "kept-secret"},
			"renamed": {UserID: "2", ClientID: "old-client", ClientSecret: "old-secret"},
			"fresh":   {UserID: "3", ClientID: "fresh", ClientSecret: "stale-secret"},
		},
	}
	next := &generatedConfig{
		APIApp: admin.AppCredentials{ClientID: "api"},
		Users: map[string]admin.OnboardResult{
			"kept":    {UserID: "1", ClientID: "kept"},
			"renamed": {UserID: "2", ClientID: "new-client"},
			"fresh":   {UserID: "3", ClientID: "fresh", ClientSecret: "new-secret"},
			"added":   {UserID: "4", ClientID: "added"},
		},
	}

	preserveKnownSecrets(previous, next)

	if next.APIApp.ClientSecret != "api-secret" {
		t.Errorf("api secret = %q, want preserved", next.APIApp.ClientSecret)
	}
	want := map[string]string{
		"kept":    "kept-secret", // same client, secret not returned: preserve
		"renamed": "",            // client ID changed: never reuse the old secret
		"fresh":   "new-secret",  // newly minted secret wins
		"added":   "",            // no previous credential
	}
	for name, secret := range want {
		if got := next.Users[name].ClientSecret; got != secret {
			t.Errorf("%s secret = %q, want %q", name, got, secret)
		}
	}
}

func TestPreserveKnownSecrets_changedAPIClient(t *testing.T) {
	previous := &generatedConfig{APIApp: admin.AppCredentials{ClientID: "old", ClientSecret: "old-secret"}}
	next := &generatedConfig{APIApp: admin.AppCredentials{ClientID: "new"}}
	preserveKnownSecrets(previous, next)
	if next.APIApp.ClientSecret != "" {
		t.Fatalf("api secret = %q, want empty for a changed client ID", next.APIApp.ClientSecret)
	}
	preserveKnownSecrets(nil, next)
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "generated-config.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte(`{"project_id":"p"}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != `{"project_id":"p"}` {
		t.Fatalf("content = %q, err = %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v", info.Mode().Perm(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}
