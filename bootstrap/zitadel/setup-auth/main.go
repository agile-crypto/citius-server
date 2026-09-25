// Package main is the Citius bootstrap CLI for Zitadel. It owns four
// commands:
//
//	setup-auth validate -acl PATH
//	    Parse and validate an ACL file. No network calls, no PAT needed.
//	    Use this in CI to fail a PR that introduces a typo'd permission.
//
//	setup-auth apply    -acl PATH [-dry-run]
//	    Bootstrap the citius-api project and per-RPC permission catalog
//	    (idempotent), then onboard every user in the ACL. Writes the secret
//	    ../generated-config.json used by bootstrap.sh and, when a Web app is
//	    declared, the non-secret ../citius-ui-auth.json.
//
//	setup-auth users    -acl PATH [-dry-run]
//	   Reconcile the optional Web application and onboard users, reusing
//	   the project_id from existing ../generated-config.json. Use this for
//	   incremental ACL edits when the project + catalog already exist.
//
//	setup-auth verify   -acl PATH
//	   Compare the declared human-login configuration with Zitadel using
//	   read-only APIs and report any drift.
//
// Required environment for `apply`, `users`, and `verify`:
//
//	ZITADEL_ADMIN_PAT       - PAT with org-owner / project-owner scope
//	ZITADEL_DOMAIN          - default citius-auth.localhost
//	ZITADEL_PORT            - default 443
//	ZITADEL_INSECURE        - "true" to disable TLS (local-only)
//	<password_env>          - each human user's initial password variable
//	                          (`apply` and `users` only)
//
// The CLI is a separate Go module (see go.mod) so bootstrap-only deps
// (yaml, the Zitadel admin SDK) don't pollute the main citius-server build.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agile-crypto/zitadel-grpc-auth/admin"
	"github.com/joho/godotenv"
)

const (
	// claimNamespace is the URN prefix under which all Citius custom claims
	// are projected into bearer tokens (urn:citius:permissions, etc.).
	claimNamespace = "urn:citius"

	// projectName is the Zitadel project that owns the API application
	// the Citius server uses for token introspection.
	projectName = "citius-api"

	// bootstrapTimeout bounds the total provisioning attempt for any
	// single subcommand invocation.
	bootstrapTimeout = 2 * time.Minute

	// defaultACL is resolved relative to the setup-auth/ working directory
	// (../acl.yaml). The CLI is normally invoked from setup-auth/ via
	// bootstrap.sh; the operator can always override with -acl.
	defaultACL = "../acl.yaml"

	// generatedConfigPath is the contract with bootstrap.sh.
	generatedConfigPath = "../generated-config.json"

	// uiAuthConfigPath is safe to provide to the UI process. It contains
	// public OIDC coordinates and identity labels, never credentials.
	uiAuthConfigPath = "../citius-ui-auth.json"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "validate":
		os.Exit(runValidate(args))
	case "apply":
		os.Exit(runApply(args))
	case "users":
		os.Exit(runUsers(args))
	case "verify":
		os.Exit(runVerify(args))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `setup-auth - Citius Zitadel bootstrap CLI

Usage:
  setup-auth validate -acl PATH
  setup-auth apply    -acl PATH [-dry-run]
  setup-auth users    -acl PATH [-dry-run]
  setup-auth verify   -acl PATH

Commands:
  validate   Parse and validate an ACL file. No network calls.
  apply      Bootstrap project + RPC catalog, then onboard users from ACL.
  users      Reconcile the Web app and users against an existing project.
  verify     Read Zitadel configuration and report human-login drift.

Environment (apply, users, verify):
  ZITADEL_ADMIN_PAT  required - PAT with org/project owner scope
  ZITADEL_DOMAIN     default citius-auth.localhost
  ZITADEL_PORT       default 443
  ZITADEL_INSECURE   "true" to disable TLS (local-only)

Additional environment (apply, users):
  <password_env>     each human user's initial password variable

Default ACL path: %s
`, defaultACL)
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

func runValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	aclPath := fs.String("acl", defaultACL, "path to ACL file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	acl, err := loadACL(*aclPath)
	if err != nil {
		log.Printf("validate: %v", err)
		return 1
	}
	log.Printf("ACL OK: %d user(s) in %s", acl.userCount(), *aclPath)
	for _, u := range acl.MachineUsers {
		log.Printf("  %s: %d permission(s), key_allow=%v, policy_allow=%v",
			u.Username, len(u.Permissions),
			u.KeyAccess.AllowedKeyPatterns, u.PolicyAccess.AllowedPolicyPatterns)
	}
	for _, u := range acl.HumanUsers {
		log.Printf("  %s (human): %d permission(s), key_allow=%v, policy_allow=%v",
			u.Username, len(u.Permissions),
			u.KeyAccess.AllowedKeyPatterns, u.PolicyAccess.AllowedPolicyPatterns)
	}
	return 0
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

func runApply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	aclPath := fs.String("acl", defaultACL, "path to ACL file")
	dryRun := fs.Bool("dry-run", false, "validate ACL + connect, but skip mutations")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	loadEnv()
	acl, err := loadACL(*aclPath)
	if err != nil {
		log.Printf("apply: %v", err)
		return 1
	}

	pat := mustEnv("ZITADEL_ADMIN_PAT")
	domain := envOr("ZITADEL_DOMAIN", "citius-auth.localhost")
	port := envOr("ZITADEL_PORT", "443")
	insecure := os.Getenv("ZITADEL_INSECURE") == "true"

	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	bs, err := admin.NewClient(ctx, admin.Config{
		Domain: domain, Port: port, Insecure: insecure, PAT: pat, Namespace: claimNamespace,
	})
	if err != nil {
		log.Printf("admin.NewClient (bootstrap): %v", err)
		return 1
	}
	defer func() { _ = bs.Close() }()

	if *dryRun {
		log.Printf("dry-run: would bootstrap project %q with %d operations, reconcile_web=%t, and onboard %d machine plus %d human user(s)",
			projectName, len(citiusOperations()), acl.WebApplication != nil,
			len(acl.MachineUsers), len(acl.HumanUsers))
		return 0
	}

	res, err := bs.Bootstrap(ctx, admin.BootstrapInput{
		ProjectName:    projectName,
		ClaimNamespace: claimNamespace,
		Operations:     citiusOperations(),
	})
	if err != nil {
		log.Printf("admin.Bootstrap: %v", err)
		return 1
	}
	log.Printf("project provisioned: id=%s api_app_client_id=%s", res.ProjectID, res.APIApp.ClientID)

	identities, err := reconcileIdentities(ctx, domain, port, insecure, pat, res.ProjectID, acl)
	if err != nil {
		log.Printf("reconcile identities: %v", err)
		return 1
	}

	out := generatedConfig{
		ProjectID:      res.ProjectID,
		ActionID:       res.ActionID,
		APIApp:         res.APIApp,
		WebApplication: identities.WebApplication,
		Users:          identities.MachineUsers,
		HumanUsers:     identities.HumanUsers,
	}
	if previous, readErr := readGeneratedConfig(); readErr == nil {
		preserveKnownSecrets(previous, &out)
	}
	wroteUI, err := writeBootstrapConfigs(out, acl, issuerFromEnvironment(domain, port, insecure))
	if err != nil {
		log.Printf("write bootstrap configuration: %v", err)
		return 1
	}
	logWrittenConfigs(wroteUI)
	return 0
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

func runUsers(args []string) int {
	fs := flag.NewFlagSet("users", flag.ContinueOnError)
	aclPath := fs.String("acl", defaultACL, "path to ACL file")
	dryRun := fs.Bool("dry-run", false, "validate ACL + connect, but skip mutations")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	loadEnv()
	acl, err := loadACL(*aclPath)
	if err != nil {
		log.Printf("users: %v", err)
		return 1
	}

	existing, err := readGeneratedConfig()
	if err != nil {
		log.Printf("users: %v (run `apply` first to bootstrap the project)", err)
		return 1
	}

	pat := mustEnv("ZITADEL_ADMIN_PAT")
	domain := envOr("ZITADEL_DOMAIN", "citius-auth.localhost")
	port := envOr("ZITADEL_PORT", "443")
	insecure := os.Getenv("ZITADEL_INSECURE") == "true"

	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	if *dryRun {
		log.Printf("dry-run: would reconcile_web=%t and onboard %d machine plus %d human user(s) into project %s",
			acl.WebApplication != nil, len(acl.MachineUsers), len(acl.HumanUsers), existing.ProjectID)
		return 0
	}

	identities, err := reconcileIdentities(ctx, domain, port, insecure, pat, existing.ProjectID, acl)
	if err != nil {
		log.Printf("reconcile identities: %v", err)
		return 1
	}

	// Merge over any users that disappeared from the ACL but stay in the
	// file. We deliberately do NOT delete users from Zitadel here — that
	// is destructive and should be an explicit operator action.
	previous := *existing
	previous.Users = make(map[string]admin.OnboardResult, len(existing.Users))
	for k, v := range existing.Users {
		previous.Users[k] = v
	}
	if existing.Users == nil {
		existing.Users = map[string]admin.OnboardResult{}
	}
	for k, v := range identities.MachineUsers {
		existing.Users[k] = v
	}
	preserveKnownSecrets(&previous, existing)
	if existing.HumanUsers == nil {
		existing.HumanUsers = map[string]admin.HumanOnboardResult{}
	}
	for k, v := range identities.HumanUsers {
		existing.HumanUsers[k] = v
	}
	if identities.WebApplication != nil {
		existing.WebApplication = identities.WebApplication
	}
	wroteUI, err := writeBootstrapConfigs(*existing, acl, issuerFromEnvironment(domain, port, insecure))
	if err != nil {
		log.Printf("write bootstrap configuration: %v", err)
		return 1
	}
	logWrittenConfigs(wroteUI)
	return 0
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	aclPath := fs.String("acl", defaultACL, "path to ACL file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	loadEnv()
	acl, err := loadACL(*aclPath)
	if err != nil {
		log.Printf("verify: %v", err)
		return 1
	}
	existing, err := readGeneratedConfig()
	if err != nil {
		log.Printf("verify: %v (run `apply` first to bootstrap the project)", err)
		return 1
	}

	pat := mustEnv("ZITADEL_ADMIN_PAT")
	domain := envOr("ZITADEL_DOMAIN", "citius-auth.localhost")
	port := envOr("ZITADEL_PORT", "443")
	insecure := os.Getenv("ZITADEL_INSECURE") == "true"
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	client, err := admin.NewClient(ctx, admin.Config{
		Domain: domain, Port: port, Insecure: insecure, PAT: pat,
		Namespace: claimNamespace, ProjectID: existing.ProjectID,
	})
	if err != nil {
		log.Printf("verify: admin.NewClient: %v", err)
		return 1
	}
	defer func() { _ = client.Close() }()

	result, err := verifyIdentityResources(ctx, client, acl)
	if err != nil {
		log.Printf("verify: %v", err)
		return 1
	}
	if !result.Current {
		log.Printf("human authentication configuration has %d drift item(s)", len(result.Drift))
		for _, drift := range result.Drift {
			log.Printf("  %s.%s: expected=%s actual=%s", drift.Resource, drift.Field, drift.Expected, drift.Actual)
		}
		return 1
	}
	log.Printf("human authentication configuration is current for project %s", result.ProjectID)
	return 0
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

type identityAdmin interface {
	EnsureWebApplication(context.Context, admin.WebApplicationInput) (*admin.WebApplicationResult, error)
	Onboard(context.Context, admin.OnboardInput) (*admin.OnboardResult, error)
	OnboardHuman(context.Context, admin.HumanOnboardInput) (*admin.HumanOnboardResult, error)
}

type identityVerifier interface {
	VerifyHumanAuthConfiguration(context.Context, admin.HumanAuthConfigurationInput) (*admin.HumanAuthConfigurationResult, error)
}

type identityResults struct {
	WebApplication *admin.WebApplicationResult
	MachineUsers   map[string]admin.OnboardResult
	HumanUsers     map[string]admin.HumanOnboardResult
}

func reconcileIdentities(
	ctx context.Context,
	domain, port string,
	insecure bool,
	pat, projectID string,
	acl *parsedACL,
) (*identityResults, error) {
	client, err := admin.NewClient(ctx, admin.Config{
		Domain: domain, Port: port, Insecure: insecure, PAT: pat,
		Namespace: claimNamespace, ProjectID: projectID,
	})
	if err != nil {
		return nil, fmt.Errorf("admin.NewClient: %w", err)
	}
	defer func() { _ = client.Close() }()
	return reconcileIdentityResources(ctx, client, acl)
}

func reconcileIdentityResources(ctx context.Context, client identityAdmin, acl *parsedACL) (*identityResults, error) {
	humanInputs, err := resolveHumanInputs(acl.HumanUsers)
	if err != nil {
		return nil, err
	}
	out := &identityResults{
		MachineUsers: make(map[string]admin.OnboardResult, len(acl.MachineUsers)),
		HumanUsers:   make(map[string]admin.HumanOnboardResult, len(acl.HumanUsers)),
	}
	if web := acl.webApplicationInput(); web != nil {
		result, err := client.EnsureWebApplication(ctx, *web)
		if err != nil {
			return nil, fmt.Errorf("ensure Web application %q: %w", web.Name, err)
		}
		log.Printf("reconciled Web application: %s (client_id=%s created=%t updated=%t)",
			web.Name, result.ClientID, result.Created, result.Updated)
		out.WebApplication = result
	}

	for _, spec := range acl.MachineUsers {
		u, err := client.Onboard(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("onboard machine user %q: %w", spec.Username, err)
		}
		log.Printf("onboarded service user: %s (client_id=%s)", spec.Username, u.ClientID)
		out.MachineUsers[spec.Username] = *u
	}

	for _, spec := range humanInputs {
		u, err := client.OnboardHuman(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("onboard human user %q: %w", spec.Username, err)
		}
		log.Printf("onboarded human user: %s (login_name=%s created=%t)", spec.Username, u.LoginName, u.Created)
		out.HumanUsers[spec.Username] = *u
	}
	return out, nil
}

func resolveHumanInputs(specs []aclHumanUser) ([]admin.HumanOnboardInput, error) {
	out := make([]admin.HumanOnboardInput, 0, len(specs))
	for _, spec := range specs {
		password := os.Getenv(spec.PasswordEnv)
		if password == "" {
			return nil, fmt.Errorf("required password env var %s for human user %q is empty", spec.PasswordEnv, spec.Username)
		}
		out = append(out, spec.onboardInput(password))
	}
	return out, nil
}

func verifyIdentityResources(ctx context.Context, client identityVerifier, acl *parsedACL) (*admin.HumanAuthConfigurationResult, error) {
	input, err := acl.humanAuthConfigurationInput()
	if err != nil {
		return nil, err
	}
	result, err := client.VerifyHumanAuthConfiguration(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("verify human authentication configuration: %w", err)
	}
	return result, nil
}

// generatedConfig is the on-disk shape of generated-config.json.
// bootstrap.sh slices this file into citius-zitadel.env.
type generatedConfig struct {
	ProjectID      string                              `json:"project_id"`
	ActionID       string                              `json:"action_id"`
	APIApp         admin.AppCredentials                `json:"api_app"`
	WebApplication *admin.WebApplicationResult         `json:"web_application,omitempty"`
	Users          map[string]admin.OnboardResult      `json:"users"`
	HumanUsers     map[string]admin.HumanOnboardResult `json:"human_users,omitempty"`
}

type uiAuthConfig struct {
	ProjectID string                      `json:"project_id"`
	Issuer    string                      `json:"issuer"`
	Audience  string                      `json:"audience"`
	WebApp    uiWebApplicationConfig      `json:"web_app"`
	DemoUsers map[string]uiDemoUserConfig `json:"demo_users"`
}

type uiWebApplicationConfig struct {
	ClientID               string   `json:"client_id"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	EnableRefreshTokens    bool     `json:"enable_refresh_tokens"`
}

type uiDemoUserConfig struct {
	UserID      string `json:"user_id"`
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
}

func writeBootstrapConfigs(generated generatedConfig, acl *parsedACL, issuer string) (bool, error) {
	ui, err := buildUIAuthConfig(generated, acl, issuer)
	if err != nil {
		return false, err
	}
	if err := writeGeneratedConfig(generated); err != nil {
		return false, fmt.Errorf("write %s: %w", generatedConfigPath, err)
	}
	if ui == nil {
		if err := os.Remove(uiAuthConfigPath); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("remove stale %s: %w", uiAuthConfigPath, err)
		}
		return false, nil
	}
	data, err := json.MarshalIndent(ui, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal UI auth configuration: %w", err)
	}
	if err := os.WriteFile(uiAuthConfigPath, data, 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", uiAuthConfigPath, err)
	}
	return true, nil
}

func logWrittenConfigs(wroteUI bool) {
	if wroteUI {
		log.Printf("wrote %s and %s", generatedConfigPath, uiAuthConfigPath)
		return
	}
	log.Printf("wrote %s", generatedConfigPath)
}

func buildUIAuthConfig(generated generatedConfig, acl *parsedACL, issuer string) (*uiAuthConfig, error) {
	web := acl.webApplicationInput()
	if web == nil {
		return nil, nil
	}
	if generated.ProjectID == "" {
		return nil, fmt.Errorf("cannot generate UI auth configuration: project_id is empty")
	}
	if generated.WebApplication == nil || generated.WebApplication.ClientID == "" {
		return nil, fmt.Errorf("cannot generate UI auth configuration: Web application client_id is empty")
	}
	parsedIssuer, err := url.Parse(issuer)
	if err != nil || parsedIssuer.Host == "" || parsedIssuer.User != nil || parsedIssuer.RawQuery != "" ||
		parsedIssuer.Fragment != "" || (parsedIssuer.Scheme != "https" && parsedIssuer.Scheme != "http") {
		return nil, fmt.Errorf("cannot generate UI auth configuration: invalid issuer %q", issuer)
	}

	demoUsers := make(map[string]uiDemoUserConfig, len(acl.HumanUsers))
	for _, human := range acl.HumanUsers {
		result, ok := generated.HumanUsers[human.Username]
		if !ok || result.UserID == "" {
			return nil, fmt.Errorf("cannot generate UI auth configuration: human user %q has no generated user_id", human.Username)
		}
		demoUsers[human.Username] = uiDemoUserConfig{
			UserID: result.UserID, LoginName: result.LoginName, DisplayName: human.DisplayName,
		}
	}

	return &uiAuthConfig{
		ProjectID: generated.ProjectID,
		Issuer:    strings.TrimRight(issuer, "/"),
		Audience:  "urn:zitadel:iam:org:project:id:" + generated.ProjectID + ":aud",
		WebApp: uiWebApplicationConfig{
			ClientID:               generated.WebApplication.ClientID,
			RedirectURIs:           append([]string(nil), web.RedirectURIs...),
			PostLogoutRedirectURIs: append([]string(nil), web.PostLogoutRedirectURIs...),
			EnableRefreshTokens:    web.EnableRefreshTokens,
		},
		DemoUsers: demoUsers,
	}, nil
}

func issuerFromEnvironment(domain, port string, insecure bool) string {
	if configured := strings.TrimSpace(os.Getenv("ZITADEL_ISSUER")); configured != "" {
		return configured
	}
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	host := domain
	if port != "" && port != "443" && !(scheme == "http" && port == "80") {
		host = net.JoinHostPort(domain, port)
	}
	return (&url.URL{Scheme: scheme, Host: host}).String()
}

func writeGeneratedConfig(c generatedConfig) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return writeFileAtomic(generatedConfigPath, data, 0o600)
}

// writeFileAtomic writes data to a temporary file in the target directory and
// renames it into place, so an interrupted run never leaves a truncated
// generated-config.json (which holds the only copy of the client secrets).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// preserveKnownSecrets carries client secrets from a previous
// generated-config.json into next. Zitadel returns a client secret only when
// the machine user or API application is created, so re-running apply/users
// against an already provisioned instance yields empty secrets. A previous
// secret is kept only when next has none and the client ID is unchanged; a
// new client ID means a new credential, whose old secret must not be reused.
func preserveKnownSecrets(previous, next *generatedConfig) {
	if previous == nil || next == nil {
		return
	}
	if next.APIApp.ClientSecret == "" && next.APIApp.ClientID == previous.APIApp.ClientID {
		next.APIApp.ClientSecret = previous.APIApp.ClientSecret
	}
	for name, user := range next.Users {
		old, ok := previous.Users[name]
		if ok && user.ClientSecret == "" && user.ClientID == old.ClientID {
			user.ClientSecret = old.ClientSecret
			next.Users[name] = user
		}
	}
}

func readGeneratedConfig() (*generatedConfig, error) {
	raw, err := os.ReadFile(generatedConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", generatedConfigPath, err)
	}
	var c generatedConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", generatedConfigPath, err)
	}
	if c.ProjectID == "" {
		return nil, fmt.Errorf("%s has empty project_id", generatedConfigPath)
	}
	return &c, nil
}

// loadEnv loads ../.env if present, falling back to ./.env. Missing file is
// not fatal — the program still works if every variable is exported.
func loadEnv() {
	for _, p := range []string{filepath.Join("..", ".env"), ".env"} {
		if err := godotenv.Load(p); err == nil {
			return
		}
	}
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("required env var %s is empty", k)
	}
	return v
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
