// Package main is the Citius bootstrap CLI for Zitadel. It owns three
// commands:
//
//	setup-auth validate -acl PATH
//	    Parse and validate an ACL file. No network calls, no PAT needed.
//	    Use this in CI to fail a PR that introduces a typo'd permission.
//
//	setup-auth apply    -acl PATH [-dry-run]
//	    Bootstrap the citius-api project and per-RPC permission catalog
//	    (idempotent), then onboard every user in the ACL. Writes the same
//	    ../generated-config.json that bootstrap.sh slices into
//	    citius-zitadel.env.
//
//	setup-auth users    -acl PATH [-dry-run]
//	   Reconcile the optional Web application and onboard users, reusing
//	   the project_id from existing ../generated-config.json. Use this for
//	   incremental ACL edits when the project + catalog already exist.
//
// Required environment for `apply` and `users`:
//
//	ZITADEL_ADMIN_PAT       - PAT with org-owner / project-owner scope
//	ZITADEL_DOMAIN          - default citius-auth.localhost
//	ZITADEL_PORT            - default 443
//	ZITADEL_INSECURE        - "true" to disable TLS (local-only)
//	<password_env>          - each human user's initial password variable
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
	"os"
	"path/filepath"
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

Commands:
  validate   Parse and validate an ACL file. No network calls.
  apply      Bootstrap project + RPC catalog, then onboard users from ACL.
  users      Reconcile the Web app and users against an existing project.

Environment (apply, users):
  ZITADEL_ADMIN_PAT  required - PAT with org/project owner scope
  ZITADEL_DOMAIN     default citius-auth.localhost
  ZITADEL_PORT       default 443
  ZITADEL_INSECURE   "true" to disable TLS (local-only)
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
	if err := writeGeneratedConfig(out); err != nil {
		log.Printf("write %s: %v", generatedConfigPath, err)
		return 1
	}
	log.Printf("wrote %s", generatedConfigPath)
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
	if existing.Users == nil {
		existing.Users = map[string]admin.OnboardResult{}
	}
	for k, v := range identities.MachineUsers {
		existing.Users[k] = v
	}
	if existing.HumanUsers == nil {
		existing.HumanUsers = map[string]admin.HumanOnboardResult{}
	}
	for k, v := range identities.HumanUsers {
		existing.HumanUsers[k] = v
	}
	if identities.WebApplication != nil {
		existing.WebApplication = identities.WebApplication
	}
	if err := writeGeneratedConfig(*existing); err != nil {
		log.Printf("write %s: %v", generatedConfigPath, err)
		return 1
	}
	log.Printf("wrote %s", generatedConfigPath)
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

func writeGeneratedConfig(c generatedConfig) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(generatedConfigPath, data, 0o600)
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
