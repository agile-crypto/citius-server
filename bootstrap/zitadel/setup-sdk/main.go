// Package main provisions the Citius project, per-RPC permission catalog,
// pre-userinfo action, API application, and seed service users in a Zitadel
// instance brought up by ../bootstrap.sh.
//
// It is a separate Go module so that bootstrap-only dependencies
// (godotenv, the Zitadel admin SDK) do not pollute the main citius-server
// go.mod. It is run once after `bootstrap.sh up` and is idempotent.
//
//	cd bootstrap/zitadel/setup-sdk
//	go run .
//
// On success the program writes ../generated-config.json with the project,
// app credentials, and per-user client_id / client_secret values that
// bootstrap.sh slices into ../citius-zitadel.env.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"github.ibm.com/citius/zitadel-grpc-auth/admin"
)

const (
	// claimNamespace is the URN prefix under which all Citius custom claims
	// are projected into bearer tokens (urn:citius:permissions, etc.).
	claimNamespace = "urn:citius"

	// projectName is the Zitadel project that owns the API application
	// the Citius server uses for token introspection.
	projectName = "citius-api"

	// bootstrapTimeout bounds the total provisioning attempt.
	bootstrapTimeout = 2 * time.Minute
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	loadEnv()

	pat := mustEnv("ZITADEL_ADMIN_PAT")
	domain := envOr("ZITADEL_DOMAIN", "citius-auth.localhost")
	port := envOr("ZITADEL_PORT", "443")
	insecure := os.Getenv("ZITADEL_INSECURE") == "true"

	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	bs, err := admin.NewClient(ctx, admin.Config{
		Domain:    domain,
		Port:      port,
		Insecure:  insecure,
		PAT:       pat,
		Namespace: claimNamespace,
	})
	if err != nil {
		log.Fatalf("admin.NewClient (bootstrap): %v", err)
	}
	defer func() { _ = bs.Close() }()

	res, err := bs.Bootstrap(ctx, admin.BootstrapInput{
		ProjectName:    projectName,
		ClaimNamespace: claimNamespace,
		Operations:     citiusOperations(),
	})
	if err != nil {
		log.Fatalf("admin.Bootstrap: %v", err)
	}
	log.Printf("project provisioned: id=%s api_app_client_id=%s", res.ProjectID, res.APIApp.ClientID)

	on, err := admin.NewClient(ctx, admin.Config{
		Domain:    domain,
		Port:      port,
		Insecure:  insecure,
		PAT:       pat,
		Namespace: claimNamespace,
		ProjectID: res.ProjectID,
	})
	if err != nil {
		log.Fatalf("admin.NewClient (onboard): %v", err)
	}
	defer func() { _ = on.Close() }()

	users := map[string]admin.OnboardResult{}
	for _, spec := range citiusUsers() {
		u, err := on.Onboard(ctx, spec)
		if err != nil {
			log.Fatalf("onboard %s: %v", spec.Username, err)
		}
		log.Printf("onboarded service user: %s (client_id=%s)", spec.Username, u.ClientID)
		users[spec.Username] = *u
	}

	out := generatedConfig{
		ProjectID: res.ProjectID,
		ActionID:  res.ActionID,
		APIApp:    res.APIApp,
		Users:     users,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatalf("marshal generated-config.json: %v", err)
	}
	outPath := filepath.Join("..", "generated-config.json")
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	log.Printf("wrote %s", outPath)
}

// generatedConfig is the on-disk shape of generated-config.json.
// bootstrap.sh slices it into citius-zitadel.env.
type generatedConfig struct {
	ProjectID string                          `json:"project_id"`
	ActionID  string                          `json:"action_id"`
	APIApp    admin.AppCredentials            `json:"api_app"`
	Users     map[string]admin.OnboardResult  `json:"users"`
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

