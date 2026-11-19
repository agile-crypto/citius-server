package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// healthProbeTimeout bounds a single probe so a hung server fails the
// container healthcheck instead of blocking it.
const healthProbeTimeout = 3 * time.Second

// runHealthProbe calls grpc.health.v1.Health/Check on addr and returns an
// error unless the server reports SERVING. It lets the server binary act as
// its own container healthcheck, so the runtime image needs no extra probe
// tool.
//
// Over TLS the server certificate is verified against the system roots,
// which honour SSL_CERT_FILE, and against the host part of addr. The probe
// sends no bearer token: the server must run with -grpc-health, which also
// makes Health/Check a public method.
func runHealthProbe(ctx context.Context, addr string, plaintext bool) error {
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if plaintext {
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("health probe: dial %s: %w", addr, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return fmt.Errorf("health probe: check %s: %w", addr, err)
	}
	if s := resp.GetStatus(); s != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("health probe: %s reports %s", addr, s)
	}
	return nil
}
