package main

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// startHealthServer serves the gRPC health service in plaintext on a free
// loopback port with the given overall status and returns its address.
func startHealthServer(t *testing.T, status healthpb.HealthCheckResponse_ServingStatus) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("", status)
	healthpb.RegisterHealthServer(srv, hs)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func TestRunHealthProbe_Serving(t *testing.T) {
	addr := startHealthServer(t, healthpb.HealthCheckResponse_SERVING)
	if err := runHealthProbe(context.Background(), addr, true); err != nil {
		t.Fatalf("expected healthy, got %v", err)
	}
}

func TestRunHealthProbe_NotServing(t *testing.T) {
	addr := startHealthServer(t, healthpb.HealthCheckResponse_NOT_SERVING)
	if err := runHealthProbe(context.Background(), addr, true); err == nil {
		t.Fatal("expected an error for NOT_SERVING")
	}
}

func TestRunHealthProbe_NoServer(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close() // nothing listens on addr anymore

	if err := runHealthProbe(context.Background(), addr, true); err == nil {
		t.Fatal("expected an error when no server is listening")
	}
}
