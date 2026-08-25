// Package main is the entry-point for the standalone CaaS gRPC server.
//
//  - Parse flags and build Config.
//  - Call NewServer (all wiring lives in wire.go).
//  - Load auth.Config from environment and Build interceptors.
//  - Optionally enable TLS (required when AUTH_ENABLED=true).
//  - Start a gRPC listener.
//  - Block until SIGINT / SIGTERM, then shut down gracefully.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	servicespb "github.com/agile-crypto/citius-server/gen/go/api/services"
	"github.com/agile-crypto/citius-server/internal/auth"
	"github.com/agile-crypto/citius-server/internal/cmd/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	addr := flag.String("addr", ":50051", "gRPC listen address")
	catalog := flag.String("catalog", defaultCatalogPath(), "path to standard_algorithms.json")
	tlsCert := flag.String("tls-cert", os.Getenv("TLS_CERT_FILE"), "path to TLS certificate (PEM); required when AUTH_ENABLED=true")
	tlsKey := flag.String("tls-key", os.Getenv("TLS_KEY_FILE"), "path to TLS private key (PEM); required when AUTH_ENABLED=true")
	fipsConfig := flag.String("fips-config", os.Getenv("OPENSSL_FIPS_CONFIG"),
		"path to an OpenSSL config activating the fips provider (see openssl.WithFIPS); "+
			"when unset, no openssl-fips provider is registered")
	enableReflection := flag.Bool("grpc-reflection", os.Getenv("GRPC_REFLECTION") == "true",
		"register the gRPC reflection service. Default false; production deployments should leave it off. "+
			"When true, reflection RPCs bypass authentication and authorization \u2014 a deliberate carve-out "+
			"so `grpcurl list` works. Treat enabling this as exposing the API surface to anonymous callers.")
	// TODO(mtls): add -mtls-ca to enable client-cert authentication as a defence-in-depth
	// layer alongside bearer-token introspection. Tracked in the auth roadmap.
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	authCfg, err := auth.LoadFromEnv()
	if err != nil {
		log.Fatalf("auth config: %v", err)
	}
	// Reflection-on-with-auth-on means an unauthenticated peer can list
	// the API surface. The operator opts in by setting -grpc-reflection;
	// we honour that by carving reflection out of the policy map.
	authCfg.AllowUnauthenticatedReflection = *enableReflection

	authOpts, authCloser, err := auth.Build(authCfg)
	if err != nil {
		log.Fatalf("auth build: %v", err)
	}
	defer func() {
		if authCloser != nil {
			if cerr := authCloser.Close(); cerr != nil {
				log.Printf("auth closer: %v", cerr)
			}
		}
	}()

	serverOpts := append([]grpc.ServerOption{}, authOpts...)

	// Hard guard: bearer-token auth on plaintext is a credential-leak
	// vector. Require TLS whenever auth is enabled.
	if authCfg.Enabled {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatalf("AUTH_ENABLED=true requires -tls-cert and -tls-key (or TLS_CERT_FILE/TLS_KEY_FILE env)")
		}
	}
	if *tlsCert != "" && *tlsKey != "" {
		creds, credsErr := credentials.NewServerTLSFromFile(*tlsCert, *tlsKey)
		if credsErr != nil {
			log.Fatalf("load tls credentials: %v", credsErr)
		}
		serverOpts = append(serverOpts, grpc.Creds(creds))
		log.Printf("TLS enabled (cert=%s)", *tlsCert) //nolint:gosec // cert path from operator-controlled flag
	}

	handler, err := server.NewServer(ctx, server.Config{
		CatalogPath:    *catalog,
		FIPSConfigPath: *fipsConfig,
	})
	if err != nil {
		log.Fatalf("failed to initialise server: %v", err)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *addr, err)
	}
	defer lis.Close()

	srv := grpc.NewServer(serverOpts...)
	servicespb.RegisterCryptoServiceServer(srv, handler)
	servicespb.RegisterKeyManagementServiceServer(srv, handler)
	servicespb.RegisterCryptoPolicyServiceServer(srv, handler)
	if *enableReflection {
		reflection.Register(srv)
		log.Println("gRPC reflection registered")
	}

	// Graceful shutdown: when ctx is cancelled, stop accepting new RPCs.
	go func() {
		<-ctx.Done()
		log.Println("shutting down gRPC server...")
		srv.GracefulStop()
	}()

	log.Printf("CaaS gRPC server listening on %s (auth_enabled=%t)", lis.Addr(), authCfg.Enabled)
	if err := srv.Serve(lis); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

// defaultCatalogPath returns the path to standard_algorithms.json relative
// to this source file.  This works during `go run` and development
// TODO: In a production container the -catalog flag should be used explicitly.
func defaultCatalogPath() string {
	_, f, _, ok := runtime.Caller(0)
	if !ok {
		return "proto/standard_algorithms.json"
	}
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "proto", "standard_algorithms.json")
}
