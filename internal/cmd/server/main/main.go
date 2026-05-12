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

	servicespb "github.ibm.com/citius/citius-server/gen/go/services"
	"github.ibm.com/citius/citius-server/internal/auth"
	"github.ibm.com/citius/citius-server/internal/cmd/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	addr := flag.String("addr", ":50051", "gRPC listen address")
	catalog := flag.String("catalog", defaultCatalogPath(), "path to standard_algorithms.json")
	tlsCert := flag.String("tls-cert", os.Getenv("TLS_CERT_FILE"), "path to TLS certificate (PEM); required when AUTH_ENABLED=true")
	tlsKey := flag.String("tls-key", os.Getenv("TLS_KEY_FILE"), "path to TLS private key (PEM); required when AUTH_ENABLED=true")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	authCfg, err := auth.LoadFromEnv()
	if err != nil {
		log.Fatalf("auth config: %v", err)
	}

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
		creds, err := credentials.NewServerTLSFromFile(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("load tls credentials: %v", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(creds))
		log.Printf("TLS enabled (cert=%s)", *tlsCert)
	}

	handler, err := server.NewServer(ctx, server.Config{
		CatalogPath: *catalog,
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
	reflection.Register(srv)

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
