// Package main is the entry-point for the standalone CaaS gRPC server.
//
//  - Parse flags and build Config.
//  - Call NewServer (all wiring lives in wire.go).
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
	"github.ibm.com/citius/citius-server/internal/cmd/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	addr := flag.String("addr", ":50051", "gRPC listen address")
	catalog := flag.String("catalog", defaultCatalogPath(), "path to standard_algorithms.json")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	srv := grpc.NewServer()
	servicespb.RegisterCryptoServiceServer(srv, handler)
	reflection.Register(srv)

	// Graceful shutdown: when ctx is cancelled, stop accepting new RPCs.
	go func() {
		<-ctx.Done()
		log.Println("shutting down gRPC server...")
		srv.GracefulStop()
	}()

	log.Printf("CaaS gRPC server listening on %s", lis.Addr())
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
