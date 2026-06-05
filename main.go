package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/demo/oci-proxy/internal"
	"github.com/joho/godotenv"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	err := godotenv.Load()
	if err != nil {
		slog.Warn("no .env file found, relying on environment variables")
	}

	upstream := os.Getenv("UPSTREAM_REGISTRY")
	if upstream == "" {
		upstream = "registry-1.docker.io"
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":5000"
	}

	slog.Info("starting OCI proxy",
		"listen", listenAddr,
		"upstream", upstream,
	)
	slog.Info("policy: blocking image name 'busybox' and tag 'latest'")

	policy := internal.NewCompositePolicy(
		internal.DenyImageName("busybox"),
		internal.DenyTag("latest"),
	)

	handler, err := internal.NewHandler(internal.Config{
		UpstreamRegistry: upstream,
		Policy:           policy,
		Logger:           slog.Default(),
	})
	if err != nil {
		slog.Error("failed to create proxy handler", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // blobs can be large
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		fmt.Printf("\n  OCI Pull-Through Proxy\n")
		fmt.Printf("  ─────────────────────────────────────────\n")
		fmt.Printf("  Listening : http://localhost%s\n", listenAddr)
		fmt.Printf("  Upstream  : %s\n", upstream)
		fmt.Printf("  Blocked   : image=busybox, tag=latest\n")
		fmt.Printf("  ─────────────────────────────────────────\n\n")
		fmt.Printf("  Test pulls:\n")
		fmt.Printf("    docker pull localhost%s/library/alpine:3.19  → ALLOW\n", listenAddr)
		fmt.Printf("    docker pull localhost%s/library/nginx:1.25   → ALLOW\n", listenAddr)
		fmt.Printf("    docker pull localhost%s/library/alpine:latest → DENY (latest)\n", listenAddr)
		fmt.Printf("    docker pull localhost%s/library/busybox:1.36 → DENY (busybox)\n\n", listenAddr)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
