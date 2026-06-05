package internal

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"

	"github.com/google/go-containerregistry/pkg/registry"
)

// Config holds all configuration for the proxy.
type Config struct {
	// UpstreamRegistry is the host[:port] of the registry to proxy to.
	// e.g. "registry-1.docker.io", "ghcr.io", "quay.io"
	UpstreamRegistry string

	// Policy decides whether a given (repo, ref) pull is allowed.
	// Defaults to AllowAll if nil.
	Policy Policy

	// Logger is the structured logger. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// NewHandler returns an http.Handler that is a policy-enforcing OCI
// pull-through proxy built entirely on go-containerregistry.
//
// Architecture:
//
//	manifestMiddleware  ← HTTP middleware: intercepts /v2/.../manifests/...
//	      │                  applies policy, fetches from upstream via remote.Get
//	      │
//	registry.New()      ← pkg/registry: handles /v2/, /v2/.../blobs/...
//	      │                  uses our blobHandler for blob GET/HEAD
//	      │
//	blobHandler         ← implements registry.BlobHandler + registry.BlobStatHandler
//	                         streams blobs from upstream via remote.Layer
//
// NOTE: pkg/registry has NO WithManifestHandler option (as of v0.20.x).
// The manifest interception is done by the HTTP middleware layer above registry.New().
func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.UpstreamRegistry == "" {
		return nil, fmt.Errorf("UpstreamRegistry must be set")
	}
	if cfg.Policy == nil {
		cfg.Policy = AllowAll
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// blobHandler satisfies both registry.BlobHandler (Get) and
	// registry.BlobStatHandler (Stat). The registry detects the latter
	// via a type assertion and uses it for HEAD /v2/.../blobs/<digest>.
	bh := &blobHandler{
		upstream: cfg.UpstreamRegistry,
		logger:   cfg.Logger,
	}

	// registry.New() builds the spec-compliant OCI Distribution v2 router.
	// registry.Logger takes a *log.Logger — we pass a discard logger because
	// our structured slog output in the handlers replaces it.
	discardLogger := log.New(io.Discard, "", 0)
	inner := registry.New(
		registry.WithBlobHandler(bh),
		registry.Logger(discardLogger),
	)

	// manifestMiddleware wraps inner: it intercepts manifest routes first,
	// applies policy, and fetches directly from upstream.
	// All other routes (version check, blob routes) fall through to inner.
	handler := manifestMiddleware(cfg.UpstreamRegistry, cfg.Policy, cfg.Logger, inner)

	return requestLogger(cfg.Logger, handler), nil
}

// requestLogger is a thin middleware that logs every HTTP request + response status.
func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		logger.Debug("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.code,
			"remote", r.RemoteAddr,
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}
