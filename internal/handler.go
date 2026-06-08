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

// NewHandler returns an http.Handler that is a policy-enforcing, auth-aware
// OCI pull-through proxy built entirely on go-containerregistry.
//
// Request pipeline (outermost → innermost):
//
//	requestLogger          ← logs every HTTP request + status code
//	  │
//	  authMiddleware       ← /v2/: relay upstream challenge
//	  │                      /v2/token,/v2/auth: reverse-proxy to upstream
//	  │                      everything else: extract Bearer token → context
//	  │
//	  manifestMiddleware   ← GET/HEAD /v2/.../manifests/...:
//	  │                      policy check → upstream fetch via token in context
//	  │
//	  registry.New()       ← OCI Distribution v2 HTTP router (blob routes)
//	        │
//	        blobHandler    ← GET/HEAD /v2/.../blobs/...:
//	                          stream from upstream via token in context
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

	// ── 1. Blob handler ───────────────────────────────────────────────────────
	// Implements registry.BlobHandler (Get) + registry.BlobStatHandler (Stat).
	// registry.New() detects BlobStatHandler via type assertion.
	bh := &blobHandler{
		upstream: cfg.UpstreamRegistry,
		logger:   cfg.Logger,
	}

	// ── 2. Inner registry handler (blob routes + /v2/ boilerplate) ───────────
	// registry.Logger takes a *log.Logger — pass a discard logger since our
	// structured slog output in the handlers replaces it entirely.
	discardLogger := log.New(io.Discard, "", 0)
	inner := registry.New(
		registry.WithBlobHandler(bh),
		registry.Logger(discardLogger),
	)

	// ── 3. Manifest middleware (wraps inner) ──────────────────────────────────
	// Intercepts GET/HEAD /v2/<repo>/manifests/<ref> before they reach the
	// registry handler (which has no manifest hook). Applies policy and fetches
	// from upstream using the token from context.
	withManifests := manifestMiddleware(
		cfg.UpstreamRegistry, cfg.Policy, cfg.Logger, inner,
	)

	// ── 4. Auth middleware (outermost content handler) ────────────────────────
	// Handles /v2/ challenge relay, /v2/token passthrough, and token extraction.
	withAuth := authMiddleware(cfg.UpstreamRegistry, cfg.Logger, withManifests)

	// ── 5. Request logger ─────────────────────────────────────────────────────
	return requestLogger(cfg.Logger, withAuth), nil
}

// requestLogger logs every HTTP request with method, path, and response status.
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
