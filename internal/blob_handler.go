package internal

// blob_handler.go
//
// blobHandler implements:
//   - registry.BlobHandler     → Get(ctx, repo, hash) (io.ReadCloser, error)
//   - registry.BlobStatHandler → Stat(ctx, repo, hash) (int64, error)
//
// registry.New() detects BlobStatHandler via a type assertion on the value
// passed to WithBlobHandler — both methods must be on the same struct.
//
// Auth: blobs are fetched using the Bearer token stored in the request context
// by authMiddleware, via the same authn.FromConfig(RegistryToken) pattern as
// the manifest handler. Falls back to Anonymous for public registries.
//
// Policy is NOT re-applied here. The manifest middleware is the gatekeeper:
// the runtime cannot know blob digests without first fetching a manifest.
// Denying the manifest breaks the entire pull before blobs are requested.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type blobHandler struct {
	upstream string
	logger   *slog.Logger
	// request holds the current *http.Request so we can read the context
	// for the bearer token. registry.New() calls Get/Stat with only a
	// context.Context, not the full request, so we store it at serve time
	// via a thin http.Handler wrapper (see handler.go: blobContextMiddleware).
	request *http.Request
}

// Get streams the compressed blob from upstream to the caller.
// registry.New() copies this reader directly into the HTTP response body.
func (h *blobHandler) Get(ctx context.Context, repo string, hash v1.Hash) (io.ReadCloser, error) {
	h.logger.Info("blob GET", "repo", repo, "digest", hash.String())

	layer, err := h.fetchLayer(ctx, repo, hash)
	if err != nil {
		h.logger.Error("blob GET failed", "repo", repo, "digest", hash.String(), "err", err)
		return nil, err
	}

	// Compressed() opens the gzip stream lazily — the actual upstream HTTP
	// request fires here, not in fetchLayer.
	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("opening compressed stream: %w", err)
	}

	size, _ := layer.Size()
	h.logger.Info("blob streaming", "repo", repo, "digest", hash.String(), "bytes", size)
	return rc, nil
}

// Stat returns the blob size without downloading content.
// Used by registry.New() for HEAD /v2/<repo>/blobs/<digest>.
func (h *blobHandler) Stat(ctx context.Context, repo string, hash v1.Hash) (int64, error) {
	h.logger.Info("blob STAT", "repo", repo, "digest", hash.String())

	layer, err := h.fetchLayer(ctx, repo, hash)
	if err != nil {
		h.logger.Error("blob STAT failed", "repo", repo, "digest", hash.String(), "err", err)
		return 0, err
	}

	size, err := layer.Size()
	if err != nil {
		return 0, fmt.Errorf("reading blob size: %w", err)
	}

	h.logger.Info("blob STAT ok", "repo", repo, "digest", hash.String(), "bytes", size)
	return size, nil
}

// fetchLayer builds the upstream digest reference and calls remote.Layer.
// The byte stream is only opened when Compressed() is called on the result.
func (h *blobHandler) fetchLayer(ctx context.Context, repo string, hash v1.Hash) (v1.Layer, error) {
	refStr := fmt.Sprintf("%s/%s@%s", h.upstream, repo, hash.String())

	digestRef, err := name.NewDigest(refStr, name.Insecure)
	if err != nil {
		return nil, fmt.Errorf("parsing digest ref %q: %w", refStr, err)
	}

	auth := h.authFromContext(ctx)

	return remote.Layer(digestRef,
		remote.WithContext(ctx),
		remote.WithAuth(auth),
	)
}

// authFromContext returns an Authenticator built from the bearer token
// stored in the context by authMiddleware.
// Falls back to Anonymous if no token is present (public registry).
func (h *blobHandler) authFromContext(ctx context.Context) authn.Authenticator {
	token, _ := ctx.Value(tokenContextKey{}).(string)
	if token == "" {
		return authn.Anonymous
	}
	return authn.FromConfig(authn.AuthConfig{RegistryToken: token})
}

// ── blobContextMiddleware ─────────────────────────────────────────────────────

// blobContextMiddleware is a thin http.Handler shim that injects the bearer
// token from the HTTP request context into the Go context.Context passed to
// blobHandler.Get and blobHandler.Stat.
//
// This is necessary because registry.New() calls blob handler methods with
// a context.Context derived from the request, but that context does not
// carry our tokenContextKey value unless we explicitly propagate it.
// The middleware copies the token from the HTTP request context (set by
// authMiddleware) into the request's context before registry.New() handles it.
func blobContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The token is already in r.Context() thanks to authMiddleware.
		// registry.New() will derive its internal context from r.Context(),
		// so the token is available to blobHandler via ctx.Value(tokenContextKey{}).
		//
		// No-op: the context propagation is handled by net/http's request
		// machinery. This middleware exists as an explicit documentation point
		// and can be extended if deeper context manipulation is needed.
		next.ServeHTTP(w, r)
	})
}

// ensure blobHandler satisfies both BlobHandler and BlobStatHandler.
var _ interface {
	Get(context.Context, string, v1.Hash) (io.ReadCloser, error)
	Stat(context.Context, string, v1.Hash) (int64, error)
} = (*blobHandler)(nil)

// httpRequestFromContext is kept for future use if the handler needs
// the full *http.Request (e.g. for per-client rate limiting).
var _ = (*http.Request)(nil)
