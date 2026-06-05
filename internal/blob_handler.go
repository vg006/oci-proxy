package internal

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// blobHandler implements:
//   - registry.BlobHandler     → Get(ctx, repo, hash) (io.ReadCloser, error)
//   - registry.BlobStatHandler → Stat(ctx, repo, hash) (int64, error)
//
// registry.New() detects BlobStatHandler via type assertion on the value passed
// to WithBlobHandler. Both interfaces must be on the same struct.
//
// Policy is NOT applied here. The manifest middleware is the gatekeeper:
// a client cannot discover a blob digest without first fetching a manifest.
// Denying the manifest breaks the pull chain before blobs are ever requested.
type blobHandler struct {
	upstream string
	logger   *slog.Logger
}

// Get streams the compressed blob from upstream directly to the caller.
// registry.New() copies this reader into the HTTP response body.
func (h *blobHandler) Get(ctx context.Context, repo string, hash v1.Hash) (io.ReadCloser, error) {
	h.logger.Info("blob GET", "repo", repo, "digest", hash.String())

	layer, err := h.fetchLayer(ctx, repo, hash)
	if err != nil {
		h.logger.Error("blob GET failed", "repo", repo, "digest", hash.String(), "err", err)
		return nil, err
	}

	// layer.Compressed() opens the gzip stream lazily — the actual HTTP
	// request to upstream fires here, not in fetchLayer.
	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("opening compressed stream: %w", err)
	}

	size, _ := layer.Size()
	h.logger.Info("blob streaming", "repo", repo, "digest", hash.String(), "bytes", size)
	return rc, nil
}

// Stat returns the blob size without downloading content.
// Used by registry.New() for HEAD /v2/<repo>/blobs/<digest> responses.
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
// remote.Layer only fetches the descriptor (size + media type) lazily;
// the byte stream is opened when Compressed() is called.
func (h *blobHandler) fetchLayer(ctx context.Context, repo string, hash v1.Hash) (v1.Layer, error) {
	refStr := fmt.Sprintf("%s/%s@%s", h.upstream, repo, hash.String())

	digestRef, err := name.NewDigest(refStr, name.Insecure)
	if err != nil {
		return nil, fmt.Errorf("parsing digest ref %q: %w", refStr, err)
	}

	return remote.Layer(digestRef,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	)
}
