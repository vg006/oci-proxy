package internal

// manifest_handler.go
//
// pkg/registry (v0.20.x) does NOT expose a ManifestHandler interface or a
// WithManifestHandler option. All manifest routing is handled inside the
// unexported `manifests` struct of registry.New().
//
// The correct intercept point is a plain HTTP middleware that matches the OCI
// manifest URL pattern BEFORE the request reaches registry.New(). This file
// implements that middleware and the upstream fetch logic.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// manifestPattern matches /v2/<repo>/manifests/<ref>
// where <repo> may contain multiple path segments (e.g. "library/nginx").
var manifestPattern = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)

// manifestMiddleware returns an http.Handler that:
//  1. Intercepts GET and HEAD /v2/<repo>/manifests/<ref>
//  2. Evaluates the policy — returns 403 JSON on deny
//  3. Fetches the manifest from upstream via remote.Get and writes it directly
//  4. Passes every other request through to `next` (registry.New())
func manifestMiddleware(upstream string, policy Policy, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only intercept manifest routes; everything else goes to the registry handler.
		m := manifestPattern.FindStringSubmatch(r.URL.Path)
		if m == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}

		repo := m[1]
		ref := m[2]

		logger.Info("manifest request", "method", r.Method, "repo", repo, "ref", ref)

		// ── 1. Policy ─────────────────────────────────────────────────────────
		if d := policy.Evaluate(repo, ref); !d.Allow {
			logger.Warn("manifest DENIED", "repo", repo, "ref", ref, "reason", d.Reason)
			writeOCIError(w, http.StatusForbidden, "DENIED", d.Reason)
			return
		}

		// ── 2. Build the upstream reference ───────────────────────────────────
		var refStr string
		if strings.HasPrefix(ref, "sha256:") {
			refStr = fmt.Sprintf("%s/%s@%s", upstream, repo, ref)
		} else {
			refStr = fmt.Sprintf("%s/%s:%s", upstream, repo, ref)
		}

		parsed, err := name.ParseReference(refStr, name.Insecure)
		if err != nil {
			logger.Error("bad upstream reference", "ref", refStr, "err", err)
			writeOCIError(w, http.StatusBadRequest, "NAME_INVALID", err.Error())
			return
		}

		// ── 3. Fetch from upstream ─────────────────────────────────────────────
		// remote.Get returns a *remote.Descriptor which carries:
		//   .Manifest    []byte         — raw manifest bytes
		//   .MediaType   types.MediaType
		//   .Digest      v1.Hash
		//   .Size        int64
		desc, err := remote.Get(parsed,
			remote.WithContext(r.Context()),
			remote.WithAuth(authn.Anonymous),
		)
		if err != nil {
			status := statusFromErr(err)
			logger.Error("upstream manifest fetch failed",
				"repo", repo, "ref", ref, "err", err, "status", status)
			writeOCIError(w, status, "MANIFEST_UNKNOWN", err.Error())
			return
		}

		logger.Info("manifest ALLOWED",
			"repo", repo, "ref", ref,
			"digest", desc.Digest.String(),
			"mediaType", string(desc.MediaType),
			"size", len(desc.Manifest),
		)

		// ── 4. Write the response ──────────────────────────────────────────────
		w.Header().Set("Content-Type", string(desc.MediaType))
		w.Header().Set("Docker-Content-Digest", desc.Digest.String())

		if r.Method == http.MethodHead {
			// HEAD: headers only, no body
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(desc.Manifest)))
			w.WriteHeader(http.StatusOK)
			return
		}

		// GET: write raw manifest bytes
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(desc.Manifest)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(desc.Manifest)
	})
}

// statusFromErr extracts the HTTP status code from a transport.Error,
// falling back to 502 Bad Gateway for unknown errors.
func statusFromErr(err error) int {
	var te *transport.Error
	if errors.As(err, &te) {
		return te.StatusCode
	}
	return http.StatusBadGateway
}

// writeOCIError writes an OCI Distribution Spec-compliant JSON error body.
func writeOCIError(w http.ResponseWriter, httpStatus int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []map[string]string{
			{"code": code, "message": message},
		},
	})
}
