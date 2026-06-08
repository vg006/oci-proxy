package internal

// manifest_handler.go
//
// pkg/registry (v0.20.x) exposes no ManifestHandler hook. Manifest routing
// lives in the unexported `manifests` struct of registry.New().
//
// The correct intercept point is an HTTP middleware that matches the OCI
// manifest URL pattern before the request reaches registry.New(). This file
// implements that middleware and the upstream fetch using the bearer token
// the runtime already obtained (stored in the request context by authMiddleware).

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
// <repo> may contain multiple path segments (e.g. "library/nginx").
var manifestPattern = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)

// manifestMiddleware intercepts GET/HEAD /v2/<repo>/manifests/<ref>,
// applies policy, and fetches the manifest from upstream using the bearer
// token extracted from the request context by authMiddleware.
// All other paths are passed through to `next` (registry.New()).
func manifestMiddleware(upstream string, policy Policy, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// ── 2. Build upstream reference ───────────────────────────────────────
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

		// ── 3. Build authenticator from context token ─────────────────────────
		// authMiddleware extracted the runtime's Bearer token and stored it in
		// the context. We replay it on the upstream call via RegistryToken so
		// go-containerregistry forwards it as "Authorization: Bearer <token>".
		// Falls back to Anonymous for public registries (empty token).
		auth := authenticatorFromContext(r)

		// ── 4. Fetch manifest from upstream ───────────────────────────────────
		desc, err := remote.Get(parsed,
			remote.WithContext(r.Context()),
			remote.WithAuth(auth),
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

		// ── 5. Write response ─────────────────────────────────────────────────
		w.Header().Set("Content-Type", string(desc.MediaType))
		w.Header().Set("Docker-Content-Digest", desc.Digest.String())
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(desc.Manifest)))

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(desc.Manifest)
	})
}

// authenticatorFromContext builds an authn.Authenticator from the bearer token
// stored in the request context by authMiddleware.
// If no token is present (anonymous/public registry), returns authn.Anonymous.
func authenticatorFromContext(r *http.Request) authn.Authenticator {
	token := tokenFromContext(r.Context())
	if token == "" {
		return authn.Anonymous
	}
	// authn.FromConfig with RegistryToken causes go-containerregistry to send
	// "Authorization: Bearer <token>" on every upstream request — exactly what
	// the upstream registry expects after issuing the token to the runtime.
	return authn.FromConfig(authn.AuthConfig{
		RegistryToken: token,
	})
}

// statusFromErr extracts the HTTP status code from a transport.Error.
// Falls back to 502 Bad Gateway for unknown error types.
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
