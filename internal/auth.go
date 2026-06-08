package internal

// auth.go
//
// Auth strategy: proxy-passthrough model.
//
// The OCI auth flow (Docker Token Spec) is:
//
//   1. Runtime → GET /v2/                  → 401 + WWW-Authenticate (from upstream, relayed)
//   2. Runtime → GET <realm>?scope=...     → token (reverse-proxied through to upstream)
//   3. Runtime → GET /v2/<repo>/manifests/ → Authorization: Bearer <token>
//
// The proxy never issues its own tokens and never touches credentials.
// It relays the upstream challenge, reverse-proxies the token fetch, then
// reuses the token the runtime obtained when calling upstream on its behalf.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// ── Challenge cache ───────────────────────────────────────────────────────────

type challengeCache struct {
	mu      sync.RWMutex
	entries map[string]cachedChallenge
}

type cachedChallenge struct {
	header  string
	fetchAt time.Time
}

const challengeTTL = 10 * time.Minute

var globalChallengeCache = &challengeCache{
	entries: make(map[string]cachedChallenge),
}

func (c *challengeCache) get(upstream string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[upstream]
	if !ok || time.Since(e.fetchAt) > challengeTTL {
		return "", false
	}
	return e.header, true
}

func (c *challengeCache) set(upstream, header string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[upstream] = cachedChallenge{header: header, fetchAt: time.Now()}
}

// ── Context key for the bearer token ─────────────────────────────────────────

type tokenContextKey struct{}

// withToken stores the bearer token in the request context.
func withToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// tokenFromContext retrieves the bearer token stored by authMiddleware.
// Returns "" for unauthenticated / anonymous requests.
func tokenFromContext(ctx context.Context) string {
	v, _ := ctx.Value(tokenContextKey{}).(string)
	return v
}

// ── Auth middleware ───────────────────────────────────────────────────────────

// authMiddleware sits at the outermost layer of the request pipeline:
//
//	authMiddleware → manifestMiddleware → registry.New() + blobHandler
//
// It handles three cases:
//   - /v2/              → ping upstream, relay its 401 + WWW-Authenticate
//   - /v2/token, /v2/auth → reverse-proxy directly to upstream (credential exchange)
//   - everything else   → extract Bearer token from request, attach to context
func authMiddleware(upstream string, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/" || r.URL.Path == "/v2":
			handleVersionCheck(w, r, upstream, logger)

		case isTokenEndpoint(r.URL.Path):
			relayToUpstream(w, r, upstream, logger)

		default:
			// Attach the token from the Authorization header to the context.
			// Downstream handlers use tokenFromContext(r.Context()) to build
			// an authn.Authenticator that replays this token upstream.
			token := extractBearerToken(r)
			next.ServeHTTP(w, r.WithContext(withToken(r.Context(), token)))
		}
	})
}

// ── /v2/ version check ────────────────────────────────────────────────────────

// handleVersionCheck pings the real upstream, takes its WWW-Authenticate
// challenge, and relays it back to the runtime. The runtime then knows the
// correct token realm and service values to use when fetching a token.
func handleVersionCheck(w http.ResponseWriter, r *http.Request, upstream string, logger *slog.Logger) {
	// If the client already has a Bearer token (e.g. docker login's final
	// verification step), return 200 immediately. The token was issued by the
	// upstream auth server and will be validated on real API calls.
	if extractBearerToken(r) != "" {
		logger.Debug("version check: client has token, returning 200", "upstream", upstream)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}

	if challenge, ok := globalChallengeCache.get(upstream); ok {
		logger.Debug("version check: serving cached challenge", "upstream", upstream)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	reg, err := name.NewRegistry(upstream, name.Insecure)
	if err != nil {
		logger.Error("version check: bad upstream", "upstream", upstream, "err", err)
		http.Error(w, "bad upstream", http.StatusInternalServerError)
		return
	}

	ch, err := transport.Ping(r.Context(), reg, http.DefaultTransport)
	if err != nil {
		logger.Error("version check: upstream ping failed", "upstream", upstream, "err", err)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}

	// Open registry (no auth required).
	if ch.Scheme == "" {
		logger.Info("version check: upstream is open (no auth)", "upstream", upstream)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}

	challengeHeader := buildWWWAuthenticate(ch)
	globalChallengeCache.set(upstream, challengeHeader)

	logger.Info("version check: relaying auth challenge",
		"upstream", upstream, "scheme", ch.Scheme)

	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("WWW-Authenticate", challengeHeader)
	w.WriteHeader(http.StatusUnauthorized)
}

// ── Token endpoint passthrough ────────────────────────────────────────────────

// relayToUpstream reverse-proxies the request (including query params, headers,
// and body) directly to the upstream registry. Used for /v2/token and /v2/auth
// so the runtime can exchange its credentials for a bearer token without the
// proxy needing to see or handle credentials at all.
func relayToUpstream(w http.ResponseWriter, r *http.Request, upstream string, logger *slog.Logger) {
	// Use http for localhost/127.0.0.1 (test servers, local registries),
	// https for everything else.
	scheme := upstreamScheme(upstream)
	target, err := url.Parse(fmt.Sprintf("%s://%s", scheme, upstream))
	if err != nil {
		logger.Error("relay: bad upstream URL", "upstream", upstream, "err", err)
		http.Error(w, "bad upstream", http.StatusInternalServerError)
		return
	}

	logger.Info("relay: forwarding token request to upstream",
		"path", r.URL.Path, "upstream", upstream)

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("relay: upstream error", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
	}

	r2 := r.Clone(r.Context())
	r2.Host = target.Host
	proxy.ServeHTTP(w, r2)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isTokenEndpoint returns true for any path that is a registry token/auth
// endpoint. This covers:
//   - Docker Hub style:  /v2/token, /v2/auth
//   - Harbor style:      /service/token
//   - Generic patterns:  anything ending in /token or /auth under known prefixes
func isTokenEndpoint(path string) bool {
	return path == "/v2/token" ||
		path == "/v2/auth" ||
		strings.HasPrefix(path, "/v2/token/") ||
		strings.HasPrefix(path, "/v2/auth/") ||
		path == "/service/token" || // Harbor
		strings.HasPrefix(path, "/service/token")
}

// upstreamScheme returns "http" for localhost/127.0.0.1 upstreams (test servers,
// local registries) and "https" for everything else.
func upstreamScheme(upstream string) string {
	if strings.HasPrefix(upstream, "127.0.0.1") ||
		strings.HasPrefix(upstream, "localhost") ||
		strings.HasPrefix(upstream, "[::1]") {
		return "http"
	}
	return "https"
}

// buildWWWAuthenticate reconstructs a WWW-Authenticate header string from the
// parsed transport.Challenge, e.g.:
//
//	Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
func buildWWWAuthenticate(ch *transport.Challenge) string {
	if len(ch.Parameters) == 0 {
		return ch.Scheme
	}
	parts := make([]string, 0, len(ch.Parameters))
	for k, v := range ch.Parameters {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return fmt.Sprintf("%s %s", ch.Scheme, strings.Join(parts, ","))
}

// extractBearerToken parses "Authorization: Bearer <token>" from the request.
// Returns "" if the header is absent or not a bearer token.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
