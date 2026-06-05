# oci-proxy

A minimal OCI pull-through proxy built on [`go-containerregistry`](https://github.com/google/go-containerregistry). It sits between container runtimes and an upstream registry, enforcing pull policy on every image request before forwarding it.

Built as a proof-of-concept for the [Harbor Satellite](https://satellite.container-registry.com/) proxy layer.

---

## How it works

```
Container Runtime
      │  GET /v2/<repo>/manifests/<ref>
      ▼
 manifestMiddleware        ← policy check → 403 on deny
      │  allowed
      ▼
 remote.Get(upstream)      ← fetch manifest from upstream registry
      │
      ▼  blob digests extracted by the runtime
 registry.New() + blobHandler
      │  GET /v2/<repo>/blobs/<digest>
      ▼
 remote.Layer(upstream)    ← stream blob to client
```

**Policy is enforced at the manifest layer.** A runtime cannot request a blob without first fetching a manifest, so denying the manifest breaks the pull before any layer data is transferred.

The proxy currently blocks:
- Any image named `busybox` (across all registries and namespaces)
- Any image tagged `latest`
- Digest-pinned pulls (`sha256:...`) bypass tag rules but are still subject to name rules

---

## Project structure

```
oci-proxy/
├── main.go                  entry point, wires config + HTTP server
└── proxy/
    ├── handler.go           NewHandler() — assembles the pipeline
    ├── manifest_handler.go  HTTP middleware intercepting manifest routes
    ├── blob_handler.go      BlobHandler + BlobStatHandler for layer streaming
    ├── policy.go            Policy interface, CompositePolicy, DenyImageName, DenyTag
    ├── policy_test.go       unit tests for all policy rules
    └── handler_test.go      integration tests for the HTTP layer
```

---

## Requirements

- Go 1.22+
- Network access to `registry-1.docker.io` (or another upstream registry)

---

## Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/your-org/oci-proxy
cd oci-proxy
go mod download
```

### 2. Run

```bash
go run .
```

Default behaviour: listens on `:5000`, proxies to Docker Hub (`registry-1.docker.io`).

Override with environment variables:

```bash
LISTEN_ADDR=:8080 UPSTREAM_REGISTRY=ghcr.io go run .
```

### 3. Test pulls

In a separate terminal:

```bash
# Allowed — pinned tag, not a blocked image name
docker pull localhost:5000/library/alpine:3.19
docker pull localhost:5000/library/nginx:1.25

# Denied — blocked tag
docker pull localhost:5000/library/alpine:latest
# Error response: {"errors":[{"code":"DENIED","message":"tag \"latest\" is blocked by policy"}]}

# Denied — blocked image name
docker pull localhost:5000/library/busybox:1.36
# Error response: {"errors":[{"code":"DENIED","message":"image name \"busybox\" is blocked by policy"}]}

# Digest pull of a blocked name — still denied (name rule applies to digest refs too)
docker pull localhost:5000/library/busybox@sha256:...
```

### 4. Run tests

```bash
go test ./... -v
```

---

## Configuration

| Environment variable  | Default                    | Description                        |
|-----------------------|----------------------------|------------------------------------|
| `LISTEN_ADDR`         | `:5000`                    | Address the proxy listens on       |
| `UPSTREAM_REGISTRY`   | `registry-1.docker.io`     | Upstream registry host to proxy to |

Policy rules are defined in `main.go` and applied by composing `proxy.Policy` values:

```go
policy := proxy.NewCompositePolicy(
    proxy.DenyImageName("busybox"),   // blocks by image name
    proxy.DenyTag("latest"),          // blocks by tag
)
```

To allow everything (no restrictions):

```go
policy := proxy.AllowAll
```

---

## Adding a custom policy rule

Implement the `proxy.Policy` interface:

```go
type Policy interface {
    Evaluate(repo, ref string) Decision
}
```

`repo` is the repository path (e.g. `library/nginx`), `ref` is the tag or digest. Return `Decision{Allow: false, Reason: "..."}` to deny, `Decision{Allow: true}` to pass.

Example — block all images not from `myorg`:

```go
proxy.PolicyFunc(func(repo, ref string) proxy.Decision {
    if !strings.HasPrefix(repo, "myorg/") {
        return proxy.Decision{Allow: false, Reason: "only myorg images are allowed"}
    }
    return proxy.Decision{Allow: true}
})
```

Compose multiple rules with `proxy.NewCompositePolicy(rule1, rule2, ...)`. Rules are evaluated in order; the first deny wins.

---

## Key design decisions

**Why `go-containerregistry` and not `distribution/distribution`?**

`pkg/registry` from `go-containerregistry` is already the replication dependency in Harbor Satellite (`crane`, `remote`). Using it for the proxy side means zero new modules. `distribution/distribution` pulls in storage drivers, a full auth stack, and garbage collection — too heavy for an embedded edge process, and it only supports one upstream registry per instance.

**Why HTTP middleware for manifests instead of a registry handler hook?**

`pkg/registry` (v0.20.x) exposes blob hooks (`BlobHandler`, `BlobStatHandler`) but has no `WithManifestHandler` option. Manifest routing is handled by the library's unexported internals. The correct intercept point is an HTTP middleware layer that matches the OCI manifest URL pattern (`/v2/<repo>/manifests/<ref>`) before the request reaches `registry.New()`.

**Why is policy only applied at the manifest layer?**

The OCI pull protocol is sequential: manifest first, then blobs. A client cannot know which blobs to request without first receiving a manifest. Denying the manifest breaks the entire pull without needing to inspect blob requests, which keeps the policy surface minimal and the logic easy to reason about.

---

## Dependencies

| Package | Role |
|---|---|
| `pkg/registry` | OCI Distribution v2 HTTP router (blob routes) |
| `pkg/v1/remote` | Fetch manifests and stream blobs from upstream |
| `pkg/name` | Parse and validate OCI image references |
| `pkg/authn` | Authentication (anonymous for public registries) |
| `pkg/v1/remote/transport` | HTTP status code extraction from upstream errors |
