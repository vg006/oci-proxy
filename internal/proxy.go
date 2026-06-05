package internal

import (
	"fmt"
	"strings"
)

// Decision is the outcome of evaluating a policy rule.
type Decision struct {
	Allow  bool
	Reason string
}

// Policy decides whether a (repo, ref) pull is permitted.
// repo  = repository path, e.g. "library/nginx"
// ref   = tag or digest,   e.g. "1.25" or "sha256:abc..."
type Policy interface {
	Evaluate(repo, ref string) Decision
}

// PolicyFunc adapts a plain function to the Policy interface.
type PolicyFunc func(repo, ref string) Decision

func (f PolicyFunc) Evaluate(repo, ref string) Decision { return f(repo, ref) }

// CompositePolicy runs rules in order; first DENY wins, otherwise ALLOW.
type CompositePolicy struct{ rules []Policy }

func NewCompositePolicy(rules ...Policy) *CompositePolicy {
	return &CompositePolicy{rules: rules}
}

func (c *CompositePolicy) Evaluate(repo, ref string) Decision {
	for _, r := range c.rules {
		if d := r.Evaluate(repo, ref); !d.Allow {
			return d
		}
	}
	return Decision{Allow: true, Reason: "all rules passed"}
}

// DenyImageName blocks any repo whose last path segment matches name (case-insensitive).
// "library/busybox" → blocked. "myorg/busybox-extra" → NOT blocked (substring ≠ match).
func DenyImageName(name string) Policy {
	return PolicyFunc(func(repo, ref string) Decision {
		parts := strings.Split(repo, "/")
		if strings.EqualFold(parts[len(parts)-1], name) {
			return Decision{false, fmt.Sprintf("image name %q is blocked by policy", name)}
		}
		return Decision{Allow: true}
	})
}

// DenyTag blocks exact tag matches (case-insensitive).
// Digest refs (sha256:...) are never blocked by this rule.
func DenyTag(tag string) Policy {
	return PolicyFunc(func(repo, ref string) Decision {
		if strings.HasPrefix(ref, "sha256:") {
			return Decision{Allow: true} // digest pins bypass tag rules
		}
		if strings.EqualFold(ref, tag) {
			return Decision{false, fmt.Sprintf("tag %q is blocked by policy", tag)}
		}
		return Decision{Allow: true}
	})
}

// AllowAll permits every pull — useful as a no-op base or in tests.
var AllowAll Policy = PolicyFunc(func(_, _ string) Decision {
	return Decision{Allow: true, Reason: "allow-all"}
})
