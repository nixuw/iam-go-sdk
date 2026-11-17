package iam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	defaultIntrospectionTTL = 30 * time.Second
	maxIntrospectionTTL     = 5 * time.Minute
	introspectionCacheSize  = 10000
)

// IntrospectionConfig enables token introspection (RFC 7662) for the rules
// that ask for it. Introspection is an optional addition to the offline
// checks, not a replacement: it only adds the knowledge that a caller
// revoked its own token. It makes every request of those endpoints depend on
// IAM being reachable.
type IntrospectionConfig struct {
	// ClientID and Credential identify a service credential that an IAM
	// administrator registered on this application as allowed to introspect
	// its tokens. Any other client only ever gets "inactive". Required.
	ClientID   string
	Credential Credential
	// CacheTTL is how long an answer is reused for the same token. Zero
	// means 30 seconds; the maximum is 5 minutes.
	CacheTTL time.Duration
}

type introspector struct {
	cl  *client
	ttl time.Duration

	mu    sync.Mutex
	cache map[string]introspection
}

type introspection struct {
	active bool
	until  time.Time
}

func newIntrospector(ctx context.Context, p *provider, cfg *IntrospectionConfig) (*introspector, error) {
	if cfg.ClientID == "" {
		return nil, configError("Introspection.ClientID", "is required")
	}
	if cfg.Credential == nil {
		return nil, configError("Introspection.Credential", "is required")
	}
	if _, err := cfg.Credential.fingerprint(ctx); err != nil {
		return nil, prefixField(err, "Introspection.")
	}
	ttl := cfg.CacheTTL
	switch {
	case ttl == 0:
		ttl = defaultIntrospectionTTL
	case ttl < 0 || ttl > maxIntrospectionTTL:
		return nil, configError("Introspection.CacheTTL", "must be between 0 and 5 minutes")
	}
	return &introspector{cl: &client{p: p, id: cfg.ClientID, cred: cfg.Credential}, ttl: ttl, cache: map[string]introspection{}}, nil
}

// active reports whether IAM considers the token active for this
// application. Answers are cached briefly per token ID.
func (i *introspector) active(ctx context.Context, token string, id *Identity) (bool, error) {
	now := i.cl.p.clock()
	key := id.TokenID
	if key != "" {
		i.mu.Lock()
		hit, ok := i.cache[key]
		i.mu.Unlock()
		if ok && now.Before(hit.until) {
			return hit.active, nil
		}
	}
	meta, err := i.cl.p.metadata(ctx)
	if err != nil {
		return false, err
	}
	if meta.IntrospectionEndpoint == "" {
		return false, errors.New("the issuer has no introspection endpoint")
	}
	res, body, _, err := i.cl.post(ctx, "introspection", meta.IntrospectionEndpoint, url.Values{"token": {token}, "token_type_hint": {"access_token"}})
	if err != nil {
		return false, err
	}
	if res.StatusCode != http.StatusOK {
		return false, protocolError("introspection", res, body)
	}
	var out struct {
		Active bool            `json:"active"`
		Aud    json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false, errors.New("the introspection response is malformed")
	}
	active := out.Active
	if active && len(out.Aud) > 0 {
		// The answer must be about a token for this application.
		var aud string
		if json.Unmarshal(out.Aud, &aud) != nil || aud != id.Audience {
			active = false
		}
	}
	if key != "" {
		until := now.Add(i.ttl)
		if active && until.After(id.ExpiresAt) {
			until = id.ExpiresAt
		}
		i.mu.Lock()
		if len(i.cache) >= introspectionCacheSize {
			for k, v := range i.cache {
				if !now.Before(v.until) {
					delete(i.cache, k)
				}
			}
			if len(i.cache) >= introspectionCacheSize {
				clear(i.cache)
			}
		}
		i.cache[key] = introspection{active: active, until: until}
		i.mu.Unlock()
	}
	return active, nil
}

// prefixField qualifies the field name of a configuration error.
func prefixField(err error, prefix string) error {
	var ce *ConfigError
	if errors.As(err, &ce) {
		return &ConfigError{Field: prefix + ce.Field, Reason: ce.Reason}
	}
	return err
}
