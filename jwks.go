package iam

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Signing key cache, section 5.3 of the specification.
const (
	// jwksRefreshInterval is how long downloaded keys are used before they
	// are downloaded again in the background.
	jwksRefreshInterval = 10 * time.Minute
	// jwksMinRefresh is the shortest time before the next download after a
	// download failed or did not contain the wanted kid. It keeps forged
	// kids from being amplified into requests to IAM.
	jwksMinRefresh = 30 * time.Second
	// jwksMaxStale is how long cached keys stay usable while IAM cannot be
	// reached.
	jwksMaxStale = 24 * time.Hour
	minRSABits   = 2048
)

var errKeyNotFound = errors.New("signing key not found")

// keySet caches the public signing keys of the issuer. Keys only ever come
// from the jwks_uri of the configured issuer's discovery document; header
// parameters of a token (jku, jwk, x5u) are never consulted.
type keySet struct {
	p *provider

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time // last successful download
	notBefore time.Time // no download on demand before this time
	flight    *flight
}

func newKeySet(p *provider) *keySet { return &keySet{p: p} }

// warm downloads the keys once, at startup.
func (k *keySet) warm(ctx context.Context) error {
	k.mu.Lock()
	fl := k.refreshLocked(ctx)
	k.mu.Unlock()
	return fl.wait(ctx)
}

// key returns the public key for kid.
//
//   - A cached key is returned without contacting IAM. When the cache is
//     older than the refresh interval, a download is started in the
//     background and the cached key is still used.
//   - An unknown kid triggers one download (shared by concurrent callers),
//     unless the rate limit forbids it.
//   - errKeyNotFound means IAM does not publish this kid; ErrUnavailable
//     means there is no usable key at all.
func (k *keySet) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	for attempt := 0; ; attempt++ {
		k.mu.Lock()
		now := k.p.clock()
		age := now.Sub(k.fetchedAt)
		if len(k.keys) > 0 && age > jwksMaxStale {
			// Keys this old are no longer trusted without confirmation.
			k.keys = nil
		}
		if key, ok := k.keys[kid]; ok {
			if age > jwksRefreshInterval && k.flight == nil && !now.Before(k.notBefore) {
				k.refreshLocked(ctx)
			}
			k.mu.Unlock()
			return key, nil
		}
		fl := k.flight
		if fl == nil && (attempt > 0 || now.Before(k.notBefore)) {
			empty := len(k.keys) == 0
			if attempt > 0 {
				// Just downloaded and the kid is still unknown.
				k.notBefore = now.Add(jwksMinRefresh)
			}
			k.mu.Unlock()
			if empty {
				return nil, ErrUnavailable
			}
			return nil, errKeyNotFound
		}
		if fl == nil {
			fl = k.refreshLocked(ctx)
		}
		k.mu.Unlock()
		if err := fl.wait(ctx); err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Look again, whatever the download returned: on failure the cached
		// keys are still valid.
	}
}

// refreshLocked starts a download unless one is already running. k.mu must
// be held.
func (k *keySet) refreshLocked(ctx context.Context) *flight {
	if k.flight != nil {
		return k.flight
	}
	fl := newFlight()
	k.flight = fl
	go func() {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		defer cancel()
		keys, err := k.fetch(fctx)
		k.mu.Lock()
		now := k.p.clock()
		if err == nil {
			k.keys, k.fetchedAt = keys, now
		} else {
			k.notBefore = now.Add(jwksMinRefresh)
			k.p.log.WarnContext(fctx, "iam: downloading the signing keys failed; cached keys stay in use", "error", err.Error(), "cached_keys", len(k.keys))
		}
		k.flight = nil
		k.mu.Unlock()
		fl.finish(err)
	}()
	return fl
}

func (k *keySet) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	meta, err := k.p.metadata(ctx)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := k.p.getJSON(ctx, "jwks", meta.JWKSURI, &set); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		pub, ok := jwk.Key.(*rsa.PublicKey)
		if !ok || jwk.KeyID == "" || !jwk.Valid() || pub.N.BitLen() < minRSABits {
			continue
		}
		if (jwk.Use != "" && jwk.Use != "sig") || (jwk.Algorithm != "" && jwk.Algorithm != string(jose.RS256)) {
			continue
		}
		keys[jwk.KeyID] = pub
	}
	if len(keys) == 0 {
		return nil, &NetworkError{Op: "jwks", Err: errors.New("the key set contains no usable RS256 key")}
	}
	return keys, nil
}
