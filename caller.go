package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// A token is never handed out when it expires within expiryMargin.
	expiryMargin = 5 * time.Second
	// tokenFetchTimeout bounds one token acquisition including its retries.
	tokenFetchTimeout = 30 * time.Second
	// Attempts within one acquisition when IAM is unreachable or answers 5xx.
	fetchAttempts  = 3
	fetchRetryBase = 200 * time.Millisecond
	// Back-off between acquisitions after IAM stayed unavailable.
	transientBackoffBase = time.Second
	transientBackoffMax  = 30 * time.Second
	// Back-off after IAM refused a request (configuration or authorisation
	// problem). Repeating such a request unchanged only feeds the rate
	// limit that IAM applies to the whole client ID.
	refusalBackoffBase = 10 * time.Second
	refusalBackoffMax  = 5 * time.Minute
	// refusalBudget is the number of refused requests per minute, over all
	// targets, after which the instance stops asking for a while. It is far
	// below IAM's default limit of 30 per minute and client ID.
	refusalBudget = 6
	// defaultRateLimitWait applies to a 429 without Retry-After.
	defaultRateLimitWait = 60 * time.Second
)

// CallerConfig configures the caller side: a system that calls other
// applications as itself with system tokens.
type CallerConfig struct {
	// Issuer is the IAM issuer. Required.
	Issuer string
	// ClientID is the client ID of a service credential (svc_…). It is not
	// the client ID of the OIDC application used for sign-in. Required.
	ClientID string
	// Credential authenticates the service credential with the method it is
	// registered for. Required.
	Credential Credential
	// AllowInsecureTransport permits sending tokens to targets over
	// plaintext connections (http://, gRPC without TLS), for example inside
	// a cluster. Off by default.
	AllowInsecureTransport bool
	// HTTPClient is used to reach IAM, not the targets. Nil means a client
	// with a 10 second timeout.
	HTTPClient *http.Client
	// Logger receives diagnostics. Nil disables logging.
	Logger *slog.Logger
	// AllowInsecureIssuer permits an http:// issuer. For integration
	// environments only.
	AllowInsecureIssuer bool
	// TolerateStartupFailure makes NewCaller succeed when IAM cannot be
	// reached at startup; discovery is then retried on use.
	TolerateStartupFailure bool
}

// Target is one application to call: every token is issued for exactly one
// target, and each outbound client is bound to one.
type Target struct {
	// Resource is the resource identifier of the target application, as its
	// owner states it. The SDK never builds it from a prefix. Required.
	Resource string
	// Scopes are the permission codes to request. Empty asks IAM for every
	// permission of the grant; naming the minimum is recommended.
	Scopes []string
	// BaseURL, when set, restricts an outbound HTTP client to this address:
	// requests to another scheme, host or path prefix fail with
	// ErrTargetMismatch before a token is sent. It does not change where
	// requests go.
	BaseURL string
}

// target is a validated Target.
type target struct {
	resource string
	scopes   []string
	base     *url.URL
}

func (t Target) normalize() (target, error) {
	if t.Resource == "" || strings.ContainsAny(t.Resource, " \t\r\n") {
		return target{}, configError("Target.Resource", "is required: the resource identifier of the target application")
	}
	out := target{resource: t.Resource}
	for _, s := range t.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return target{}, configError("Target.Scopes", "a permission code must not be empty or contain spaces")
		}
		if !slices.Contains(out.scopes, s) {
			out.scopes = append(out.scopes, s)
		}
	}
	slices.Sort(out.scopes)
	if t.BaseURL != "" {
		u, err := url.Parse(t.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return target{}, configError("Target.BaseURL", "must be an absolute http(s) URL")
		}
		out.base = u
	}
	return out, nil
}

// cacheKey identifies (target, permission set); the credential is the Caller.
func (t target) cacheKey() string {
	return t.resource + "\x00" + strings.Join(t.scopes, " ")
}

// failure is the memory of a failed token request: nothing is sent again
// before until.
type failure struct {
	err   error
	until time.Time
	count int
	fp    string // fingerprint of the credential that was refused
}

type tokenEntry struct {
	token     string
	expiry    time.Time
	refreshAt time.Time
	fail      failure
	flight    *flight
}

// Caller obtains, caches and renews system tokens for target applications.
// Create it once and keep it for the lifetime of the process.
type Caller struct {
	cl         *client
	allowPlain bool
	sleep      func(context.Context, time.Duration) error
	jitter     func() float64

	mu      sync.Mutex
	entries map[string]*tokenEntry
	// blocked stops every request: a 429 from IAM, or the refusal budget.
	blocked failure
	// credFail stops every request after the credential itself was refused,
	// until it changes.
	credFail failure
	refusals []time.Time
}

// NewCaller validates the configuration and reads the discovery document.
func NewCaller(ctx context.Context, cfg CallerConfig) (*Caller, error) {
	p, err := newProvider(commonConfig{issuer: cfg.Issuer, insecure: cfg.AllowInsecureIssuer, hc: cfg.HTTPClient, log: cfg.Logger})
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, configError("ClientID", "is required: the client ID of the service credential")
	}
	if cfg.Credential == nil {
		return nil, configError("Credential", "is required: ClientSecret or PrivateKeyJWT")
	}
	if _, err := cfg.Credential.fingerprint(ctx); err != nil {
		return nil, err
	}
	c := &Caller{
		cl:         &client{p: p, id: cfg.ClientID, cred: cfg.Credential},
		allowPlain: cfg.AllowInsecureTransport,
		sleep:      sleepContext,
		jitter:     rand.Float64,
		entries:    map[string]*tokenEntry{},
	}
	if err := p.start(ctx, false, cfg.TolerateStartupFailure); err != nil {
		return nil, err
	}
	return c, nil
}

// Token returns a currently valid system token for the target. Tokens are
// cached per target and permission set, renewed before they expire, and
// concurrent requests for the same token are merged into one.
//
// When IAM refuses a request (*OAuthError such as invalid_target,
// invalid_scope, invalid_client) the refusal is remembered and the same
// request is not sent again before a back-off has passed; calls in between
// return the remembered error. A 429 is honoured for its Retry-After. While
// IAM is unavailable, a cached token that has not expired keeps being
// returned.
func (c *Caller) Token(ctx context.Context, t Target) (string, error) {
	nt, err := t.normalize()
	if err != nil {
		return "", err
	}
	return c.token(ctx, nt, "")
}

// Invalidate drops the cached token for the target, so that the next call
// obtains a new one. With refused set, the cache is only dropped if it still
// holds that token: pass the token the target has just refused, so that
// concurrent calls trigger a single new request. The outbound HTTP client
// and the gRPC interceptors do this by themselves.
func (c *Caller) Invalidate(t Target, refused string) {
	nt, err := t.normalize()
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[nt.cacheKey()]; e != nil && (refused == "" || e.token == refused) {
		e.token = ""
	}
}

// Revoke revokes the cached token for the target at IAM and forgets it. Use
// it when shutting a workload down or when a leak is suspected. A target
// that validates tokens offline still accepts the token until it expires.
func (c *Caller) Revoke(ctx context.Context, t Target) error {
	nt, err := t.normalize()
	if err != nil {
		return err
	}
	c.mu.Lock()
	token := ""
	if e := c.entries[nt.cacheKey()]; e != nil {
		token, e.token = e.token, ""
	}
	c.mu.Unlock()
	if token == "" {
		return nil
	}
	return c.cl.revoke(ctx, token, "access_token")
}

// InsecureTransportAllowed reports CallerConfig.AllowInsecureTransport. The
// adapters consult it before sending a token over a plaintext connection.
func (c *Caller) InsecureTransportAllowed() bool { return c.allowPlain }

// token returns a token for t that is not the refused one.
func (c *Caller) token(ctx context.Context, t target, refused string) (string, error) {
	key := t.cacheKey()
	for range 4 {
		c.mu.Lock()
		e := c.entries[key]
		if e == nil {
			e = &tokenEntry{}
			c.entries[key] = e
		}
		now := c.cl.p.clock()
		if refused != "" && e.token == refused {
			e.token = ""
		}
		if e.token != "" && now.Before(e.refreshAt) {
			token := e.token
			c.mu.Unlock()
			return token, nil
		}
		usable := e.token != "" && now.Before(e.expiry.Add(-expiryMargin))
		token := e.token
		fl := e.flight
		if fl == nil {
			if f, byCredential, ok := c.suppressedLocked(e, now); ok {
				c.mu.Unlock()
				if byCredential && c.credentialChanged(ctx, f.fp) {
					continue
				}
				if usable {
					return token, nil
				}
				return "", fmt.Errorf("%w (not asking IAM again before %s)", f.err, f.until.UTC().Format(time.RFC3339))
			}
			fl = newFlight()
			e.flight = fl
			go c.fetch(ctx, e, t, fl)
		}
		c.mu.Unlock()
		if usable {
			// Renewal runs in the background; the call is not held up.
			return token, nil
		}
		if err := fl.wait(ctx); err != nil {
			return "", err
		}
	}
	return "", &NetworkError{Op: "token request", Err: errors.New("the token was invalidated repeatedly while it was being obtained")}
}

// suppressedLocked returns the failure that currently forbids a token
// request, if any, and whether it is the refusal of the credential.
func (c *Caller) suppressedLocked(e *tokenEntry, now time.Time) (f failure, byCredential, ok bool) {
	switch {
	case now.Before(c.blocked.until):
		return c.blocked, false, true
	case now.Before(c.credFail.until):
		return c.credFail, true, true
	case now.Before(e.fail.until):
		return e.fail, false, true
	}
	return failure{}, false, false
}

// credentialChanged reports whether the credential differs from the one IAM
// refused. A replaced secret or key lifts the back-off at once.
func (c *Caller) credentialChanged(ctx context.Context, refusedFP string) bool {
	current, err := c.cl.cred.fingerprint(ctx)
	if err != nil || current == refusedFP {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credFail.fp == refusedFP {
		c.credFail = failure{}
	}
	return true
}

// fetch obtains a token for one cache entry and publishes the outcome to
// everyone waiting on fl.
func (c *Caller) fetch(ctx context.Context, e *tokenEntry, t target, fl *flight) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenFetchTimeout)
	defer cancel()
	p := c.cl.p
	started := p.clock()
	tr, fp, err := c.request(fctx, t)
	c.mu.Lock()
	now := p.clock()
	if err == nil {
		ttl := time.Duration(tr.ExpiresIn) * time.Second
		e.token, e.expiry, e.refreshAt = tr.AccessToken, started.Add(ttl), started.Add(renewAfter(ttl))
		e.fail, c.credFail = failure{}, failure{}
	} else {
		c.failedLocked(e, err, fp, now)
	}
	e.flight = nil
	c.mu.Unlock()
	if err != nil {
		attrs := []any{"resource", t.resource, "error", err.Error()}
		var oe *OAuthError
		if errors.As(err, &oe) {
			attrs = append(attrs, "code", oe.Code, "request_id", oe.RequestID)
		}
		p.log.WarnContext(fctx, "iam: token request failed", attrs...)
	} else {
		p.log.DebugContext(fctx, "iam: token obtained", "resource", t.resource, "expires_in", tr.ExpiresIn)
	}
	fl.finish(err)
}

// request performs the client credentials request, retrying with jittered
// exponential back-off while IAM is unreachable or answers 5xx.
func (c *Caller) request(ctx context.Context, t target) (*tokenResponse, string, error) {
	for attempt := 0; ; attempt++ {
		form := url.Values{"grant_type": {"client_credentials"}, "resource": {t.resource}}
		if len(t.scopes) > 0 {
			form.Set("scope", strings.Join(t.scopes, " "))
		}
		tr, fp, err := c.cl.token(ctx, form)
		if err == nil {
			return tr, fp, nil
		}
		if !transient(err) || attempt+1 >= fetchAttempts {
			return nil, fp, err
		}
		if serr := c.sleep(ctx, c.jittered(backoff(attempt+1, fetchRetryBase, transientBackoffMax))); serr != nil {
			return nil, fp, err
		}
	}
}

// failedLocked records a failed request so that it is not repeated blindly.
func (c *Caller) failedLocked(e *tokenEntry, err error, fp string, now time.Time) {
	var oe *OAuthError
	isOAuth := errors.As(err, &oe)
	switch {
	case isOAuth && oe.StatusCode == http.StatusTooManyRequests:
		wait := oe.RetryAfter
		if wait <= 0 {
			wait = defaultRateLimitWait
		}
		c.blocked = failure{err: err, until: now.Add(wait)}
	case transient(err) || !isOAuth:
		e.fail.count++
		e.fail.err = err
		e.fail.until = now.Add(c.jittered(backoff(e.fail.count, transientBackoffBase, transientBackoffMax)))
	case oe.Code == "invalid_client" || oe.Code == "unauthorized_client":
		// The credential itself is refused: every target would fail.
		c.credFail.count++
		c.credFail.err, c.credFail.fp = err, fp
		c.credFail.until = now.Add(backoff(c.credFail.count, refusalBackoffBase, refusalBackoffMax))
		c.refusedLocked(err, now)
	default:
		// invalid_target, invalid_scope, invalid_request, …: this target or
		// permission set is refused.
		e.fail.count++
		e.fail.err = err
		e.fail.until = now.Add(backoff(e.fail.count, refusalBackoffBase, refusalBackoffMax))
		c.refusedLocked(err, now)
	}
}

// refusedLocked keeps the number of refused requests per minute, over all
// targets, below the budget.
func (c *Caller) refusedLocked(err error, now time.Time) {
	cutoff := now.Add(-time.Minute)
	c.refusals = slices.DeleteFunc(c.refusals, func(t time.Time) bool { return !t.After(cutoff) })
	c.refusals = append(c.refusals, now)
	if len(c.refusals) >= refusalBudget {
		if until := c.refusals[0].Add(time.Minute); until.After(c.blocked.until) {
			c.blocked = failure{err: err, until: until}
		}
	}
}

func (c *Caller) jittered(d time.Duration) time.Duration {
	return d/2 + time.Duration(c.jitter()*float64(d/2))
}

// renewAfter is how long after it was issued a token is renewed: when less
// than a minute or less than a fifth of its lifetime remains, but not before
// half of the lifetime has passed.
func renewAfter(ttl time.Duration) time.Duration {
	early := max(time.Minute, ttl/5)
	return ttl - min(early, ttl/2)
}

// backoff returns base·2^(n-1), capped at limit, for the n-th failure.
func backoff(n int, base, limit time.Duration) time.Duration {
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
