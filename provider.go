package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	// discoveryRetry is the shortest time between two discovery attempts
	// after a failure (only relevant with TolerateStartupFailure).
	discoveryRetry = 5 * time.Second
	// fetchTimeout bounds a discovery or JWKS download that several callers
	// may be waiting for.
	fetchTimeout = 15 * time.Second
	maxBodyBytes = 1 << 20
	userAgent    = "iam-go-sdk/" + Version
)

// metadata is the part of the discovery document the SDK uses. Endpoint
// addresses always come from here; none is hard-coded.
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// provider is the connection of one SDK instance to its issuer: HTTP access,
// the cached discovery document and the cached signing keys.
type provider struct {
	issuer   string
	insecure bool // http:// issuer explicitly allowed
	hc       *http.Client
	log      *slog.Logger
	clock    func() time.Time

	mu      sync.Mutex
	meta    *metadata
	flight  *flight
	retryAt time.Time
	lastErr error

	keys *keySet
}

// commonConfig carries the settings shared by the three scenarios.
type commonConfig struct {
	issuer   string
	insecure bool
	hc       *http.Client
	log      *slog.Logger
	tolerate bool
}

func newProvider(c commonConfig) (*provider, error) {
	if err := checkIssuer(c.issuer, c.insecure); err != nil {
		return nil, err
	}
	hc := c.hc
	if hc == nil {
		hc = &http.Client{Timeout: defaultHTTPTimeout}
	}
	log := c.log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	p := &provider{issuer: c.issuer, insecure: c.insecure, hc: hc, log: log, clock: time.Now}
	p.keys = newKeySet(p)
	return p, nil
}

// checkIssuer validates the configured issuer without normalising it: the
// value is later compared character by character with the discovery document
// and with the iss claim of every token.
func checkIssuer(issuer string, allowHTTP bool) error {
	if issuer == "" {
		return configError("Issuer", "is required")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimSpace(issuer) != issuer {
		return configError("Issuer", "must be an absolute URL without user info, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return configError("Issuer", "must use https (set AllowInsecureIssuer only for integration environments)")
		}
	default:
		return configError("Issuer", "must use https")
	}
	return nil
}

// start performs the startup check of an instance: discovery and, when
// wantKeys is set, a first JWKS download. Configuration problems always
// fail; with tolerate, a failure to reach IAM is only logged and retried on
// later use.
func (p *provider) start(ctx context.Context, wantKeys, tolerate bool) error {
	_, err := p.metadata(ctx)
	if err == nil && wantKeys {
		err = p.keys.warm(ctx)
	}
	if err == nil {
		return nil
	}
	if tolerate && !errors.Is(err, ErrConfig) && ctx.Err() == nil {
		p.log.WarnContext(ctx, "iam: IAM is not reachable at startup; continuing and retrying on use", "issuer", p.issuer, "error", err.Error())
		return nil
	}
	return err
}

// metadata returns the discovery document, loading it on first use. Callers
// that arrive while a download is in flight share its result.
func (p *provider) metadata(ctx context.Context) (*metadata, error) {
	p.mu.Lock()
	if p.meta != nil {
		m := p.meta
		p.mu.Unlock()
		return m, nil
	}
	if p.flight == nil && p.clock().Before(p.retryAt) {
		err := p.lastErr
		p.mu.Unlock()
		return nil, err
	}
	fl := p.flight
	if fl == nil {
		fl = newFlight()
		p.flight = fl
		go func() {
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
			defer cancel()
			m, err := p.discover(fctx)
			p.mu.Lock()
			if err == nil {
				p.meta = m
			} else {
				p.lastErr, p.retryAt = err, p.clock().Add(discoveryRetry)
			}
			p.flight = nil
			p.mu.Unlock()
			fl.finish(err)
		}()
	}
	p.mu.Unlock()
	if err := fl.wait(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.meta, nil
}

func (p *provider) discover(ctx context.Context) (*metadata, error) {
	var m metadata
	if err := p.getJSON(ctx, "discovery", strings.TrimSuffix(p.issuer, "/")+"/.well-known/openid-configuration", &m); err != nil {
		return nil, err
	}
	if m.Issuer != p.issuer {
		return nil, configError("Issuer", fmt.Sprintf("the discovery document names issuer %q, which is not the configured %q (the two must be identical character by character)", m.Issuer, p.issuer))
	}
	if m.JWKSURI == "" || m.TokenEndpoint == "" {
		return nil, &NetworkError{Op: "discovery", Err: errors.New("the discovery document lacks jwks_uri or token_endpoint")}
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint": m.AuthorizationEndpoint, "token_endpoint": m.TokenEndpoint, "userinfo_endpoint": m.UserinfoEndpoint,
		"jwks_uri": m.JWKSURI, "revocation_endpoint": m.RevocationEndpoint, "introspection_endpoint": m.IntrospectionEndpoint,
		"end_session_endpoint": m.EndSessionEndpoint,
	} {
		if endpoint == "" {
			continue
		}
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && p.insecure)) {
			return nil, &NetworkError{Op: "discovery", Err: fmt.Errorf("the discovery document has an unusable %s", name)}
		}
	}
	return &m, nil
}

// do sends a request to IAM. Transport failures become *NetworkError; the
// error text never includes request bodies or headers.
func (p *provider) do(ctx context.Context, op string, req *http.Request) (*http.Response, []byte, error) {
	req.Header.Set("User-Agent", userAgent)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	res, err := p.hc.Do(req.WithContext(ctx))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return nil, nil, ctxErr
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			// Keep the cause, drop the URL: a request URL can carry
			// parameters that do not belong in logs.
			err = ue.Err
		}
		return nil, nil, &NetworkError{Op: op, Err: err}
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes+1))
	if err != nil {
		return nil, nil, &NetworkError{Op: op, Err: err}
	}
	if len(body) > maxBodyBytes {
		return nil, nil, &NetworkError{Op: op, Err: errors.New("response too large")}
	}
	return res, body, nil
}

func (p *provider) getJSON(ctx context.Context, op, rawURL string, out any) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return &NetworkError{Op: op, Err: err}
	}
	res, body, err := p.do(ctx, op, req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return protocolError(op, res, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &NetworkError{Op: op, Err: errors.New("response is not valid JSON")}
	}
	return nil
}

// protocolError turns a non-success response of IAM into an error: an
// *OAuthError when the body is an OAuth error, a *NetworkError otherwise
// (for example the HTML page of a gateway in front of IAM).
func protocolError(op string, res *http.Response, body []byte) error {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		if res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests {
			return &OAuthError{StatusCode: res.StatusCode, RequestID: res.Header.Get("X-Request-ID"), RetryAfter: retryAfter(res.Header)}
		}
		return &NetworkError{Op: op, Err: fmt.Errorf("unexpected HTTP %d", res.StatusCode)}
	}
	return &OAuthError{
		Code: e.Error, Description: e.Description, StatusCode: res.StatusCode,
		RequestID: res.Header.Get("X-Request-ID"), RetryAfter: retryAfter(res.Header),
	}
}

// retryAfter parses a Retry-After header given in seconds or as a date.
func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// flight is one in-progress operation that several goroutines wait for.
type flight struct {
	done chan struct{}
	err  error
}

func newFlight() *flight { return &flight{done: make(chan struct{})} }

func (f *flight) finish(err error) {
	f.err = err
	close(f.done)
}

func (f *flight) wait(ctx context.Context) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
