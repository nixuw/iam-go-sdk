package iam

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// HTTPClient returns an *http.Client bound to one target: every request
// made with it carries a token for that target, and only for it. The client
// is safe for concurrent use; create one per target and keep it.
//
//   - Tokens are only sent over https, unless
//     CallerConfig.AllowInsecureTransport is set.
//   - A redirect to another origin is followed without the token.
//   - When the target answers 401 invalid_token, the cached token is dropped
//     and the request is repeated once with a new token, provided it can be
//     replayed (no body, or Request.GetBody is set). A second refusal is
//     returned as an error matching ErrInvalidToken.
//   - When the target answers 403 insufficient_scope, the request is not
//     repeated and an error matching ErrInsufficientScope is returned.
//
// Both errors are *BearerError values. Any other response, including other
// 401 and 403 responses, is returned unchanged. A failure to obtain the
// token is returned as the error of the request (wrapped in *url.Error by
// net/http; errors.Is and errors.As see through it).
func (c *Caller) HTTPClient(t Target) *http.Client {
	return &http.Client{Transport: c.Transport(t, nil)}
}

// Transport is the http.RoundTripper behind HTTPClient, for applications
// that build their own http.Client (timeouts, tracing, connection pools).
// base carries the requests to the target; nil means http.DefaultTransport.
func (c *Caller) Transport(t Target, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	nt, err := t.normalize()
	return &boundTransport{caller: c, target: nt, invalid: err, base: base}
}

type boundTransport struct {
	caller  *Caller
	target  target
	invalid error // the Target was invalid; reported on first use
	base    http.RoundTripper
}

func (b *boundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if first := firstRequest(req); b.invalid == nil && first != req && !sameOrigin(first.URL, req.URL) {
		// A redirect led away from the target: the token stays behind.
		return b.base.RoundTrip(req)
	}
	token, err := b.authorize(req)
	if err != nil {
		// A RoundTripper closes the request body even when it fails.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	res, err := b.send(req, token)
	if err != nil {
		return nil, err
	}
	refusal := targetRefusal(res)
	if refusal == nil {
		return res, nil
	}
	discard(res)
	if refusal.Code != codeInvalidToken {
		// insufficient_scope: a matter of grants; repeating cannot help.
		return nil, refusal
	}
	// invalid_token: the cached token is of no use any more.
	b.caller.dropToken(b.target, token)
	if !replayable(req) {
		return nil, refusal
	}
	fresh, err := b.caller.token(req.Context(), b.target, token)
	if err != nil {
		return nil, err
	}
	retry := req
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, refusal
		}
		retry = req.Clone(req.Context())
		retry.Body = body
	}
	res, err = b.send(retry, fresh)
	if err != nil {
		return nil, err
	}
	if again := targetRefusal(res); again != nil {
		discard(res)
		return nil, again
	}
	return res, nil
}

// authorize checks that the request may carry a token for the target and
// returns that token.
func (b *boundTransport) authorize(req *http.Request) (string, error) {
	switch {
	case b.invalid != nil:
		return "", b.invalid
	case req.URL.Scheme != "https" && !b.caller.allowPlain:
		return "", ErrInsecureTransport
	case b.target.base != nil && !within(b.target.base, req.URL):
		return "", ErrTargetMismatch
	}
	return b.caller.token(req.Context(), b.target, "")
}

// send forwards a copy of req carrying the token. The original request is
// never modified, as http.RoundTripper requires.
func (b *boundTransport) send(req *http.Request, token string) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	return b.base.RoundTrip(out)
}

// dropToken forgets the cached token if it is still the refused one.
func (c *Caller) dropToken(t target, refused string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[t.cacheKey()]; e != nil && e.token == refused {
		e.token = ""
	}
}

// targetRefusal recognises the two RFC 6750 answers of a target that concern
// the token itself.
func targetRefusal(res *http.Response) *BearerError {
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
		return nil
	}
	params, ok := bearerChallenge(res.Header)
	if !ok {
		return nil
	}
	code := params["error"]
	if (res.StatusCode == http.StatusUnauthorized && code == codeInvalidToken) ||
		(res.StatusCode == http.StatusForbidden && code == codeInsufficientScope) {
		return &BearerError{Status: res.StatusCode, Code: code, Description: params["error_description"], Scope: params["scope"], Realm: params["realm"]}
	}
	return nil
}

// bearerChallenge extracts the parameters of a Bearer challenge from the
// WWW-Authenticate headers of a response.
func bearerChallenge(h http.Header) (map[string]string, bool) {
	for _, value := range h.Values("WWW-Authenticate") {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(value), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		return parseAuthParams(rest), true
	}
	return nil, false
}

// parseAuthParams parses `name=value, name="quoted value"` pairs. It stops
// at anything that is not a parameter, such as a further challenge.
func parseAuthParams(s string) map[string]string {
	params := map[string]string{}
	for {
		s = strings.TrimLeft(s, " \t,")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || strings.ContainsAny(s[:eq], " \t,\"") {
			return params
		}
		name := strings.ToLower(s[:eq])
		s = s[eq+1:]
		var value strings.Builder
		if strings.HasPrefix(s, `"`) {
			i := 1
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				value.WriteByte(s[i])
			}
			if i >= len(s) {
				return params // unterminated quoted-string
			}
			s = s[i+1:]
		} else {
			end := strings.IndexAny(s, ", \t")
			if end < 0 {
				end = len(s)
			}
			value.WriteString(s[:end])
			s = s[end:]
		}
		params[name] = value.String()
	}
}

// firstRequest follows the chain of redirects back to the request the
// application made.
func firstRequest(req *http.Request) *http.Request {
	for req.Response != nil && req.Response.Request != nil {
		req = req.Response.Request
	}
	return req
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

// within reports whether u lies under the base address.
func within(base, u *url.URL) bool {
	if !sameOrigin(base, u) {
		return false
	}
	prefix := strings.TrimSuffix(base.Path, "/")
	return prefix == "" || u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/")
}

// replayable reports whether a request can be sent a second time.
func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// discard releases a response that is not handed to the application.
func discard(res *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	_ = res.Body.Close()
}
