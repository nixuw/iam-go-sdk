// Package iamtest provides a local fake of the IAM issuer for unit tests.
// With it, the tests of an application that uses the SDK need no real IAM:
//
//	iss := iamtest.NewIssuer(t)
//	verifier, _ := iam.NewVerifier(ctx, iam.VerifierConfig{
//		Issuer: iss.URL(), Audience: "urn:example:app:orders", HTTPClient: iss.HTTPClient(),
//	})
//	token := iss.ServiceToken("urn:example:app:orders", "svc_caller", "order.read")
//
// The fake serves the discovery document and the JWKS, signs access tokens
// with any content, and implements the protocol endpoints the SDK talks to
// (authorization, token, userinfo, logout, revocation, introspection) with
// the constraints of the real IAM: PKCE S256, state and nonce are mandatory,
// client_secret_post is refused, client_credentials needs exactly one
// resource, refresh tokens rotate and a reused one revokes its chain.
//
// It is for tests only. It listens on a loopback address with a throw-away
// certificate; pass HTTPClient to the SDK configuration to trust it.
package iamtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Paths of the fake issuer's endpoints, for Requests and Fail.
const (
	PathDiscovery  = "/.well-known/openid-configuration"
	PathJWKS       = "/oauth2/jwks"
	PathAuthorize  = "/oauth2/authorize"
	PathToken      = "/oauth2/token"
	PathUserInfo   = "/oidc/userinfo"
	PathLogout     = "/oidc/logout"
	PathRevoke     = "/oauth2/revoke"
	PathIntrospect = "/oauth2/introspect"
)

// Issuer is a running fake IAM.
type Issuer struct {
	srv *httptest.Server

	mu         sync.Mutex
	now        func() time.Time
	keys       []*signingKey // published keys
	activeKey  *signingKey
	lifetime   time.Duration // access token lifetime of the token endpoint
	logins     map[string]*LoginClient
	services   map[string]*ServiceClient
	grants     map[string]map[string][]string // client ID → resource → permissions
	introspect map[string][]string            // client ID → resources it may introspect
	user       *User
	authTime   time.Time
	sid        string
	authError  string
	codes      map[string]*authCode
	refresh    map[string]*refreshToken
	revoked    map[string]bool // revoked refresh chains and access token IDs
	seenJTI    map[string]bool
	requests   map[string]int
	faults     map[string][]Fault
	down       bool
	sensitive  []string
	tokenForms []url.Values
	idHook     func(claims map[string]any, sign func(header, claims map[string]any) string) string
}

type signingKey struct {
	kid  string
	priv *rsa.PrivateKey
}

// LoginClient is an OIDC application (type web_backend) registered at the
// fake issuer.
type LoginClient struct {
	// ID is the client ID.
	ID string
	// Secret authenticates the client with client_secret_basic. Leave it
	// empty and set PublicKeys for private_key_jwt.
	Secret string
	// PublicKeys are the registered public keys by kid (private_key_jwt).
	PublicKeys map[string]crypto.PublicKey
	// RedirectURIs and PostLogoutRedirectURIs are matched exactly.
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// RefreshTokens makes the token endpoint issue refresh tokens.
	RefreshTokens bool
}

// ServiceClient is a service credential registered at the fake issuer.
type ServiceClient struct {
	// ID is the client ID.
	ID string
	// Secrets are the currently valid secrets (client_secret_basic); more
	// than one models the overlap during a rotation.
	Secrets []string
	// PublicKeys are the registered public keys by kid (private_key_jwt).
	PublicKeys map[string]crypto.PublicKey
}

// User is the person the fake authorization endpoint signs in.
type User struct {
	// Subject is the user ID (the sub claim).
	Subject string
	// Name and Username become the name and preferred_username claims when
	// the profile scope is requested.
	Name     string
	Username string
	// Email and EmailVerified become claims when the email scope is
	// requested and Email is not empty.
	Email         string
	EmailVerified bool
	// AMR lists how the user authenticated; the default is ["pwd"].
	AMR []string
}

// Token describes an access token to sign with AccessToken.
type Token struct {
	// Subject, ClientID, Audience, Principal and Scopes become the sub,
	// client_id, aud, principal_type and scope claims.
	Subject   string
	ClientID  string
	Audience  string
	Principal string
	Scopes    []string
	// Lifetime defaults to 15 minutes; IssuedAt defaults to now. A token
	// that expired long ago is {IssuedAt: an hour ago}.
	Lifetime time.Duration
	IssuedAt time.Time
	// Header adds or replaces protected header parameters, e.g. "typ".
	Header map[string]any
	// Claims adds or replaces claims; a nil value removes a claim. Use it
	// for tokens the real IAM would never issue, e.g. an array "aud".
	Claims map[string]any
	// KeyID signs with that key instead of the active one. It may name a
	// retired key.
	KeyID string
}

// Fault is a canned response for an endpoint, see Fail.
type Fault struct {
	// Status and Error become the HTTP status and the OAuth error code.
	Status int
	Error  string
	// RetryAfter, in seconds, is sent as Retry-After when not zero.
	RetryAfter int
	// Times is how many requests get this response; 0 means one.
	Times int
}

type authCode struct {
	clientID, redirectURI, challenge, nonce string
	scopes                                  []string
	user                                    User
	authTime                                time.Time
	sid                                     string
}

type refreshToken struct {
	clientID string
	chain    string
	used     bool
	scopes   []string
	user     User
	authTime time.Time
	sid      string
	nonce    string
}

// NewIssuer starts a fake issuer and stops it when the test ends.
func NewIssuer(tb testing.TB) *Issuer {
	tb.Helper()
	i := &Issuer{
		now: time.Now, lifetime: 15 * time.Minute,
		logins: map[string]*LoginClient{}, services: map[string]*ServiceClient{}, grants: map[string]map[string][]string{},
		introspect: map[string][]string{}, codes: map[string]*authCode{}, refresh: map[string]*refreshToken{},
		revoked: map[string]bool{}, seenJTI: map[string]bool{}, requests: map[string]int{}, faults: map[string][]Fault{},
	}
	i.activeKey = i.newKey()
	i.keys = []*signingKey{i.activeKey}
	mux := http.NewServeMux()
	mux.HandleFunc(PathDiscovery, i.discovery)
	mux.HandleFunc("/.well-known/oauth-authorization-server", i.discovery)
	mux.HandleFunc(PathJWKS, i.jwks)
	mux.HandleFunc(PathAuthorize, i.authorize)
	mux.HandleFunc(PathToken, i.token)
	mux.HandleFunc(PathUserInfo, i.userinfo)
	mux.HandleFunc(PathLogout, i.logout)
	mux.HandleFunc(PathRevoke, i.revoke)
	mux.HandleFunc(PathIntrospect, i.introspection)
	i.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		i.requests[r.URL.Path]++
		down := i.down
		var fault *Fault
		if queue := i.faults[r.URL.Path]; len(queue) > 0 {
			f := queue[0]
			fault = &f
			if queue[0].Times--; queue[0].Times <= 0 {
				i.faults[r.URL.Path] = queue[1:]
			}
		}
		i.mu.Unlock()
		if down {
			// Drop the connection: the client sees a network failure.
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("X-Request-ID", "fake-"+randomString(8))
		if fault != nil {
			if fault.RetryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprint(fault.RetryAfter))
			}
			oauthError(w, fault.Status, fault.Error, "injected by the test")
			return
		}
		mux.ServeHTTP(w, r)
	}))
	tb.Cleanup(i.srv.Close)
	return i
}

// URL returns the issuer identifier: use it as the Issuer of the SDK
// configuration.
func (i *Issuer) URL() string { return i.srv.URL }

// HTTPClient returns a client that trusts the fake issuer's certificate:
// use it as the HTTPClient of the SDK configuration.
func (i *Issuer) HTTPClient() *http.Client { return i.srv.Client() }

// Close stops the issuer. NewIssuer arranges for it at the end of the test.
func (i *Issuer) Close() { i.srv.Close() }

// UserInfoAudience returns the audience of the access tokens of a sign-in.
func (i *Issuer) UserInfoAudience() string { return i.URL() + PathUserInfo }

// ---- keys -------------------------------------------------------------------

func (i *Issuer) newKey() *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("iamtest: generating a key: " + err.Error())
	}
	return &signingKey{kid: "fake-key-" + randomString(6), priv: priv}
}

// KeyID returns the kid of the key that currently signs tokens.
func (i *Issuer) KeyID() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.activeKey.kid
}

// RotateKey publishes a new signing key and makes it the active one. The
// previous key stays published, as during a rotation at the real IAM. It
// returns the new kid.
func (i *Issuer) RotateKey() string {
	key := i.newKey()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = append(i.keys, key)
	i.activeKey = key
	return key.kid
}

// RetireKey removes a key from the published key set. Tokens signed with it
// must fail verification once the verifier has refreshed its keys.
func (i *Issuer) RetireKey(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = slices.DeleteFunc(i.keys, func(k *signingKey) bool { return k.kid == kid && k != i.activeKey })
}

// PublicKey returns the public half of the active signing key.
func (i *Issuer) PublicKey() *rsa.PublicKey {
	i.mu.Lock()
	defer i.mu.Unlock()
	return &i.activeKey.priv.PublicKey
}

// ---- tokens -----------------------------------------------------------------

// AccessToken signs an access token with the given content. Unless
// overridden, the header is {alg: RS256, typ: at+jwt, kid: active key} and
// the claims are those of the real IAM.
func (i *Issuer) AccessToken(t Token) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	issued := t.IssuedAt
	if issued.IsZero() {
		issued = i.now()
	}
	lifetime := t.Lifetime
	if lifetime == 0 {
		lifetime = 15 * time.Minute
	}
	claims := map[string]any{
		"iss": i.srv.URL, "sub": t.Subject, "aud": t.Audience, "iat": issued.Unix(), "exp": issued.Add(lifetime).Unix(),
		"jti": randomString(16), "client_id": t.ClientID, "scope": strings.Join(t.Scopes, " "), "principal_type": t.Principal,
	}
	if t.Principal == "user" {
		claims["sid"], claims["auth_time"] = "fake-session", issued.Unix()
	}
	for k, v := range t.Claims {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	header := map[string]any{"typ": "at+jwt"}
	for k, v := range t.Header {
		header[k] = v
	}
	key := i.activeKey
	if t.KeyID != "" {
		key = &signingKey{kid: t.KeyID, priv: i.activeKey.priv}
		for _, k := range i.keys {
			if k.kid == t.KeyID {
				key = k
			}
		}
	}
	return i.signLocked(key, header, claims)
}

// ServiceToken signs a system token: the caller is clientID acting as
// itself.
func (i *Issuer) ServiceToken(audience, clientID string, scopes ...string) string {
	return i.AccessToken(Token{Subject: clientID, ClientID: clientID, Audience: audience, Principal: "service", Scopes: scopes})
}

// UserToken signs a user-delegated token: clientID acts for the user.
func (i *Issuer) UserToken(audience, clientID, subject string, scopes ...string) string {
	return i.AccessToken(Token{Subject: subject, ClientID: clientID, Audience: audience, Principal: "user", Scopes: scopes})
}

// Sign signs arbitrary claims with the active key. The header gets alg
// RS256 and the active kid unless header says otherwise. It is the tool for
// tokens the real IAM would never issue.
func (i *Issuer) Sign(header, claims map[string]any) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.signLocked(i.activeKey, header, claims)
}

// OnIDToken installs a hook that runs for every ID token the token endpoint
// is about to issue. It may change the claims in place; when it returns a
// non-empty string, that string is sent as the ID token instead. sign signs
// with the active key (call it instead of Issuer.Sign inside the hook). Nil
// removes the hook.
func (i *Issuer) OnIDToken(hook func(claims map[string]any, sign func(header, claims map[string]any) string) string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.idHook = hook
}

// signLocked signs claims with key. Header parameters other than alg are
// taken from header; a "kid" there overrides the key's.
func (i *Issuer) signLocked(key *signingKey, header, claims map[string]any) string {
	opts := &jose.SignerOptions{}
	if _, ok := header["kid"]; !ok {
		opts.WithHeader("kid", key.kid)
	}
	for k, v := range header {
		if v != nil {
			opts.WithHeader(jose.HeaderKey(k), v)
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key.priv}, opts)
	if err != nil {
		panic("iamtest: " + err.Error())
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		panic("iamtest: " + err.Error())
	}
	token, _ := jws.CompactSerialize()
	i.sensitive = append(i.sensitive, token)
	return token
}

// ---- registry ---------------------------------------------------------------

// AddLoginClient registers an OIDC application.
func (i *Issuer) AddLoginClient(c LoginClient) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.logins[c.ID] = &c
	if c.Secret != "" {
		i.sensitive = append(i.sensitive, c.Secret)
	}
}

// AddServiceClient registers a service credential. Registering the same ID
// again replaces it, which is how a test rotates its secrets or keys.
func (i *Issuer) AddServiceClient(c ServiceClient) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.services[c.ID] = &c
	i.sensitive = append(i.sensitive, c.Secrets...)
}

// Grant gives a service credential the permissions on a target ("system"
// grant). Without permissions the grant is removed.
func (i *Issuer) Grant(clientID, resource string, permissions ...string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.grants[clientID] == nil {
		i.grants[clientID] = map[string][]string{}
	}
	if len(permissions) == 0 {
		delete(i.grants[clientID], resource)
		return
	}
	sorted := slices.Clone(permissions)
	slices.Sort(sorted)
	i.grants[clientID][resource] = sorted
}

// AllowIntrospection registers a service credential as allowed to
// introspect the tokens for a resource.
func (i *Issuer) AllowIntrospection(clientID, resource string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.introspect[clientID] = append(i.introspect[clientID], resource)
}

// SignIn makes the authorization endpoint sign this user in without any
// interaction, like an existing IAM session would.
func (i *Issuer) SignIn(u User) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.user, i.authTime, i.sid = &u, i.now(), "sid-"+randomString(8)
}

// SignOut ends the user's session at the issuer: refresh tokens issued
// under it stop working, and the authorization endpoint has nobody to sign
// in.
func (i *Issuer) SignOut() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.sid != "" {
		i.revoked["sid:"+i.sid] = true
	}
	i.user, i.sid = nil, ""
}

// ---- behaviour, faults, observation -------------------------------------------

// SetTokenLifetime sets the lifetime of the access tokens the token
// endpoint issues (expires_in). The default is 15 minutes.
func (i *Issuer) SetTokenLifetime(d time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lifetime = d
}

// SetClock replaces the issuer's clock.
func (i *Issuer) SetClock(now func() time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.now = now
}

// SetDown makes every request fail at the connection level, as if IAM were
// unreachable, until it is called with false.
func (i *Issuer) SetDown(down bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.down = down
}

// Fail makes the next request(s) to an endpoint path get the canned error
// response instead of being processed.
func (i *Issuer) Fail(path string, f Fault) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if f.Times <= 0 {
		f.Times = 1
	}
	i.faults[path] = append(i.faults[path], f)
}

// FailAuthorize makes the next authorization request come back with this
// error, e.g. "access_denied".
func (i *Issuer) FailAuthorize(code string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.authError = code
}

// Requests returns how many requests an endpoint path has received.
func (i *Issuer) Requests(path string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.requests[path]
}

// TokenRequests returns the form parameters of the token requests received
// so far, without credentials.
func (i *Issuer) TokenRequests() []url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.tokenForms)
}

// Sensitive returns every secret value the issuer has issued or received:
// tokens, authorization codes, client secrets, client assertions and PKCE
// verifiers. A test can assert that none of them shows up in logs or error
// messages.
func (i *Issuer) Sensitive() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.sensitive)
}

// ---- helpers ----------------------------------------------------------------

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("iamtest: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func sha256Sum(s string) [sha256.Size]byte { return sha256.Sum256([]byte(s)) }
