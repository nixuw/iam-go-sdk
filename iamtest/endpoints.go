package iamtest

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func (i *Issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := i.srv.URL
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + PathAuthorize,
		"token_endpoint":                                 iss + PathToken,
		"userinfo_endpoint":                              iss + PathUserInfo,
		"jwks_uri":                                       iss + PathJWKS,
		"revocation_endpoint":                            iss + PathRevoke,
		"introspection_endpoint":                         iss + PathIntrospect,
		"end_session_endpoint":                           iss + PathLogout,
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "private_key_jwt"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{"openid", "profile", "email", "offline_access"},
		"authorization_response_iss_parameter_supported": true,
		"iam_resource_prefix":                            "urn:iam:app:",
	})
}

func (i *Issuer) jwks(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, k := range i.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: "RS256", Use: "sig"})
	}
	i.mu.Unlock()
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

// authorize implements the authorization endpoint. There are no pages: the
// user set with SignIn is signed in at once.
func (i *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	i.mu.Lock()
	defer i.mu.Unlock()
	client := i.logins[q.Get("client_id")]
	redirectURI := q.Get("redirect_uri")
	if client == nil || !slices.Contains(client.RedirectURIs, redirectURI) {
		// No verified redirect URI: an error page, never a redirect.
		http.Error(w, "unknown client_id or unregistered redirect_uri", http.StatusBadRequest)
		return
	}
	state := q.Get("state")
	fail := func(code, description string) {
		u, _ := url.Parse(redirectURI)
		v := u.Query()
		v.Set("error", code)
		v.Set("error_description", description)
		if state != "" {
			v.Set("state", state)
		}
		v.Set("iss", i.srv.URL)
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	scopes := strings.Fields(q.Get("scope"))
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only the code response type is supported")
		return
	case state == "":
		fail("invalid_request", "state is required")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		fail("invalid_request", "PKCE with S256 is required")
		return
	case !slices.Contains(scopes, "openid"):
		fail("invalid_scope", "openid is required")
		return
	case q.Get("nonce") == "":
		fail("invalid_request", "nonce is required with openid")
		return
	case q.Has("resource"):
		fail("invalid_target", "the fake issuer does not model user delegation")
		return
	}
	if i.authError != "" {
		code := i.authError
		i.authError = ""
		fail(code, "injected by the test")
		return
	}
	prompt := q.Get("prompt")
	if i.user == nil {
		if prompt == "none" {
			fail("login_required", "the user is not authenticated")
			return
		}
		http.Error(w, "nobody is signed in at the fake issuer: call Issuer.SignIn first", http.StatusUnauthorized)
		return
	}
	now := i.now()
	if v := q.Get("max_age"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && now.Sub(i.authTime) > time.Duration(secs)*time.Second {
			if prompt == "none" {
				fail("login_required", "the authentication is too old")
				return
			}
			i.authTime = now // the user authenticates again
		}
	}
	if strings.Contains(prompt, "login") {
		i.authTime = now
	}
	code := "code-" + randomString(16)
	i.codes[code] = &authCode{
		clientID: client.ID, redirectURI: redirectURI, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
		scopes: scopes, user: *i.user, authTime: i.authTime, sid: i.sid,
	}
	i.sensitive = append(i.sensitive, code)
	u, _ := url.Parse(redirectURI)
	v := u.Query()
	v.Set("code", code)
	v.Set("state", state)
	v.Set("iss", i.srv.URL)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// form parses the body of a protocol request as the real IAM does.
func form(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Method != http.MethodPost || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		oauthError(w, http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded")
		return nil, false
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return nil, false
	}
	for k, vs := range r.PostForm {
		if len(vs) > 1 {
			if k == "resource" {
				oauthError(w, http.StatusBadRequest, "invalid_target", "only one resource may be requested")
			} else {
				oauthError(w, http.StatusBadRequest, "invalid_request", "duplicate parameter: "+k)
			}
			return nil, false
		}
	}
	return r.PostForm, true
}

// authenticated is the client a protocol request was authenticated as.
type authenticated struct {
	id      string
	login   *LoginClient
	service *ServiceClient
}

// authenticate implements client authentication: client_secret_basic and
// private_key_jwt, one method per request, nothing else. i.mu must be held.
func (i *Issuer) authenticate(w http.ResponseWriter, r *http.Request, f url.Values) (*authenticated, bool) {
	invalid := func(description string) (*authenticated, bool) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2", error="invalid_client"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", description)
		return nil, false
	}
	if f.Get("client_secret") != "" {
		return invalid("client_secret_post is not supported; use client_secret_basic")
	}
	basicID, basicSecret, hasBasic := basicAuth(r)
	assertion := f.Get("client_assertion")
	if hasBasic && (assertion != "" || f.Get("client_assertion_type") != "") {
		oauthError(w, http.StatusBadRequest, "invalid_request", "multiple client authentication methods used")
		return nil, false
	}
	lookup := func(id string) *authenticated {
		if c := i.logins[id]; c != nil {
			return &authenticated{id: id, login: c}
		}
		if c := i.services[id]; c != nil {
			return &authenticated{id: id, service: c}
		}
		return nil
	}
	switch {
	case hasBasic:
		i.sensitive = append(i.sensitive, basicSecret)
		c := lookup(basicID)
		if c == nil {
			return invalid("client authentication failed")
		}
		secrets := []string{}
		if c.login != nil && c.login.Secret != "" {
			secrets = append(secrets, c.login.Secret)
		}
		if c.service != nil {
			secrets = c.service.Secrets
		}
		for _, s := range secrets {
			if equal(s, basicSecret) {
				return c, true
			}
		}
		return invalid("client authentication failed")
	case assertion != "":
		i.sensitive = append(i.sensitive, assertion)
		if f.Get("client_assertion_type") != assertionType {
			oauthError(w, http.StatusBadRequest, "invalid_request", "unsupported client_assertion_type")
			return nil, false
		}
		jws, err := jose.ParseSignedCompact(assertion, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil || len(jws.Signatures) != 1 {
			return invalid("malformed client_assertion")
		}
		var claims struct {
			Iss string  `json:"iss"`
			Sub string  `json:"sub"`
			Aud any     `json:"aud"`
			Exp float64 `json:"exp"`
			JTI string  `json:"jti"`
		}
		if json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims) != nil || claims.Iss == "" || claims.Iss != claims.Sub {
			return invalid("client_assertion iss and sub must equal the client_id")
		}
		c := lookup(claims.Iss)
		if c == nil {
			return invalid("client authentication failed")
		}
		var keys map[string]crypto.PublicKey
		if c.login != nil {
			keys = c.login.PublicKeys
		} else {
			keys = c.service.PublicKeys
		}
		key, ok := keys[jws.Signatures[0].Protected.KeyID]
		if !ok {
			return invalid("client_assertion kid is not registered")
		}
		if _, err := jws.Verify(key); err != nil {
			return invalid("client_assertion signature invalid")
		}
		if aud, _ := claims.Aud.(string); aud != i.srv.URL+PathToken && aud != i.srv.URL {
			return invalid("client_assertion audience mismatch")
		}
		now := i.now().Unix()
		if exp := int64(claims.Exp); exp == 0 || exp < now-60 {
			return invalid("client_assertion expired")
		} else if exp-now > 300+60 {
			return invalid("client_assertion lifetime too long")
		}
		if claims.JTI == "" || i.seenJTI[c.id+"|"+claims.JTI] {
			return invalid("client_assertion jti missing or replayed")
		}
		i.seenJTI[c.id+"|"+claims.JTI] = true
		return c, true
	default:
		return invalid("client authentication required")
	}
}

func basicAuth(r *http.Request) (id, secret string, ok bool) {
	scheme, value, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", "", true
	}
	a, b, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", true
	}
	id, err1 := url.QueryUnescape(a)
	secret, err2 := url.QueryUnescape(b)
	if err1 != nil || err2 != nil {
		return "", "", true
	}
	return id, secret, true
}

func (i *Issuer) token(w http.ResponseWriter, r *http.Request) {
	f, ok := form(w, r)
	if !ok {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	logged := url.Values{}
	for k, vs := range f {
		if k != "client_assertion" && k != "code" && k != "code_verifier" && k != "refresh_token" {
			logged[k] = vs
		}
	}
	i.tokenForms = append(i.tokenForms, logged)
	c, ok := i.authenticate(w, r, f)
	if !ok {
		return
	}
	switch f.Get("grant_type") {
	case "client_credentials":
		i.clientCredentials(w, c, f)
	case "authorization_code":
		i.authorizationCode(w, c, f)
	case "refresh_token":
		i.refreshGrant(w, c, f)
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (i *Issuer) clientCredentials(w http.ResponseWriter, c *authenticated, f url.Values) {
	if c.service == nil {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "this client is an OIDC application and cannot use client_credentials; use a service credential")
		return
	}
	resource := f.Get("resource")
	granted, ok := i.grants[c.id][resource]
	if resource == "" || !ok {
		oauthError(w, http.StatusBadRequest, "invalid_target", "this client is not authorized for the target")
		return
	}
	scopes := strings.Fields(f.Get("scope"))
	for _, s := range scopes {
		if !slices.Contains(granted, s) {
			oauthError(w, http.StatusBadRequest, "invalid_scope", "the requested permission is not covered by the grant")
			return
		}
	}
	if len(scopes) == 0 {
		scopes = granted
	}
	scopes = slices.Clone(scopes)
	slices.Sort(scopes)
	now := i.now()
	token := i.signLocked(i.activeKey, map[string]any{"typ": "at+jwt"}, map[string]any{
		"iss": i.srv.URL, "sub": c.id, "aud": resource, "iat": now.Unix(), "exp": now.Add(i.lifetime).Unix(),
		"jti": randomString(16), "client_id": c.id, "scope": strings.Join(scopes, " "), "principal_type": "service",
	})
	writeJSON(w, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(i.lifetime / time.Second), "scope": strings.Join(scopes, " ")})
}

func (i *Issuer) authorizationCode(w http.ResponseWriter, c *authenticated, f url.Values) {
	if c.login == nil {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "service credentials can only use the client_credentials grant")
		return
	}
	i.sensitive = append(i.sensitive, f.Get("code_verifier"))
	if f.Get("code") == "" || f.Get("code_verifier") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
		return
	}
	code := i.codes[f.Get("code")]
	delete(i.codes, f.Get("code")) // single use
	switch {
	case code == nil:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired or already used code")
		return
	case code.clientID != c.id:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was not issued to this client")
		return
	case f.Get("redirect_uri") != code.redirectURI:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	case pkceChallenge(f.Get("code_verifier")) != code.challenge:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	rt := &refreshToken{clientID: c.id, chain: randomString(8), scopes: code.scopes, user: code.user, authTime: code.authTime, sid: code.sid, nonce: code.nonce}
	i.issueLogin(w, c.login, rt)
}

func (i *Issuer) refreshGrant(w http.ResponseWriter, c *authenticated, f url.Values) {
	if c.login == nil {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "service credentials can only use the client_credentials grant")
		return
	}
	if !c.login.RefreshTokens {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "refresh_token grant not allowed for this client")
		return
	}
	old := i.refresh[f.Get("refresh_token")]
	switch {
	case old == nil || old.clientID != c.id:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	case old.used:
		// Reuse of a rotated token: the whole chain is revoked.
		i.revoked["chain:"+old.chain] = true
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
		return
	case i.revoked["chain:"+old.chain]:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token revoked")
		return
	case !slices.Contains(old.scopes, "offline_access") && i.revoked["sid:"+old.sid]:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "session is no longer active")
		return
	}
	old.used = true
	next := *old
	next.used = false
	i.issueLogin(w, c.login, &next)
}

// issueLogin answers a sign-in or refresh: access token for UserInfo, ID
// token, and a rotated refresh token when the client may refresh.
func (i *Issuer) issueLogin(w http.ResponseWriter, client *LoginClient, rt *refreshToken) {
	now := i.now()
	scopes := slices.Clone(rt.scopes)
	slices.Sort(scopes)
	access := i.signLocked(i.activeKey, map[string]any{"typ": "at+jwt"}, map[string]any{
		"iss": i.srv.URL, "sub": rt.user.Subject, "aud": i.srv.URL + PathUserInfo, "iat": now.Unix(), "exp": now.Add(i.lifetime).Unix(),
		"jti": randomString(16), "client_id": client.ID, "scope": strings.Join(scopes, " "), "principal_type": "user",
		"sid": rt.sid, "auth_time": rt.authTime.Unix(),
	})
	idClaims := map[string]any{
		"iss": i.srv.URL, "sub": rt.user.Subject, "aud": client.ID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": rt.nonce, "auth_time": rt.authTime.Unix(), "sid": rt.sid, "at_hash": atHash(access),
	}
	if len(rt.user.AMR) > 0 {
		idClaims["amr"] = rt.user.AMR
	} else {
		idClaims["amr"] = []string{"pwd"}
	}
	for k, v := range profileClaims(rt.user, scopes) {
		idClaims[k] = v
	}
	idToken := ""
	if i.idHook != nil {
		idToken = i.idHook(idClaims, func(header, claims map[string]any) string { return i.signLocked(i.activeKey, header, claims) })
	}
	if idToken == "" {
		idToken = i.signLocked(i.activeKey, map[string]any{"typ": "JWT"}, idClaims)
	}
	out := map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": int(i.lifetime / time.Second), "scope": strings.Join(scopes, " "),
		"id_token": idToken,
	}
	if client.RefreshTokens {
		value := "rt_" + randomString(24)
		i.refresh[value] = rt
		i.sensitive = append(i.sensitive, value)
		out["refresh_token"] = value
	}
	writeJSON(w, out)
}

func profileClaims(u User, scopes []string) map[string]any {
	claims := map[string]any{}
	if slices.Contains(scopes, "profile") {
		claims["name"], claims["preferred_username"] = u.Name, u.Username
	}
	if slices.Contains(scopes, "email") && u.Email != "" {
		claims["email"], claims["email_verified"] = u.Email, u.EmailVerified
	}
	return claims
}

func atHash(accessToken string) string {
	sum := sha256Sum(accessToken)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// verifyOwn checks the signature of a token with the published keys and
// returns its header type and claims. i.mu must be held.
func (i *Issuer) verifyOwn(raw string) (typ string, claims map[string]any, ok bool) {
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		return "", nil, false
	}
	header := jws.Signatures[0].Protected
	for _, k := range i.keys {
		if k.kid != header.KeyID {
			continue
		}
		payload, err := jws.Verify(&k.priv.PublicKey)
		if err != nil || json.Unmarshal(payload, &claims) != nil {
			return "", nil, false
		}
		typ, _ = header.ExtraHeaders[jose.HeaderType].(string)
		return typ, claims, true
	}
	return "", nil, false
}

// activeAccess reports whether raw is an access token of this issuer that
// has neither expired nor been revoked. i.mu must be held.
func (i *Issuer) activeAccess(raw string) (map[string]any, bool) {
	typ, claims, ok := i.verifyOwn(raw)
	if !ok || typ != "at+jwt" {
		return nil, false
	}
	exp, _ := claims["exp"].(float64)
	jti, _ := claims["jti"].(string)
	if int64(exp) < i.now().Unix() || i.revoked["jti:"+jti] {
		return nil, false
	}
	return claims, true
}

func (i *Issuer) userinfo(w http.ResponseWriter, r *http.Request) {
	refuse := func(status int, code string) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="`+code+`"`)
		oauthError(w, status, code, "the access token is invalid for the userinfo endpoint")
	}
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	claims, ok := i.activeAccess(token)
	if !ok || claims["aud"] != i.srv.URL+PathUserInfo || claims["principal_type"] != "user" {
		refuse(http.StatusUnauthorized, "invalid_token")
		return
	}
	scopes := strings.Fields(claims["scope"].(string))
	if !slices.Contains(scopes, "openid") {
		refuse(http.StatusForbidden, "insufficient_scope")
		return
	}
	if i.user == nil || i.user.Subject != claims["sub"] {
		refuse(http.StatusUnauthorized, "invalid_token")
		return
	}
	out := profileClaims(*i.user, scopes)
	out["sub"] = i.user.Subject
	writeJSON(w, out)
}

// logout implements RP-initiated logout without the confirmation page: the
// user's session ends, and the browser is sent back only when the hint
// proves the client and the address is registered for it.
func (i *Issuer) logout(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.sid != "" {
		i.revoked["sid:"+i.sid] = true
	}
	i.user, i.sid = nil, ""
	if typ, claims, ok := i.verifyOwn(q.Get("id_token_hint")); ok && typ == "JWT" {
		aud, _ := claims["aud"].(string)
		if client := i.logins[aud]; client != nil && slices.Contains(client.PostLogoutRedirectURIs, q.Get("post_logout_redirect_uri")) {
			u, _ := url.Parse(q.Get("post_logout_redirect_uri"))
			if state := q.Get("state"); state != "" {
				v := u.Query()
				v.Set("state", state)
				u.RawQuery = v.Encode()
			}
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	_, _ = w.Write([]byte("signed out"))
}

func (i *Issuer) revoke(w http.ResponseWriter, r *http.Request) {
	f, ok := form(w, r)
	if !ok {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	c, ok := i.authenticate(w, r, f)
	if !ok {
		return
	}
	token := f.Get("token")
	if token == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	// A client can only revoke what it obtained itself; the answer is the
	// same either way.
	if rt := i.refresh[token]; rt != nil && rt.clientID == c.id {
		i.revoked["chain:"+rt.chain] = true
	} else if _, claims, ok := i.verifyOwn(token); ok && claims["client_id"] == c.id {
		jti, _ := claims["jti"].(string)
		i.revoked["jti:"+jti] = true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (i *Issuer) introspection(w http.ResponseWriter, r *http.Request) {
	f, ok := form(w, r)
	if !ok {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	c, ok := i.authenticate(w, r, f)
	if !ok {
		return
	}
	if f.Get("token") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	claims, active := i.activeAccess(f.Get("token"))
	aud, _ := claims["aud"].(string)
	// Only a credential registered on the token's target gets an answer.
	if !active || c.service == nil || !slices.Contains(i.introspect[c.id], aud) {
		writeJSON(w, map[string]any{"active": false})
		return
	}
	claims["active"], claims["token_type"] = true, "Bearer"
	writeJSON(w, claims)
}
