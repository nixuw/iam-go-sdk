package iam

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// idTokenCheck is what an ID token is validated against besides the fixed
// checks (signature, iss, aud, exp, iat).
type idTokenCheck struct {
	nonce       string
	checkNonce  bool
	maxAge      int64  // seconds requested with max_age; -1 when not requested
	accessToken string // for at_hash, when the ID token carries one
}

type idTokenClaims struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"`
	Azp               string          `json:"azp"`
	Exp               *float64        `json:"exp"`
	Iat               *float64        `json:"iat"`
	Nonce             string          `json:"nonce"`
	AuthTime          *float64        `json:"auth_time"`
	AtHash            string          `json:"at_hash"`
	AMR               []string        `json:"amr"`
	SID               string          `json:"sid"`
	Name              string          `json:"name"`
	PreferredUsername string          `json:"preferred_username"`
	Email             string          `json:"email"`
	EmailVerified     bool            `json:"email_verified"`
}

// verifyIDToken validates an ID token and returns the user it names. Every
// failed check fails the sign-in with an error matching ErrInvalidToken.
func (l *Login) verifyIDToken(ctx context.Context, raw string, check idTokenCheck) (*User, error) {
	p := l.cl.p
	bad := func(reason string) error { return fmt.Errorf("%w: id token: %s", ErrInvalidToken, reason) }
	if len(raw) > maxTokenBytes {
		return nil, bad("too large")
	}
	// Signature: RS256 only, with a key of the configured issuer.
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, bad("not a JWT signed with RS256")
	}
	header := jws.Signatures[0].Protected
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); strings.Contains(strings.ToLower(typ), "at+jwt") {
		return nil, bad("this is an access token")
	}
	if header.KeyID == "" {
		return nil, bad("kid missing")
	}
	key, err := p.keys.key(ctx, header.KeyID)
	switch {
	case errors.Is(err, errKeyNotFound):
		return nil, bad("signing key not found")
	case errors.Is(err, ErrUnavailable):
		return nil, fmt.Errorf("%w: the signing keys of the issuer are not available", ErrUnavailable)
	case err != nil:
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, bad("signature invalid")
	}
	var c idTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, bad("claims malformed")
	}
	if c.Iss != p.issuer {
		return nil, bad("issuer mismatch")
	}
	// aud: this application. IAM issues a single audience.
	if !soleAudience(c.Aud, l.cl.id) || (c.Azp != "" && c.Azp != l.cl.id) {
		return nil, bad("audience is not this client")
	}
	now := p.clock()
	if c.Exp == nil || *c.Exp <= 0 || now.After(unixTime(*c.Exp).Add(l.leeway)) {
		return nil, bad("expired")
	}
	if c.Iat == nil || *c.Iat <= 0 || unixTime(*c.Iat).After(now.Add(l.leeway)) {
		return nil, bad("issued in the future")
	}
	if c.Sub == "" {
		return nil, bad("sub missing")
	}
	if check.checkNonce && (c.Nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(check.nonce)) != 1) {
		return nil, bad("nonce mismatch")
	}
	if check.maxAge >= 0 {
		if c.AuthTime == nil {
			return nil, bad("auth_time missing although max_age was requested")
		}
		if now.Sub(unixTime(*c.AuthTime)) > secondsDuration(check.maxAge)+l.leeway {
			return nil, bad("the authentication is older than max_age")
		}
	}
	if c.AtHash != "" && check.accessToken != "" {
		sum := sha256.Sum256([]byte(check.accessToken))
		if base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]) != c.AtHash {
			return nil, bad("at_hash does not match the access token")
		}
	}
	user := &User{
		Issuer: c.Iss, Subject: c.Sub, Name: c.Name, PreferredUsername: c.PreferredUsername,
		Email: c.Email, EmailVerified: c.EmailVerified, AMR: c.AMR, SessionID: c.SID,
	}
	if c.AuthTime != nil {
		user.AuthTime = unixTime(*c.AuthTime).UTC()
	}
	return user, nil
}

// soleAudience reports whether aud is want, as a string or as an array with
// exactly that one element.
func soleAudience(aud json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(aud, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(aud, &many) == nil && len(many) == 1 && many[0] == want
}
