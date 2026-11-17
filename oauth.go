package iam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// client is one registered client (an OIDC application or a service
// credential) talking to the IAM endpoints that require client
// authentication: token, revocation and introspection.
type client struct {
	p    *provider
	id   string
	cred Credential
}

// tokenResponse is the success response of the token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// post sends an authenticated form request to an IAM endpoint. The client
// authentication is produced anew for every call: a private_key_jwt
// assertion is never reused. fp is the fingerprint of the credential used.
func (c *client) post(ctx context.Context, op, endpoint string, form url.Values) (res *http.Response, body []byte, fp string, err error) {
	meta, err := c.p.metadata(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	header := http.Header{}
	// The assertion audience is the token endpoint derived from the issuer,
	// for every endpoint: IAM accepts it everywhere.
	fp, err = c.cred.authenticate(ctx, c.id, meta.TokenEndpoint, form, header)
	if err != nil {
		return nil, nil, "", err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fp, &NetworkError{Op: op, Err: errors.New("invalid endpoint address")}
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, body, err = c.p.do(ctx, op, req)
	return res, body, fp, err
}

// token performs one token request.
func (c *client) token(ctx context.Context, form url.Values) (*tokenResponse, string, error) {
	meta, err := c.p.metadata(ctx)
	if err != nil {
		return nil, "", err
	}
	res, body, fp, err := c.post(ctx, "token request", meta.TokenEndpoint, form)
	if err != nil {
		return nil, fp, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fp, protocolError("token request", res, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") || tr.ExpiresIn <= 0 {
		return nil, fp, &NetworkError{Op: "token request", Err: errors.New("the token response is malformed")}
	}
	return &tr, fp, nil
}

// revoke asks IAM to revoke a token this client obtained (RFC 7009). IAM
// answers 200 whether or not the token existed.
func (c *client) revoke(ctx context.Context, token, hint string) error {
	meta, err := c.p.metadata(ctx)
	if err != nil {
		return err
	}
	if meta.RevocationEndpoint == "" {
		return &NetworkError{Op: "revocation", Err: errors.New("the issuer has no revocation endpoint")}
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	res, body, _, err := c.post(ctx, "revocation", meta.RevocationEndpoint, form)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return protocolError("revocation", res, body)
	}
	return nil
}

// splitScope splits a space separated scope value.
func splitScope(scope string) []string { return strings.Fields(scope) }
