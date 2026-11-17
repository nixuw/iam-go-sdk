package iam_test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"

	iam "github.com/nixuw/iam-go-sdk"
)

// A system calls another application as itself. The caller is created once
// and kept; one outbound client is created per target.
func ExampleNewCaller() {
	ctx := context.Background()
	caller, err := iam.NewCaller(ctx, iam.CallerConfig{
		Issuer:     os.Getenv("IAM_ISSUER"),
		ClientID:   os.Getenv("IAM_SVC_CLIENT_ID"), // the service credential, not the login client
		Credential: iam.ClientSecret(os.Getenv("IAM_SVC_CLIENT_SECRET")),
	})
	if err != nil {
		log.Fatal(err)
	}
	orders := caller.HTTPClient(iam.Target{
		Resource: os.Getenv("ORDER_RESOURCE"), // resource identifier of the target application
		Scopes:   []string{"order.read"},      // the least privilege this call needs
	})
	resp, err := orders.Get(os.Getenv("ORDER_API_URL") + "/api/orders/42")
	if err != nil {
		var oe *iam.OAuthError
		if errors.As(err, &oe) {
			// IAM refused to issue the token, e.g. invalid_target (no grant).
			log.Printf("token request refused: %s (request id %s)", oe.Code, oe.RequestID)
		}
		return
	}
	defer resp.Body.Close()
}

// A private_key_jwt credential whose key can be replaced at run time.
func ExamplePrivateKeyJWTFunc() {
	loadKey := func(context.Context) (iam.SigningKey, error) {
		pem, err := os.ReadFile(os.Getenv("IAM_SVC_PRIVATE_KEY_FILE"))
		if err != nil {
			return iam.SigningKey{}, err
		}
		key, err := iam.ParsePrivateKeyPEM(pem)
		return iam.SigningKey{KeyID: os.Getenv("IAM_SVC_KEY_ID"), Key: key}, err
	}
	_ = iam.CallerConfig{
		Issuer:     os.Getenv("IAM_ISSUER"),
		ClientID:   os.Getenv("IAM_SVC_CLIENT_ID"),
		Credential: iam.PrivateKeyJWTFunc(loadKey),
	}
}

// Verifying a token without an adapter, for transports and frameworks the
// SDK has no adapter for.
func ExampleVerifier_VerifyHeader() {
	ctx := context.Background()
	verifier, err := iam.NewVerifier(ctx, iam.VerifierConfig{
		Issuer:   os.Getenv("IAM_ISSUER"),
		Audience: os.Getenv("IAM_RESOURCE"), // this application's resource identifier
	})
	if err != nil {
		log.Fatal(err)
	}
	rule := iam.Rule{Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}}

	handler := func(w http.ResponseWriter, r *http.Request) {
		who, err := verifier.VerifyHeader(r.Context(), r.Header.Get("Authorization"), rule)
		var refused *iam.BearerError
		switch {
		case errors.As(err, &refused):
			if challenge := refused.WWWAuthenticate(); challenge != "" {
				w.Header().Set("WWW-Authenticate", challenge) // must be kept
			}
			w.WriteHeader(refused.Status)
			return
		case err != nil:
			w.WriteHeader(http.StatusForbidden) // refused by VerifierConfig.Authorize
			return
		}
		// Look at the principal type before interpreting the subject.
		if who.IsUser() {
			_ = who.Subject // a user; who.ClientID is the application acting for them
		} else {
			_ = who.ClientID // a system calling as itself
		}
	}
	_ = handler
}

// Sign-in for an application that keeps its own sessions: only the two
// protocol-level operations are used.
func ExampleLogin_AuthCodeURL() {
	ctx := context.Background()
	login, err := iam.NewLogin(ctx, iam.LoginConfig{
		Issuer:      os.Getenv("IAM_ISSUER"),
		ClientID:    os.Getenv("IAM_CLIENT_ID"),
		Credential:  iam.ClientSecret(os.Getenv("IAM_CLIENT_SECRET")),
		RedirectURL: os.Getenv("APP_CALLBACK_URL"),
	})
	if err != nil {
		log.Fatal(err)
	}
	var pending iam.PendingLogin // kept in the application's own server-side session

	start := func(w http.ResponseWriter, r *http.Request) {
		req, err := login.AuthCodeURL(r.Context(), iam.AuthOptions{ReturnTo: "/dashboard"})
		if err != nil {
			http.Error(w, "sign-in is unavailable", http.StatusServiceUnavailable)
			return
		}
		pending = req.Pending // bound to this browser; used once
		http.Redirect(w, r, req.URL, http.StatusFound)
	}
	callback := func(w http.ResponseWriter, r *http.Request) {
		result, err := login.Exchange(r.Context(), &pending, r.URL.Query())
		pending = iam.PendingLogin{}
		if err != nil {
			http.Error(w, "sign-in failed", http.StatusBadRequest)
			return
		}
		// result.User.Issuer + result.User.Subject is the key of the user.
		// Keep result.Tokens.IDToken for logout (LogoutURL) and refresh with
		// login.Refresh when a refresh token was issued.
		http.Redirect(w, r, result.ReturnTo, http.StatusFound)
	}
	_, _ = start, callback
}
