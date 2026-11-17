package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamhttp"
	"github.com/nixuw/iam-go-sdk/iamtest"
)

const resource = "urn:example:app:order"

// The example obtains a system token and calls the target, against the local
// fake issuer and a target that verifies the token with the SDK.
func TestExample(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_caller", Secrets: []string{"ssk_example_secret"}})
	iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_key", PublicKeys: map[string]crypto.PublicKey{"caller-1": &key.PublicKey}})
	iss.Grant("svc_example_caller", resource, "order.read")
	iss.Grant("svc_example_key", resource, "order.read")

	verifier, err := iam.NewVerifier(context.Background(), iam.VerifierConfig{Issuer: iss.URL(), Audience: resource, HTTPClient: iss.HTTPClient()})
	if err != nil {
		t.Fatal(err)
	}
	rule := iam.Rule{Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService}}
	target := httptest.NewServer(iamhttp.Guard(verifier).Require(rule)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("order 42 for " + iamhttp.Caller(r).ClientID))
	})))
	defer target.Close()

	t.Setenv("IAM_ISSUER", iss.URL())
	t.Setenv("IAM_SVC_CLIENT_ID", "svc_example_caller")
	t.Setenv("IAM_SVC_CLIENT_SECRET", "ssk_example_secret")
	t.Setenv("ORDER_RESOURCE", resource)
	t.Setenv("ORDER_API_URL", target.URL)
	t.Setenv("IAM_ALLOW_INSECURE", "true") // the test target speaks plain http on loopback
	call := func() (string, error) {
		t.Helper()
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		cfg.caller.HTTPClient = iss.HTTPClient() // trust the fake issuer's certificate
		var out bytes.Buffer
		err = run(context.Background(), cfg, &out)
		return out.String(), err
	}
	if out, err := call(); err != nil || out != "HTTP 200 order 42 for svc_example_caller\n" {
		t.Fatalf("client_secret_basic: %q %v", out, err)
	}

	// The same with a private_key_jwt credential read from a PEM file.
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	file := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IAM_SVC_CLIENT_ID", "svc_example_key")
	t.Setenv("IAM_SVC_KEY_ID", "caller-1")
	t.Setenv("IAM_SVC_PRIVATE_KEY_FILE", file)
	if out, err := call(); err != nil || out != "HTTP 200 order 42 for svc_example_key\n" {
		t.Fatalf("private_key_jwt: %q %v", out, err)
	}

	// Without a grant IAM refuses, and the error says why and how to find it.
	iss.Grant("svc_example_key", resource)
	if _, err := call(); err == nil || !strings.Contains(err.Error(), "invalid_target") || !strings.Contains(err.Error(), "request id") {
		t.Fatalf("without a grant: %v", err)
	}
}
