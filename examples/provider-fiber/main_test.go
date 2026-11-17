package main

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nixuw/iam-go-sdk/iamtest"
)

const resource = "urn:example:app:order"

func TestExample(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	t.Setenv("IAM_ISSUER", iss.URL())
	t.Setenv("IAM_RESOURCE", resource)
	cfg := loadConfig()
	cfg.HTTPClient = iss.HTTPClient() // trust the fake issuer's certificate
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	read := iss.ServiceToken(resource, "svc_example_caller", "order.read")
	write := iss.ServiceToken(resource, "svc_example_caller", "order.write")
	user := iss.UserToken(resource, "app_example_portal", "user-1", "order.read", "order.write")
	for _, tc := range []struct {
		name, method, path, token string
		status                    int
		contains                  string
	}{
		{"no token", "GET", "/api/orders/42", "", 401, ""},
		{"token for another application", "GET", "/api/orders/42", iss.ServiceToken("urn:example:app:billing", "svc_example_caller", "order.read"), 401, "invalid_token"},
		{"system token", "GET", "/api/orders/42", read, 200, `"requested_by":"svc_example_caller"`},
		{"user-delegated token", "GET", "/api/orders/42", user, 200, `"requested_by":"user-1"`},
		{"missing permission", "POST", "/api/orders", read, 403, "insufficient_scope"},
		{"user token on a system-only endpoint", "POST", "/api/orders", user, 403, "insufficient_scope"},
		{"write", "POST", "/api/orders", write, 201, `"created_by":"svc_example_caller"`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != tc.status || !strings.Contains(string(body), tc.contains) {
			t.Fatalf("%s: HTTP %d %s", tc.name, res.StatusCode, body)
		}
		if tc.status >= 400 && !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), `Bearer realm="`+resource+`"`) {
			t.Fatalf("%s: challenge %q", tc.name, res.Header.Get("WWW-Authenticate"))
		}
	}
}
