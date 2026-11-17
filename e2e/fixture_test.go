//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Fixture describes a real IAM and what is registered in it for this run.
// The file named by IAM_E2E_FIXTURE holds it as JSON; docs/e2e.md documents
// every field.
type Fixture struct {
	Issuer string `json:"issuer"`
	// AllowInsecure is set when the issuer and the test applications speak
	// plain http (a throw-away IAM on loopback).
	AllowInsecure bool `json:"allow_insecure"`
	Login         struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		// BaseURL is where the sign-in example must listen: BaseURL +
		// "/callback" is the registered redirect URI and BaseURL + "/" the
		// registered post-logout redirect URI.
		BaseURL  string `json:"base_url"`
		Username string `json:"username"`
		Subject  string `json:"subject"`
		Name     string `json:"name"`
		Email    string `json:"email"`
	} `json:"login"`
	CallerSecret struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"caller_secret"`
	CallerKey struct {
		ClientID      string `json:"client_id"`
		KeyID         string `json:"key_id"`
		PrivateKeyPEM string `json:"private_key_pem"`
	} `json:"caller_key"`
	Provider struct {
		// Resource is the resource identifier of the provider application
		// "order" with the permissions order.read and order.write. Both
		// caller credentials hold a system grant on both permissions.
		Resource      string `json:"resource"`
		Introspection struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"introspection"`
		// SampleRSURL is IAM's own sample resource server for Resource, with
		// GET /items (order.read; service, user) and GET /items/write
		// (order.write; service).
		SampleRSURL string `json:"sample_rs_url"`
	} `json:"provider"`
	// OtherResource is a second application the secret credential holds a
	// grant on; NoGrantResource exists but nobody holds a grant on it.
	OtherResource   string `json:"other_resource"`
	NoGrantResource string `json:"no_grant_resource"`
	Tokens          struct {
		// UserDelegated is a user-delegated access token for Resource with
		// order.read and order.write, issued to the login client.
		UserDelegated string `json:"user_delegated"`
	} `json:"tokens"`
	// ControlURL is the test operator: it plays the user in the browser and
	// the IAM administrator. Scenarios that need it are skipped without it.
	ControlURL string `json:"control_url"`
}

var fx Fixture

func TestMain(m *testing.M) {
	path := os.Getenv("IAM_E2E_FIXTURE")
	if path == "" {
		fmt.Fprintln(os.Stderr, "IAM_E2E_FIXTURE is not set: the end-to-end tests need a real IAM, see docs/e2e.md")
		os.Exit(1)
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(raw, &fx)
	}
	if err != nil || fx.Issuer == "" {
		fmt.Fprintf(os.Stderr, "cannot read the fixture %s: %v\n", path, err)
		os.Exit(1)
	}
	code := m.Run()
	stopAll(code != 0)
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// ---- the test operator --------------------------------------------------------

// control asks the test operator to do something a person would do.
func control(t *testing.T, path string, in, out any) {
	t.Helper()
	if fx.ControlURL == "" {
		t.Skip("this scenario needs the test operator (control_url in the fixture)")
	}
	body, _ := json.Marshal(in)
	res, err := http.Post(fx.ControlURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("test operator %s: %v", path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("test operator %s: HTTP %d %s", path, res.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("test operator %s: %v", path, err)
		}
	}
}

// userAuthorizes lets the user of the named browser follow an authorization
// URL at IAM (sign in, consent) and returns where IAM sends the browser.
func userAuthorizes(t *testing.T, browser, authURL string) *url.URL {
	t.Helper()
	var out struct {
		Location string `json:"location"`
	}
	control(t, "/user-agent/authorize", map[string]string{"browser": browser, "url": authURL, "username": fx.Login.Username}, &out)
	u, err := url.Parse(out.Location)
	if err != nil || out.Location == "" {
		t.Fatalf("IAM did not redirect back: %q", out.Location)
	}
	return u
}

// userConfirmsLogout lets the user follow a logout URL at IAM and confirm,
// and returns where IAM sends the browser ("" when it stays at IAM).
func userConfirmsLogout(t *testing.T, browser, logoutURL string) string {
	t.Helper()
	var out struct {
		Location string `json:"location"`
	}
	control(t, "/user-agent/logout", map[string]string{"browser": browser, "url": logoutURL}, &out)
	return out.Location
}

// rotateSigningKey lets the administrator generate and activate a new
// signing key and returns its kid.
func rotateSigningKey(t *testing.T) string {
	t.Helper()
	var out struct {
		KID string `json:"kid"`
	}
	control(t, "/signing-keys/rotate", map[string]string{}, &out)
	return out.KID
}

// ---- HTTP towards IAM ---------------------------------------------------------

// countingTransport counts the requests per path that an SDK instance sends
// to IAM, and can cut the connection.
type countingTransport struct {
	mu     sync.Mutex
	counts map[string]int
	cut    atomic.Bool
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.cut.Load() {
		return nil, errors.New("IAM is unreachable (cut by the test)")
	}
	c.mu.Lock()
	if c.counts == nil {
		c.counts = map[string]int{}
	}
	c.counts[req.URL.Path]++
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(req)
}

func (c *countingTransport) count(pathSuffix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for path, v := range c.counts {
		if strings.HasSuffix(path, pathSuffix) {
			n += v
		}
	}
	return n
}

func (c *countingTransport) client() *http.Client {
	return &http.Client{Transport: c, Timeout: 10 * time.Second}
}

// ---- example applications as processes ----------------------------------------

var (
	binDir   string
	binOnce  sync.Once
	binErr   error
	procsMu  sync.Mutex
	procs    []*exec.Cmd
	procLogs = map[string]*bytes.Buffer{}
)

// moduleRoot is the root of the SDK module; the tests run in its e2e folder.
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// example builds the example programs once and returns the path of one.
func example(t *testing.T, name string) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "iam-go-sdk-examples-")
		if binErr != nil {
			return
		}
		cmd := exec.Command("go", "build", "-trimpath", "-o", binDir+string(os.PathSeparator), "./examples/...")
		cmd.Dir = moduleRoot(t)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("building the examples: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return filepath.Join(binDir, name)
}

func insecureEnv() string {
	if fx.AllowInsecure {
		return "IAM_ALLOW_INSECURE=true"
	}
	return "IAM_ALLOW_INSECURE=false"
}

// serveExample starts an example server on addr and waits until it listens.
// It keeps running until the end of the test binary.
func serveExample(t *testing.T, name, addr string, env ...string) {
	t.Helper()
	cmd := exec.Command(example(t, name))
	cmd.Env = append(append(os.Environ(), "LISTEN_ADDR="+addr, "IAM_ISSUER="+fx.Issuer, insecureEnv()), env...)
	logs := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting example %s: %v", name, err)
	}
	procsMu.Lock()
	procs = append(procs, cmd)
	procLogs[name+" on "+addr] = logs
	procsMu.Unlock()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("example %s did not start listening on %s", name, addr)
}

// runExample runs an example command to completion and returns its output.
func runExample(t *testing.T, name string, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, example(t, name))
	cmd.Env = append(append(os.Environ(), "IAM_ISSUER="+fx.Issuer, insecureEnv()), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// stopAll ends the example processes; after a failed run it prints what
// they wrote.
func stopAll(failed bool) {
	procsMu.Lock()
	defer procsMu.Unlock()
	for _, cmd := range procs {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	if failed {
		for name, logs := range procLogs {
			if logs.Len() > 0 {
				fmt.Fprintf(os.Stderr, "--- output of example %s:\n%s\n", name, logs.String())
			}
		}
	}
}

// freeAddr returns a loopback address nothing listens on right now.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// ---- tokens -------------------------------------------------------------------

// jwtPart decodes a part (0 header, 1 payload) of a JWT without verifying.
func jwtPart(t *testing.T, token string, part int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT (%d parts)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[part])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}
