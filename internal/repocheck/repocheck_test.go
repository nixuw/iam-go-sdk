package repocheck

import (
	"bufio"
	"bytes"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const module = "github.com/nixuw/iam-go-sdk"

// root returns the repository root.
func root(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}
	return dir
}

func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

var (
	webFrameworks = []string{"github.com/gofiber/", "github.com/valyala/fasthttp", "github.com/gin-gonic/", "github.com/labstack/", "github.com/go-chi/"}
	grpcModules   = []string{"google.golang.org/grpc", "google.golang.org/protobuf", "google.golang.org/genproto"}
)

func containsAny(s string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return n
		}
	}
	return ""
}

// TestPackageDependencies is GEN-05, GEN-06 and ADAPT-05 at the package
// level: the core imports no web framework and not gRPC, and no adapter
// drags in another one.
func TestPackageDependencies(t *testing.T) {
	deps := func(pkg string) []string {
		return strings.Fields(run(t, root(t), nil, "go", "list", "-deps", pkg))
	}
	for pkg, forbidden := range map[string][]string{
		".":          append(append([]string{}, webFrameworks...), grpcModules...),
		"./iamhttp":  append(append([]string{}, webFrameworks...), grpcModules...),
		"./iamtest":  append(append([]string{}, webFrameworks...), grpcModules...),
		"./iamfiber": grpcModules,
		"./iamgrpc":  webFrameworks,
	} {
		for _, dep := range deps(pkg) {
			if bad := containsAny(dep, forbidden); bad != "" {
				t.Errorf("package %s depends on %s (%s)", pkg, bad, dep)
			}
		}
	}
	// The core needs exactly one third-party module: go-jose.
	for _, dep := range deps(".") {
		first, _, _ := strings.Cut(dep, "/")
		if !strings.Contains(first, ".") || strings.HasPrefix(dep, module) || strings.HasPrefix(dep, "github.com/go-jose/go-jose/v4") {
			continue // standard library, this module, go-jose
		}
		t.Errorf("the core has an unexpected third-party dependency: %s", dep)
	}
}

// TestFreshModule is AC-01: a brand-new Go module uses the SDK. With only the
// core imported, its dependencies (go.mod and go.sum) contain no web
// framework and no gRPC; with one adapter, not the other one's. The module
// proxy is switched off, so nothing can be fetched from anywhere else.
func TestFreshModule(t *testing.T) {
	if testing.Short() {
		t.Skip("builds three throw-away modules")
	}
	repo := root(t)
	for name, tc := range map[string]struct {
		imports   string
		use       string
		forbidden []string
	}{
		"core only": {
			imports:   `iam "` + module + `"`,
			use:       `_, _ = iam.NewVerifier(context.Background(), iam.VerifierConfig{})`,
			forbidden: append(append([]string{}, webFrameworks...), grpcModules...),
		},
		"core and net/http": {
			imports:   `iam "` + module + `"` + "\n\t\"" + module + `/iamhttp"`,
			use:       `v, _ := iam.NewVerifier(context.Background(), iam.VerifierConfig{}); _ = iamhttp.Guard(v)`,
			forbidden: append(append([]string{}, webFrameworks...), grpcModules...),
		},
		"core and Fiber": {
			imports:   `iam "` + module + `"` + "\n\t\"" + module + `/iamfiber"`,
			use:       `v, _ := iam.NewVerifier(context.Background(), iam.VerifierConfig{}); _ = iamfiber.Guard(v)`,
			forbidden: grpcModules,
		},
		"core and gRPC": {
			imports:   `iam "` + module + `"` + "\n\t\"" + module + `/iamgrpc"`,
			use:       `v, _ := iam.NewVerifier(context.Background(), iam.VerifierConfig{}); _ = iamgrpc.UnaryServerInterceptor(v, nil)`,
			forbidden: webFrameworks,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(file, content string) {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			write("go.mod", "module example.test/consumer\n\ngo 1.26.11\n\nrequire "+module+" v0.0.0\n\nreplace "+module+" => "+repo+"\n")
			write("main.go", "package main\n\nimport (\n\t\"context\"\n\n\t"+tc.imports+"\n)\n\nfunc main() {\n\t"+tc.use+"\n}\n")
			env := []string{"GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off", "CGO_ENABLED=0"}
			run(t, dir, env, "go", "mod", "tidy")
			run(t, dir, env, "go", "build", "-trimpath", "-o", os.DevNull, ".")
			for _, file := range []string{"go.mod", "go.sum"} {
				content, err := os.ReadFile(filepath.Join(dir, file))
				if err != nil {
					t.Fatal(err)
				}
				if bad := containsAny(string(content), tc.forbidden); bad != "" {
					t.Errorf("%s of a module that uses %s mentions %s:\n%s", file, name, bad, content)
				}
			}
			for _, dep := range strings.Fields(run(t, dir, env, "go", "list", "-deps", ".")) {
				if bad := containsAny(dep, tc.forbidden); bad != "" {
					t.Errorf("the build of a module that uses %s includes %s", name, dep)
				}
			}
		})
	}
}

// TestEngineeringStandard is the static part of AC-19 (the commands gofmt,
// go vet, go build, make unit and make e2e are the other part).
func TestEngineeringStandard(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	gomod := string(raw)
	if !regexp.MustCompile(`(?m)^go 1\.26\.11$`).MatchString(gomod) {
		t.Error("go.mod must say `go 1.26.11`")
	}
	if regexp.MustCompile(`(?m)^toolchain `).MatchString(gomod) {
		t.Error("go.mod must not have a toolchain line")
	}
	// The same major versions as IAM for the libraries both use.
	for _, want := range []string{"github.com/gofiber/fiber/v2 v2.", "github.com/go-jose/go-jose/v4 v4."} {
		if !strings.Contains(gomod, want) {
			t.Errorf("go.mod must require %s…", want)
		}
	}
	for _, other := range []string{"gofiber/fiber/v3", "go-jose/go-jose/v3", "gopkg.in/square/go-jose", "golang-jwt", "coreos/go-oidc", "golang.org/x/oauth2"} {
		if strings.Contains(gomod, other) {
			t.Errorf("go.mod must not require %s", other)
		}
	}
	// No cgo anywhere.
	if out := run(t, root(t), nil, "go", "list", "-f", `{{if .CgoFiles}}{{.ImportPath}}{{end}}`, "./..."); strings.TrimSpace(out) != "" {
		t.Errorf("packages using cgo: %s", out)
	}
	// The Makefile offers the standard commands.
	makefile, err := os.ReadFile(filepath.Join(root(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"vet:", "unit:", "e2e:", "fmt:"} {
		if !bytes.Contains(makefile, []byte("\n"+target)) {
			t.Errorf("the Makefile lacks the %s target", strings.TrimSuffix(target, ":"))
		}
	}
}

// Hosts that may appear in the repository: reserved example names, loopback,
// and the public homes of the standards and libraries the SDK refers to.
var allowedHosts = []string{
	"example.com", "example.org", "example.net", "example.test", ".example", ".test", "localhost", "127.0.0.1",
	"github.com", "golang.org", "pkg.go.dev", "go.dev", "google.golang.org", "gopkg.in",
	"rfc-editor.org", "ietf.org", "openid.net", "apache.org", "semver.org", "keepachangelog.com",
}

var (
	urlPattern     = regexp.MustCompile(`https?://[A-Za-z0-9._~%:@\[\]-]+`)
	ipPattern      = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	hostPattern    = regexp.MustCompile(`\b[a-z0-9][a-z0-9.-]*\.(cluster|internal|corp|intranet|lan|svc)\b`)
	clientPattern  = regexp.MustCompile(`\b(svc|app)_[A-Za-z0-9]{16}\b`)
	secretPattern  = regexp.MustCompile(`\bssk_[A-Za-z0-9_-]{24,}`)
	refreshPattern = regexp.MustCompile(`\brt_[A-Za-z0-9_-]{40,}`)
	jwtPattern     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`)
	keyPattern     = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{64,}`)
)

// findings scans text for things that must not be in a public repository.
func findings(text string) []string {
	var out []string
	for _, raw := range urlPattern.FindAllString(text, -1) {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		ok := host == ""
		for _, allowed := range allowedHosts {
			if host == allowed || strings.HasSuffix(host, "."+strings.TrimPrefix(allowed, ".")) {
				ok = true
			}
		}
		if !ok {
			out = append(out, "address of an unknown host: "+raw)
		}
	}
	for _, ip := range ipPattern.FindAllString(text, -1) {
		if ip != "127.0.0.1" && ip != "0.0.0.0" {
			out = append(out, "IP address: "+ip)
		}
	}
	for label, pattern := range map[string]*regexp.Regexp{
		"internal host name": hostPattern, "real-looking client ID": clientPattern, "client secret": secretPattern,
		"refresh token": refreshPattern, "JWT": jwtPattern, "private key": keyPattern,
	} {
		for _, m := range pattern.FindAllString(text, -1) {
			if len(m) > 40 {
				m = m[:40] + "…"
			}
			out = append(out, label+": "+m)
		}
	}
	return out
}

// TestNoSensitiveContent is AC-02 / GEN-04: no internal domain, IP address,
// real client ID, key or token in the files of the repository, nor in its
// commit history.
func TestNoSensitiveContent(t *testing.T) {
	repo := root(t)
	// The scanner itself must work.
	// (The samples are assembled at run time so that this file passes its
	// own scan.)
	for _, planted := range []string{
		"http" + "://10." + "20.30.40:30280", "https" + "://iam-portal." + "corp/docs", "registry." + "cluster:5000/golang", "svc_" + "8f3kQ2mZx7Lp0aBc",
		"ssk_" + strings.Repeat("aB3", 10), "eyJ" + strings.Repeat("a", 30) + ".eyJ" + strings.Repeat("b", 30) + "." + strings.Repeat("c", 30),
		"-----BEGIN RSA " + "PRIVATE KEY-----\n" + strings.Repeat("MIIEvQIBADANBgkq", 8),
	} {
		if len(findings(planted)) == 0 {
			t.Fatalf("the scanner misses %q", planted)
		}
	}
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(repo, path)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if rel == "go.sum" || bytes.IndexByte(content, 0) >= 0 {
			return nil // checksums; binary files
		}
		for _, f := range findings(string(content)) {
			t.Errorf("%s: %s", rel, f)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The commit history, once there is one.
	if _, err := os.Stat(filepath.Join(repo, ".git")); err == nil {
		history := run(t, repo, nil, "git", "log", "--all", "-p", "--no-color", "--", ".", ":(exclude)go.sum")
		for _, f := range findings(history) {
			t.Errorf("commit history: %s", f)
		}
	}
}

// TestExamplesStaySmall is AC-15: in every example, the code an application
// adds to integrate (between the iam:start and iam:end markers, not counting
// the reading of configuration, comments and blank lines) is at most 20
// lines, and the example never touches JWTs, PKCE, JWKS or token caches
// itself.
func TestExamplesStaySmall(t *testing.T) {
	examples, err := filepath.Glob(filepath.Join(root(t), "examples", "*", "main.go"))
	if err != nil || len(examples) < 6 {
		t.Fatalf("examples not found: %v (%d)", err, len(examples))
	}
	forbidden := regexp.MustCompile(`(?i)go-jose|golang-jwt|go-oidc|x/oauth2|jwks|pkce|code_verifier|code_challenge|ParseSigned|jwt\.|base64|expires_in`)
	for _, file := range examples {
		name := filepath.Base(filepath.Dir(file))
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		lines, inside, regions := 0, false, 0
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			switch {
			case line == "// iam:start":
				inside = true
				regions++
			case line == "// iam:end":
				inside = false
			case inside && line != "" && !strings.HasPrefix(line, "//"):
				lines++
			}
			if m := forbidden.FindString(scanner.Text()); m != "" {
				t.Errorf("example %s handles protocol details itself: %q", name, m)
			}
		}
		f.Close()
		if regions != 1 || inside {
			t.Errorf("example %s must mark its integration code with one iam:start … iam:end region", name)
		}
		if lines == 0 || lines > 20 {
			t.Errorf("example %s needs %d lines of integration code; the limit is 20", name, lines)
		}
		t.Logf("example %s: %d lines of integration code", name, lines)
	}
}
