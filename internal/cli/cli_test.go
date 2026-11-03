package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const tok = "dnt_cli_test_token_123456"

type fake struct {
	mu    sync.Mutex
	calls []string
	srv   *httptest.Server
}

func newFake(t *testing.T) *fake {
	f := &fake{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+tok {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"success":false,"message":"bad token"}`)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/compute/7":
			fmt.Fprint(w, `{"success":true,"data":{"id":7,"hostname":"web-1","status":"running","service_status":"active"}}`)
		case r.Method == "GET" && r.URL.Path == "/v1/billing/balance":
			fmt.Fprint(w, `{"success":true,"data":{"balance":-11.69,"currency":"USD"}}`)
		case r.Method == "POST" && r.URL.Path == "/v1/webhooks":
			fmt.Fprint(w, `{"success":true,"data":{"webhook":{"id":3,"name":"m","secret":"whsec_shown_once_value"}}}`)
		default:
			fmt.Fprint(w, `{"success":true,"data":{"ok":true}}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

func run(f *fake, args ...string) (int, string, string) {
	var out, errw bytes.Buffer
	e := &env{out: &out, errw: &errw, getenv: func(k string) string {
		if k == "DARTNODE_TOKEN" {
			return tok
		}
		return ""
	}}
	rest, err := e.globals(append([]string{"--api", f.srv.URL + "/v1"}, args...))
	if err != nil {
		return 2, "", err.Error()
	}
	code := 0
	if err := e.run(context.Background(), rest[0], rest[1:]); err != nil {
		code = 1
		if _, ok := err.(usageError); ok {
			code = 2
		}
		errw.WriteString(err.Error())
	}
	return code, out.String(), errw.String()
}

func TestTokenFlagRefused(t *testing.T) {
	e := &env{getenv: func(string) string { return "" }}
	for _, a := range [][]string{{"--token", "dnt_x"}, {"--token=dnt_x"}} {
		if _, err := e.globals(a); err == nil {
			t.Errorf("%v accepted", a)
		}
	}
}

func TestDestructiveGates(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"power off without yes", []string{"power", "7", "off", "--confirm", "web-1"}},
		{"power off without confirm", []string{"power", "7", "off", "--yes"}},
		{"power off wrong confirm", []string{"power", "7", "off", "--yes", "--confirm", "web-2"}},
		{"hard reboot without confirm", []string{"power", "7", "reboot-hard", "--yes"}},
		{"reinstall without confirm", []string{"reinstall", "7", "--os", "5", "--yes"}},
		{"reinstall without os", []string{"reinstall", "7", "--yes", "--confirm", "web-1"}},
		{"reset-password wrong confirm", []string{"reset-password", "7", "--yes", "--confirm", "WEB-1"}},
		{"shutdown without yes", []string{"power", "7", "shutdown"}},
		{"rdns clear without confirm", []string{"rdns", "clear", "192.0.2.1", "--yes"}},
		{"rdns set without yes", []string{"rdns", "set", "192.0.2.1", "mail.example.com"}},
		{"webhook delete wrong confirm", []string{"webhooks", "delete", "3", "--yes", "--confirm", "4"}},
		{"webhook create without secret-out", []string{"webhooks", "create", "--name", "m", "--url", "https://x.example/h", "--events", "*", "--yes"}},
		{"webhook create http url", []string{"webhooks", "create", "--name", "m", "--url", "http://x.example/h", "--events", "*", "--yes", "--secret-out", "/nonexistent-dir/s"}},
		{"deploy without yes", []string{"deploy", "create", "--plan", "1", "--region", "us-dal", "--hostname", "n", "--os", "1", "--os-version", "5"}},
		{"bad power action", []string{"power", "7", "explode", "--yes"}},
		{"bad id", []string{"power", "../7", "on", "--yes"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			code, _, _ := run(f, c.args...)
			if code == 0 {
				t.Fatal("command succeeded")
			}
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("mutation sent despite refusal: %v", m)
			}
		})
	}
}

func TestDestructiveAllowedWithMatchingConfirm(t *testing.T) {
	f := newFake(t)
	if code, _, errw := run(f, "power", "7", "off", "--yes", "--confirm", "web-1"); code != 0 {
		t.Fatalf("code %d: %s", code, errw)
	}
	if m := f.mutations(); len(m) != 1 || m[0] != "POST /v1/compute/7/power" {
		t.Fatalf("mutations %v", m)
	}
}

func TestWebhookCreateWritesSecretAndNeverPrintsIt(t *testing.T) {
	f := newFake(t)
	path := filepath.Join(t.TempDir(), "secret")
	code, out, errw := run(f, "webhooks", "create", "--name", "m", "--url", "https://hooks.example/dartnode", "--events", "*", "--secret-out", path, "--yes")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errw)
	}
	if strings.Contains(out+errw, "whsec_shown_once_value") {
		t.Fatal("secret printed")
	}
	b, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(b)) != "whsec_shown_once_value" {
		t.Fatalf("secret file %q err %v", b, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	// A second create must not overwrite the only copy of the first secret.
	if code, _, _ := run(f, "webhooks", "create", "--name", "m", "--url", "https://hooks.example/dartnode", "--events", "*", "--secret-out", path, "--yes"); code == 0 {
		t.Fatal("existing secret file overwritten")
	}
}

func TestReadsWork(t *testing.T) {
	f := newFake(t)
	if code, out, errw := run(f, "billing", "balance"); code != 0 || !strings.Contains(out, "credit") || !strings.Contains(out, "11.69") {
		t.Fatalf("code %d out %q err %q", code, out, errw)
	}
}
