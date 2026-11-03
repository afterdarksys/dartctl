package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/dartctl/internal/api"
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
		case r.Method == "GET" && (r.URL.Path == "/v1/compute/10003" || r.URL.Path == "/v1/compute/10003/config"):
			// 10003 is a real-world block storage service, not compute: DartNode
			// answers 200 success:false with no message.
			fmt.Fprint(w, `{"success":false}`)
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

func TestTokenFileBeatsEnvironment(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	os.WriteFile(p, []byte("dnt_from_file_0123456789"), 0o600)
	e := &env{tokenFile: p, getenv: func(k string) string {
		if k == "DARTNODE_TOKEN" {
			return "dnt_from_env_0123456789"
		}
		return ""
	}}
	if _, err := e.client(); err != nil {
		t.Fatal(err)
	}
	// The flag's file must be the one used: a bad file must fail even with a good env token.
	os.WriteFile(p, []byte("not-a-token"), 0o600)
	if _, err := e.client(); err == nil {
		t.Fatal("environment token silently replaced --token-file")
	}
}

func TestGlobalsStopAtCommand(t *testing.T) {
	e := &env{getenv: func(string) string { return "" }}
	rest, err := e.globals([]string{"--json", "webhooks", "update", "5", "--name", "version", "--api", "x", "--yes"})
	if err != nil || e.apiBase != "" || len(rest) != 8 || rest[0] != "webhooks" {
		t.Fatalf("rest=%v api=%q err=%v", rest, e.apiBase, err)
	}
}

func TestFindSecretStrict(t *testing.T) {
	cases := map[string]string{
		`{"secret":"plain"}`:                               "plain",
		`{"webhook":{"id":1,"secret":"plain"}}`:            "plain",
		`{"secret_hash":"abc","secret":"plain"}`:           "plain",
		`{"secret_hash":"abc"}`:                            "",
		`{"webhook":{"deliveries":[{"secret":"nested"}]}}`: "",
	}
	for raw, want := range cases {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		if got := findSecret(v); got != want {
			t.Errorf("%s: got %q want %q", raw, got, want)
		}
	}
}

func TestComputeGetNotFoundAsCompute(t *testing.T) {
	f := newFake(t)
	for _, args := range [][]string{
		{"compute", "get", "10003"},
		{"compute", "config", "10003"},
		{"power", "10003", "off", "--yes", "--confirm", "x"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, _, errw := run(f, args...)
			if code == 0 {
				t.Fatalf("command succeeded: %s", errw)
			}
			want := "instance 10003 was not found as a compute instance"
			if !strings.Contains(errw, want) {
				t.Fatalf("errw = %q, want substring %q", errw, want)
			}
		})
	}
}

func TestNotFoundAsCompute(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		changed bool
	}{
		{"200 generic success-false", &api.Error{Status: 200, Message: "request did not succeed"}, true},
		{"200 with a real message", &api.Error{Status: 200, Message: "disk is full"}, false},
		{"404", &api.Error{Status: 404, Message: "request did not succeed"}, false},
		{"non-API error", errors.New("boom"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := notFoundAsCompute(c.err, 42)
			if !c.changed {
				if got != c.err {
					t.Fatalf("error rewritten: %v", got)
				}
				return
			}
			want := "instance 42 was not found as a compute instance"
			if !strings.Contains(got.Error(), want) {
				t.Fatalf("got %q, want substring %q", got.Error(), want)
			}
		})
	}
}

func TestParseInvoiceItem(t *testing.T) {
	cases := []struct {
		desc      string
		wantID    int
		wantKind  string
		wantName  string
		wantAddon string
		wantOK    bool
	}{
		{
			desc:   "Service #10001 [VPS relay-a.example.net]",
			wantID: 10001, wantKind: "VPS", wantName: "relay-a.example.net", wantOK: true,
		},
		{
			desc:   "Service #10002 [VDS ns1.example.org]",
			wantID: 10002, wantKind: "VDS", wantName: "ns1.example.org", wantOK: true,
		},
		{
			desc:   "Service #10003 [Block Storage #7 (containers)]",
			wantID: 10003, wantKind: "Block Storage", wantName: "#7 (containers)", wantOK: true,
		},
		{
			desc:   "Addon backups [Service: #10001, VPS relay-a.example.net]",
			wantID: 10001, wantKind: "VPS", wantName: "relay-a.example.net", wantAddon: "backups", wantOK: true,
		},
		{
			desc:   "Service #10004 [Ryzen VPS builder1.example.com]",
			wantID: 10004, wantKind: "Ryzen VPS", wantName: "builder1.example.com", wantOK: true,
		},
		{desc: "", wantOK: false},
		{desc: "just some random invoice text", wantOK: false},
		{desc: "Service #123 no brackets at all", wantOK: false},
		{desc: "Service #abc [VPS x]", wantOK: false},
		{desc: "Service #123 []", wantOK: false},
		{desc: "Addon backups [Service: abc, VPS x]", wantOK: false},
		{desc: "Addon backups [Service: #123]", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			id, kind, name, addon, ok := parseInvoiceItem(c.desc)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if id != c.wantID || kind != c.wantKind || name != c.wantName || addon != c.wantAddon {
				t.Fatalf("got (%d, %q, %q, %q), want (%d, %q, %q, %q)", id, kind, name, addon, c.wantID, c.wantKind, c.wantName, c.wantAddon)
			}
		})
	}
}

func TestBillingServices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+tok {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"success":false,"message":"bad token"}`)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/billing/invoices" && r.URL.Query().Get("page") == "1":
			fmt.Fprint(w, `{"success":true,"data":{"invoices":[
				{"id":1,"status":"paid","total":12.5,"created_at":"2026-10-01T00:00:00Z"},
				{"id":2,"status":"paid","total":30.0,"created_at":"2026-11-01T00:00:00Z"}
			],"pagination":{"page":1,"per_page":100,"total":2,"total_pages":1}}}`)
		case r.Method == "GET" && r.URL.Path == "/v1/billing/invoices/1":
			fmt.Fprint(w, `{"success":true,"data":{"items":[
				{"description":"Service #10001 [VPS relay-a.example.net]","amount":10,"quantity":1,"total":10},
				{"description":"Service #10003 [Block Storage #7 (containers)]","amount":2.5,"quantity":1,"total":2.5}
			]}}`)
		case r.Method == "GET" && r.URL.Path == "/v1/billing/invoices/2":
			fmt.Fprint(w, `{"success":true,"data":{"items":[
				{"description":"Service #10001 [VPS relay-a.example.net]","amount":10,"quantity":1,"total":10},
				{"description":"Addon backups [Service: #10001, VPS relay-a.example.net]","amount":5,"quantity":1,"total":5},
				{"description":"some unrelated line item","amount":1,"quantity":1,"total":1}
			]}}`)
		default:
			fmt.Fprint(w, `{"success":true,"data":{"ok":true}}`)
		}
	}))
	defer srv.Close()
	var out, errw bytes.Buffer
	e := &env{out: &out, errw: &errw, apiBase: srv.URL + "/v1", getenv: func(k string) string {
		if k == "DARTNODE_TOKEN" {
			return tok
		}
		return ""
	}}
	if err := e.billing(context.Background(), []string{"services"}); err != nil {
		t.Fatalf("billing services: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "10001") || !strings.Contains(got, "VPS") || !strings.Contains(got, "relay-a.example.net") {
		t.Fatalf("missing VPS service in output: %q", got)
	}
	if !strings.Contains(got, "backups") {
		t.Fatalf("missing addon in output: %q", got)
	}
	if !strings.Contains(got, "2026-11-01") {
		t.Fatalf("missing newest invoice date (10001 was on both invoices) in output: %q", got)
	}
	if !strings.Contains(got, "10003") || !strings.Contains(got, "Block Storage") || !strings.Contains(got, "#7 (containers)") {
		t.Fatalf("missing block storage service in output: %q", got)
	}
	if strings.Contains(got, "unrelated") {
		t.Fatalf("junk line leaked into output: %q", got)
	}
}

func TestSendTest(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "s")
	os.WriteFile(p, []byte("secret"), 0o600)
	e := &env{out: io.Discard, errw: io.Discard, getenv: func(string) string { return "" }}
	if err := e.sendTest(context.Background(), p, srv.URL+"/h", "service.power.reboot"); err != nil {
		t.Fatalf("send-test: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil || v["type"] != "service.power.reboot" {
		t.Fatalf("body %q: %v", got, err)
	}
	for _, bad := range []string{"", "weird\x01type", `a"b.c`, "noDot", "UPPER.case"} {
		if err := e.sendTest(context.Background(), p, srv.URL+"/h", bad); err == nil {
			t.Errorf("event %q accepted", bad)
		}
	}
	if err := e.sendTest(context.Background(), p, "http://example.com/h", "service.power.reboot"); err == nil {
		t.Error("plain http to a non-loopback host accepted")
	}
}
