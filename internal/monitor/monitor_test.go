package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/dartctl/internal/api"
	"github.com/afterdarksys/dartctl/internal/webhook"
)

type memSink struct {
	got  []Alert
	fail bool
}

func (m *memSink) Name() string { return "mem" }
func (m *memSink) Send(_ context.Context, a Alert) error {
	if m.fail {
		return errors.New("down")
	}
	m.got = append(m.got, a)
	return nil
}

func newReceiver(t *testing.T, now time.Time) (*Receiver, *Store, []byte) {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("receiver-test-secret")
	return &Receiver{Path: "/hook", Secrets: [][]byte{secret}, Store: st, Now: func() time.Time { return now }, Tolerance: webhook.DefaultTolerance, Log: func(string, ...any) {}}, st, secret
}

func post(rc *Receiver, method, path string, body []byte, hdr map[string]string) int {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	rc.ServeHTTP(w, req)
	return w.Code
}

func signed(secret []byte, now time.Time, body []byte, event string) map[string]string {
	ts := strconv.FormatInt(now.Unix(), 10)
	return map[string]string{"X-DartNode-Timestamp": ts, "X-DartNode-Signature": webhook.Header(secret, ts, body), "X-DartNode-Event": event}
}

func TestReceiver(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rc, st, secret := newReceiver(t, now)
	body := []byte(`{"id":"evt_abc123","type":"service.suspended","data":{"hostname":"web-1","service_id":456}}`)

	if c := post(rc, http.MethodPost, "/hook", body, signed(secret, now, body, "service.suspended")); c != 200 {
		t.Fatalf("valid delivery: %d", c)
	}
	if c := post(rc, http.MethodPost, "/hook", body, signed(secret, now, body, "service.suspended")); c != 200 {
		t.Fatalf("duplicate delivery: %d", c)
	}
	if p, _ := st.Pending(); len(p) != 1 {
		t.Fatalf("duplicate stored twice: %d inbox files", len(p))
	}

	other := []byte(`{"id":"evt_def456","type":"invoice.paid","data":{}}`)
	tampered := bytes.Replace(body, []byte("suspended"), []byte("unsuspended"), 1)
	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
		hdr    map[string]string
		want   int
	}{
		{"wrong method", http.MethodGet, "/hook", nil, nil, 405},
		{"wrong path", http.MethodPost, "/other", other, signed(secret, now, other, "invoice.paid"), 404},
		{"unsigned", http.MethodPost, "/hook", other, nil, 401},
		{"wrong secret", http.MethodPost, "/hook", other, signed([]byte("nope"), now, other, "invoice.paid"), 401},
		{"tampered", http.MethodPost, "/hook", tampered, signed(secret, now, body, "service.suspended"), 401},
		{"stale", http.MethodPost, "/hook", other, signed(secret, now.Add(-10*time.Minute), other, "invoice.paid"), 401},
		{"event header mismatch", http.MethodPost, "/hook", other, signed(secret, now, other, "service.terminated"), 400},
		{"oversized", http.MethodPost, "/hook", make([]byte, webhook.MaxBody+10), nil, 413},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := post(rc, c.method, c.path, c.body, c.hdr); got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
	badID := []byte(`{"id":"../../etc/passwd","type":"invoice.paid"}`)
	if c := post(rc, http.MethodPost, "/hook", badID, signed(secret, now, badID, "invoice.paid")); c != 400 {
		t.Fatalf("path-like event id: %d", c)
	}
	if p, _ := st.Pending(); len(p) != 1 {
		t.Fatalf("refused deliveries were stored: %d", len(p))
	}
}

func TestDrainInboxKeepsEventWhenSinksFail(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rc, st, secret := newReceiver(t, now)
	body := []byte(`{"id":"evt_x1","type":"invoice.past_due","data":{"invoice_id":7}}`)
	post(rc, http.MethodPost, "/hook", body, signed(secret, now, body, "invoice.past_due"))

	down := &memSink{fail: true}
	d := &Dispatcher{Log: func(string, ...any) {}}
	d.Add(down, Info)
	if err := DrainInbox(context.Background(), st, d, now); err == nil {
		t.Fatal("drain reported success with every sink down")
	}
	if p, _ := st.Pending(); len(p) != 1 {
		t.Fatal("event dropped after failed delivery")
	}
	up := &memSink{}
	d = &Dispatcher{Log: func(string, ...any) {}}
	d.Add(up, Info)
	if err := DrainInbox(context.Background(), st, d, now); err != nil {
		t.Fatal(err)
	}
	if len(up.got) != 1 || up.got[0].Severity != Critical {
		t.Fatalf("got %+v", up.got)
	}
	if p, _ := st.Pending(); len(p) != 0 {
		t.Fatal("delivered event left in inbox")
	}
}

func TestDispatcherMinSeverity(t *testing.T) {
	crit := &memSink{}
	all := &memSink{}
	d := &Dispatcher{Log: func(string, ...any) {}}
	d.Add(crit, Critical)
	d.Add(all, Info)
	d.Send(context.Background(), Alert{Key: "a", Severity: Info})
	d.Send(context.Background(), Alert{Key: "b", Severity: Critical})
	if len(crit.got) != 1 || len(all.got) != 2 {
		t.Fatalf("crit=%d all=%d", len(crit.got), len(all.got))
	}
}

func TestTransition(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	a := Alert{Key: "host:x:power", Severity: Critical, Title: "x stopped"}
	send, state := Transition(nil, []Alert{a}, nil, t0)
	if len(send) != 1 {
		t.Fatalf("new finding not sent: %d", len(send))
	}
	send, state = Transition(state, []Alert{a}, nil, t0.Add(time.Hour))
	if len(send) != 0 {
		t.Fatalf("unchanged finding re-sent: %d", len(send))
	}
	send, state = Transition(state, []Alert{a}, nil, t0.Add(25*time.Hour))
	if len(send) != 1 {
		t.Fatal("no daily reminder for open critical")
	}
	send, state = Transition(state, nil, nil, t0.Add(26*time.Hour))
	if len(send) != 1 || !send[0].Resolved || len(state) != 0 {
		t.Fatalf("resolution not sent: %+v", send)
	}
}

func TestReconcile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/compute":
			fmt.Fprint(w, `{"success":true,"data":{"services":[
				{"id":1,"hostname":"web-1","status":"running","service_status":"active"},
				{"id":2,"hostname":"db-1","status":"stopped","service_status":"active"},
				{"id":3,"hostname":"surprise","status":"running","service_status":"active"}],
				"pagination":{"page":1,"total_pages":1}}}`)
		case "/v1/billing/invoices":
			fmt.Fprint(w, `{"success":true,"data":{"invoices":[
				{"id":10,"status":"paid","total":9.95},
				{"id":11,"status":"unpaid","total":19.9,"due_at":"2000-01-01T00:00:00+00:00"}],
				"pagination":{"page":1,"total_pages":1}}}`)
		case "/v1/billing/balance":
			fmt.Fprint(w, `{"success":true,"data":{"balance":-3.5,"currency":"USD"}}`)
		case "/v1/webhooks/9":
			fmt.Fprint(w, `{"success":true,"data":{"id":9,"active":false}}`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"success":false,"message":"not found"}`)
		}
	}))
	defer srv.Close()
	c, err := api.New(srv.URL+"/v1", "dnt_reconcile_test_token")
	if err != nil {
		t.Fatal(err)
	}
	min := 10.0
	got, _ := Reconcile(context.Background(), c, Expect{Hosts: []string{"web-1", "db-1", "gone-1"}, AlertNewHosts: true, MinCredit: &min, WebhookID: 9}, time.Now())
	keys := map[string]Severity{}
	for _, a := range got {
		keys[a.Key] = a.Severity
	}
	want := map[string]Severity{
		"host:db-1:power":          Critical,
		"host:gone-1:missing":      Critical,
		"host:surprise:unexpected": Warning,
		"invoice:11":               Critical,
		"balance:low":              Warning,
		"webhook:disabled":         Critical,
	}
	for k, sev := range want {
		if keys[k] != sev {
			t.Errorf("finding %s: got %v present=%v", k, keys[k], keys[k] == sev)
		}
		if _, ok := keys[k]; !ok {
			t.Errorf("missing finding %s", k)
		}
	}
	if _, ok := keys["host:web-1:power"]; ok || len(got) != len(want) {
		t.Errorf("unexpected findings: %v", keys)
	}
	for _, a := range got {
		if strings.Contains(a.Detail, "dnt_") {
			t.Fatal("token leaked into a finding")
		}
	}
}

func TestLoadConfigRefusesReceiverWithoutSecret(t *testing.T) {
	p := t.TempDir() + "/c.json"
	if err := atomicWrite(p, []byte(`{"token_file":"/x","state_dir":"/y","listen":"127.0.0.1:1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("receiver without secret accepted")
	}
	if err := atomicWrite(p, []byte(`{"token_file":"/x","state_dir":"/y","bogus":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestCheckOnceCancelledReportsNothing(t *testing.T) {
	dir := t.TempDir()
	tokPath := dir + "/tok"
	if err := atomicWrite(tokPath, []byte("dnt_cancel_test_token")); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, `{"success":true,"data":{}}`)
	}))
	defer srv.Close()
	st, _ := OpenStore(dir + "/state")
	sink := &memSink{}
	d := &Dispatcher{Log: func(string, ...any) {}}
	d.Add(sink, Info)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &Config{APIBase: srv.URL + "/v1", TokenFile: tokPath, StateDir: dir + "/state"}
	if _, err := CheckOnce(ctx, cfg, d, st, time.Now()); err == nil {
		t.Fatal("cancelled pass reported success")
	}
	if len(sink.got) != 0 {
		t.Fatalf("cancelled pass sent alerts: %+v", sink.got)
	}
	if f, _ := st.Findings(); len(f) != 0 {
		t.Fatalf("cancelled pass saved findings: %v", f)
	}
}

func TestServeReturnsWhenListenFails(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	dir := t.TempDir()
	atomicWrite(dir+"/tok", []byte("dnt_serve_test_token"))
	atomicWrite(dir+"/secret", []byte("s3cret"))
	cfg := &Config{TokenFile: dir + "/tok", StateDir: dir + "/state", Listen: busy.Addr().String(), Path: "/h", SecretFile: dir + "/secret", APIBase: "http://127.0.0.1:1/v1"}
	d := &Dispatcher{Log: func(string, ...any) {}}
	d.Add(&memSink{}, Info)
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), cfg, d, func(string, ...any) {}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve returned nil on a port conflict")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve kept running without a receiver")
	}
}

func TestOutageDoesNotResolveFindings(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	_, state := Transition(nil, []Alert{{Key: "host:web-1:missing", Severity: Critical, Title: "gone"}}, nil, t0)
	outage := []Alert{{Key: "api:compute", Severity: Critical, Title: "cannot list"}}
	send, state := Transition(state, outage, []string{"host:"}, t0.Add(time.Minute))
	for _, a := range send {
		if a.Resolved {
			t.Fatalf("outage reported %s resolved", a.Key)
		}
	}
	if _, ok := state["host:web-1:missing"]; !ok {
		t.Fatal("finding dropped during outage")
	}
}

type pickySink struct{ got []string }

func (p *pickySink) Name() string { return "picky" }
func (p *pickySink) Send(_ context.Context, a Alert) error {
	if strings.Contains(a.Title, "poison") {
		return errors.New("400 rejected")
	}
	p.got = append(p.got, a.Key)
	return nil
}

func TestPoisonEventDoesNotBlockInbox(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rc, st, secret := newReceiver(t, now)
	bad := []byte(`{"id":"evt_bad","type":"service.poison","data":{}}`)
	good := []byte(`{"id":"evt_good","type":"invoice.paid","data":{}}`)
	post(rc, http.MethodPost, "/hook", bad, signed(secret, now, bad, "service.poison"))
	post(rc, http.MethodPost, "/hook", good, signed(secret, now.Add(time.Second), good, "invoice.paid"))
	sink := &pickySink{}
	d := &Dispatcher{Log: func(string, ...any) {}}
	d.Add(sink, Info)
	if err := DrainInbox(context.Background(), st, d, now); err == nil {
		t.Fatal("failure not reported")
	}
	if len(sink.got) != 1 || sink.got[0] != "event:evt_good" {
		t.Fatalf("good event blocked behind poison: %v", sink.got)
	}
	// A day later the poison event is quarantined, not retried forever.
	DrainInbox(context.Background(), st, d, now.Add(QuarantineAfter+time.Hour))
	if p, _ := st.Pending(); len(p) != 0 {
		t.Fatalf("poison event still pending: %d", len(p))
	}
}

func TestStoreLockedAgainstSecondProcess(t *testing.T) {
	dir := t.TempDir() + "/state"
	a, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if b, err := OpenStore(dir); err == nil {
		b.Close()
		t.Fatal("second store opened on a locked state_dir")
	}
}

func TestReceiverStoreFailureIs503(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rc, st, secret := newReceiver(t, now)
	os.Chmod(st.dir+"/inbox", 0o500)
	defer os.Chmod(st.dir+"/inbox", 0o700)
	body := []byte(`{"id":"evt_ro","type":"invoice.paid","data":{}}`)
	if c := post(rc, http.MethodPost, "/hook", body, signed(secret, now, body, "invoice.paid")); c != 503 {
		t.Fatalf("store failure answered %d, want 503 so DartNode retries", c)
	}
}

func TestInboxIDsDifferingInCaseStayDistinct(t *testing.T) {
	if inboxName("evt_Abc") == inboxName("evt_abc") {
		t.Fatal("case-folded collision")
	}
}

func TestReconcileWebhookByURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/webhooks":
			fmt.Fprint(w, `{"success":true,"data":{"webhooks":[{"id":4,"url":"https://a.example/h","active":false},{"id":5,"url":"https://other.example/h","active":true}]}}`)
		default:
			fmt.Fprint(w, `{"success":true,"data":{"services":[],"invoices":[],"balance":0}}`)
		}
	}))
	defer srv.Close()
	c, _ := api.New(srv.URL+"/v1", "dnt_webhook_url_test_token")
	got, _ := Reconcile(context.Background(), c, Expect{WebhookURL: "https://a.example/h"}, time.Now())
	keys := map[string]bool{}
	for _, a := range got {
		keys[a.Key] = true
	}
	if !keys["webhook:4:disabled"] || keys["webhook:missing"] {
		t.Fatalf("got %v", keys)
	}
	got, _ = Reconcile(context.Background(), c, Expect{WebhookURL: "https://none.example/h"}, time.Now())
	keys = map[string]bool{}
	for _, a := range got {
		keys[a.Key] = true
	}
	if !keys["webhook:missing"] {
		t.Fatalf("missing webhook not reported: %v", keys)
	}
}
