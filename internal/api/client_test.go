package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "dnt_test_token_abcdef123456"

func newTest(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/v1", testToken)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(time.Duration) {}
	return c
}

func TestNewRejects(t *testing.T) {
	for _, base := range []string{"http://api.dartnode.net/v1", "https://user:pw@api.dartnode.net/v1", "https://api.dartnode.net/v1?x=1", "ftp://x"} {
		if _, err := New(base, testToken); err == nil {
			t.Errorf("base %q accepted", base)
		}
	}
	for _, tok := range []string{"", "abc", "xyz_not_a_dartnode_token", "dnt_" + strings.Repeat("a", 600), "dnt_abc def ghijk"} {
		if _, err := New("", tok); err == nil {
			t.Errorf("token %q accepted", tok)
		}
	}
}

func TestBearerAndEnvelope(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"success":true,"data":{"balance":-11.69,"currency":"USD"}}`)
	})
	b, err := c.Balance(context.Background())
	if err != nil || b.Balance != -11.69 {
		t.Fatalf("balance %+v err %v", b, err)
	}
}

func TestSuccessFalseIsError(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":false,"message":"partial failure"}`)
	})
	if _, err := c.Balance(context.Background()); err == nil || !strings.Contains(err.Error(), "partial failure") {
		t.Fatalf("got %v", err)
	}
}

func TestMissingSuccessIsError(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"data":{}}`) })
	if _, err := c.Balance(context.Background()); err == nil {
		t.Fatal("response without success accepted")
	}
}

func TestErrorNeverContainsToken(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"message":"Token lacks the required scope"}`)
	})
	_, err := c.Balance(context.Background())
	if !IsStatus(err, 403) || strings.Contains(err.Error(), testToken) {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	})
	if _, err := c.Balance(context.Background()); err == nil {
		t.Fatal("redirect followed")
	}
}

func TestOversizedResponseRefused(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"data":"`))
		w.Write([]byte(strings.Repeat("a", MaxResponse)))
		w.Write([]byte(`"}`))
	})
	if _, err := c.Balance(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v", err)
	}
}

func TestRateLimitRetriesGETOnly(t *testing.T) {
	gets, posts := 0, 0
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			if gets < 3 {
				w.WriteHeader(429)
				fmt.Fprint(w, `{"success":false,"message":"Rate limit exceeded"}`)
				return
			}
			fmt.Fprint(w, `{"success":true,"data":{"balance":0}}`)
			return
		}
		posts++
		w.WriteHeader(429)
		fmt.Fprint(w, `{"success":false}`)
	})
	if _, err := c.Balance(context.Background()); err != nil || gets != 3 {
		t.Fatalf("gets=%d err=%v", gets, err)
	}
	err := c.Do(context.Background(), http.MethodPost, "/compute/1/power", nil, map[string]string{"action": "reset"}, nil)
	if !IsStatus(err, 429) || posts != 1 {
		t.Fatalf("POST retried: posts=%d err=%v", posts, err)
	}
}

func TestListAllPaginates(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") != "100" {
			t.Errorf("per_page %q", r.URL.Query().Get("per_page"))
		}
		switch r.URL.Query().Get("page") {
		case "1":
			fmt.Fprint(w, `{"success":true,"data":{"services":[{"id":1,"hostname":"a"}],"pagination":{"page":1,"total_pages":2}}}`)
		case "2":
			fmt.Fprint(w, `{"success":true,"data":{"services":[{"id":2,"hostname":"b"}],"pagination":{"page":2,"total_pages":2}}}`)
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})
	got, err := c.Instances(context.Background(), "")
	if err != nil || len(got) != 2 || got[1].Hostname != "b" {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestInvalidPathRefused(t *testing.T) {
	c := newTest(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request sent") })
	for _, p := range []string{"compute", "/compute/../account", "/compute?x=1"} {
		if err := c.Do(context.Background(), http.MethodGet, p, nil, nil, nil); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
}

func TestWebhookDisabled(t *testing.T) {
	cases := map[string][2]bool{
		`{"id":1,"active":false}`:      {true, true},
		`{"id":1,"enabled":true}`:      {false, true},
		`{"id":1,"status":"disabled"}`: {true, true},
		`{"id":1}`:                     {false, false},
	}
	for raw, want := range cases {
		w, err := parseWebhook([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		d, k := WebhookDisabled(w)
		if d != want[0] || k != want[1] {
			t.Errorf("%s: got %v,%v want %v", raw, d, k, want)
		}
	}
}
