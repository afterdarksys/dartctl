// Package api is a small client for the DartNode REST API (v1).
//
// Threats: keeps the bearer token out of errors, logs and URLs; refuses
// plain-HTTP endpoints other than loopback (tests); bounds response size and
// request time; never retries a non-idempotent request. It does NOT limit what
// the token itself is allowed to do: scope tokens in the DartNode dashboard.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBase is DartNode's production API.
const DefaultBase = "https://api.dartnode.net/v1"

// MaxResponse bounds every response body.
const MaxResponse = 8 << 20

// Client calls the DartNode API with one service key or OAuth access token.
type Client struct {
	base       *url.URL
	token      string
	HTTP       *http.Client
	UserAgent  string
	MaxRetries int                 // retries for rate-limited idempotent requests
	MaxWait    time.Duration       // longest single rate-limit wait
	Sleep      func(time.Duration) // replaceable in tests
}

// Error is a DartNode error response. It never contains the token.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	switch {
	case e.Message != "":
		return fmt.Sprintf("DartNode API %d: %s", e.Status, e.Message)
	default:
		return fmt.Sprintf("DartNode API %d", e.Status)
	}
}

// IsStatus reports whether err is an API error with the given HTTP status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// New validates the base URL and token.
func New(base, token string) (*Client, error) {
	if base == "" {
		base = DefaultBase
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid API base URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("API base URL must not carry credentials, a query or a fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, errors.New("API base URL must use https")
	}
	token = strings.TrimSpace(token)
	if !validToken(token) {
		return nil, errors.New("token must be a DartNode service key (dnt_) or OAuth access token (dno_)")
	}
	return &Client{
		base:       u,
		token:      token,
		HTTP:       &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect},
		UserAgent:  "dnctl",
		MaxRetries: 3,
		MaxWait:    60 * time.Second,
		Sleep:      time.Sleep,
	}, nil
}

func validToken(t string) bool {
	if !(strings.HasPrefix(t, "dnt_") || strings.HasPrefix(t, "dno_")) || len(t) < 12 || len(t) > 512 {
		return false
	}
	for _, r := range t {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// A redirect would replay the Authorization header to another location.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errors.New("DartNode API redirect refused")
}

type envelope struct {
	Success *bool           `json:"success"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

// Do sends one request. path is relative to the base ("/compute"). When out is
// non-nil the response's data field is decoded into it.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
	}
	idempotent := method == http.MethodGet || method == http.MethodHead
	for attempt := 0; ; attempt++ {
		data, wait, err := c.once(ctx, method, path, query, payload)
		if err == nil {
			if out == nil || len(data) == 0 || string(data) == "null" {
				return nil
			}
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("decode %s %s response: %w", method, path, err)
			}
			return nil
		}
		if !IsStatus(err, http.StatusTooManyRequests) || !idempotent || attempt >= c.MaxRetries {
			return err
		}
		if wait > c.MaxWait {
			wait = c.MaxWait
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c.Sleep(wait)
	}
}

func (c *Client) once(ctx context.Context, method, path string, query url.Values, payload []byte) (json.RawMessage, time.Duration, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#") {
		return nil, 0, fmt.Errorf("invalid API path %q", path)
	}
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = query.Encode()
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return nil, 0, fmt.Errorf("%s %s: %w", method, path, uerr.Err)
		}
		return nil, 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read %s %s response: %w", method, path, err)
	}
	if len(raw) > MaxResponse {
		return nil, 0, fmt.Errorf("%s %s response exceeds %d bytes", method, path, MaxResponse)
	}
	var env envelope
	jsonErr := json.Unmarshal(raw, &env)
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, retryAfter(resp.Header, time.Now()), &Error{Status: resp.StatusCode, Message: safeMessage(env.Message)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, 0, &Error{Status: resp.StatusCode, Message: safeMessage(env.Message)}
	}
	if jsonErr != nil {
		return nil, 0, fmt.Errorf("%s %s: response is not JSON", method, path)
	}
	// DartNode documents that some 200 responses carry success=false.
	if env.Success == nil || !*env.Success {
		return nil, 0, &Error{Status: resp.StatusCode, Message: safeMessage(firstNonEmpty(env.Message, "request did not succeed"))}
	}
	return env.Data, 0, nil
}

func retryAfter(h http.Header, now time.Time) time.Duration {
	if reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		if d := time.Unix(reset, 0).Sub(now); d > 0 {
			return d + time.Second
		}
	}
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return 5 * time.Second
}

// safeMessage keeps server messages printable and short.
func safeMessage(m string) string {
	m = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, m)
	if len(m) > 300 {
		m = m[:300] + "..."
	}
	return strings.TrimSpace(m)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Pagination is the metadata DartNode returns on list endpoints.
type Pagination struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// ListAll fetches every page of a list endpoint and returns the raw items found
// under key (for example "services" or "invoices").
func (c *Client) ListAll(ctx context.Context, path, key string, query url.Values) ([]json.RawMessage, error) {
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("per_page", "100")
	var all []json.RawMessage
	for page := 1; page <= 1000; page++ {
		q.Set("page", strconv.Itoa(page))
		var data map[string]json.RawMessage
		if err := c.Do(ctx, http.MethodGet, path, q, nil, &data); err != nil {
			return nil, err
		}
		var items []json.RawMessage
		if raw, ok := data[key]; ok && len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, fmt.Errorf("decode %s: %w", key, err)
			}
		}
		all = append(all, items...)
		var p Pagination
		if raw, ok := data["pagination"]; ok {
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, fmt.Errorf("decode pagination: %w", err)
			}
		}
		if len(items) == 0 || p.TotalPages == 0 || page >= p.TotalPages {
			return all, nil
		}
	}
	return nil, errors.New("pagination did not terminate after 1000 pages")
}
