package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/dnctl/internal/api"
	"github.com/afterdarksys/dnctl/internal/secretfile"
)

// Sink delivers alerts somewhere a human will see them.
type Sink interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// SinkConfig selects and configures one sink. Credentials (webhook URLs,
// tokens) always come from files, never from the config itself.
type SinkConfig struct {
	Type        string `json:"type"` // stdout, webhook, slack, discord, matrix
	URLFile     string `json:"url_file,omitempty"`
	Homeserver  string `json:"homeserver,omitempty"`
	RoomID      string `json:"room_id,omitempty"`
	TokenFile   string `json:"token_file,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
}

var sinkHTTP = &http.Client{
	Timeout:   10 * time.Second,
	Transport: api.Transport(),
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	},
}

func BuildSink(c SinkConfig) (Sink, Severity, error) {
	min, err := ParseSeverity(c.MinSeverity)
	if err != nil {
		return nil, 0, err
	}
	switch c.Type {
	case "stdout":
		return stdoutSink{}, min, nil
	case "webhook", "slack", "discord":
		raw, err := secretfile.Read(c.URLFile)
		if err != nil {
			return nil, 0, fmt.Errorf("%s sink: %w", c.Type, err)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, 0, fmt.Errorf("%s sink: url_file must hold an https URL", c.Type)
		}
		return postSink{kind: c.Type, url: u.String()}, min, nil
	case "matrix":
		hs, err := url.Parse(strings.TrimRight(c.Homeserver, "/"))
		if err != nil || hs.Scheme != "https" || hs.Host == "" || hs.Path != "" {
			return nil, 0, errors.New("matrix sink: homeserver must be an https base URL")
		}
		if !strings.HasPrefix(c.RoomID, "!") || !strings.Contains(c.RoomID, ":") || strings.ContainsAny(c.RoomID, "/?# ") {
			return nil, 0, errors.New("matrix sink: room_id must look like !room:server")
		}
		tok, err := secretfile.Read(c.TokenFile)
		if err != nil {
			return nil, 0, fmt.Errorf("matrix sink: %w", err)
		}
		return matrixSink{homeserver: hs.String(), room: c.RoomID, token: tok}, min, nil
	}
	return nil, 0, fmt.Errorf("unknown sink type %q", c.Type)
}

type stdoutSink struct{}

func (stdoutSink) Name() string { return "stdout" }
func (stdoutSink) Send(_ context.Context, a Alert) error {
	a.Level = a.Severity.String()
	return json.NewEncoder(os.Stdout).Encode(a)
}

// postSink covers generic JSON webhooks and Slack/Mattermost/Discord incoming
// webhooks. The URL is a credential, so errors never include it.
type postSink struct {
	kind string
	url  string
}

func (p postSink) Name() string { return p.kind }

func (p postSink) Send(ctx context.Context, a Alert) error {
	a.Level = a.Severity.String()
	var body any
	switch p.kind {
	case "slack":
		body = map[string]string{"text": a.Text()}
	case "discord":
		body = map[string]string{"content": clip(a.Text(), 1900)}
	default:
		body = a
	}
	return postJSON(ctx, http.MethodPost, p.url, "", body, p.kind)
}

type matrixSink struct {
	homeserver, room, token string
}

func (m matrixSink) Name() string { return "matrix" }

func (m matrixSink) Send(ctx context.Context, a Alert) error {
	// Same alert, same transaction ID: Matrix drops a retried duplicate.
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%t", a.Key, a.Time.UnixNano(), a.Resolved)))
	u := m.homeserver + "/_matrix/client/v3/rooms/" + url.PathEscape(m.room) + "/send/m.room.message/dnctl" + hex.EncodeToString(sum[:16])
	return postJSON(ctx, http.MethodPut, u, m.token, map[string]string{"msgtype": "m.notice", "body": a.Text()}, "matrix")
}

func postJSON(ctx context.Context, method, target, bearer string, body any, name string) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("%s sink: build request", name)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dnctl-monitor")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := sinkHTTP.Do(req)
	if err != nil {
		// url.Error embeds the URL, which may be a credential: drop it.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("%s sink: %v", name, uerr.Err)
		}
		return fmt.Errorf("%s sink: request failed", name)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s sink: HTTP %d", name, resp.StatusCode)
	}
	return nil
}

// Dispatcher fans an alert out to every sink whose minimum severity it meets.
type Dispatcher struct {
	sinks []Sink
	mins  []Severity
	Log   func(format string, args ...any)
}

func NewDispatcher(cfgs []SinkConfig) (*Dispatcher, error) {
	d := &Dispatcher{Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}
	for _, c := range cfgs {
		s, min, err := BuildSink(c)
		if err != nil {
			return nil, err
		}
		d.Add(s, min)
	}
	if len(d.sinks) == 0 {
		d.Add(stdoutSink{}, Info)
	}
	return d, nil
}

func (d *Dispatcher) Add(s Sink, min Severity) {
	d.sinks = append(d.sinks, s)
	d.mins = append(d.mins, min)
}

// Send returns an error only when no eligible sink accepted the alert.
func (d *Dispatcher) Send(ctx context.Context, a Alert) error {
	sent, eligible := 0, 0
	var last error
	for i, s := range d.sinks {
		if a.Severity < d.mins[i] {
			continue
		}
		eligible++
		if err := s.Send(ctx, a); err != nil {
			d.Log("alert %s via %s failed: %v", a.Key, s.Name(), err)
			last = err
			continue
		}
		sent++
	}
	if eligible > 0 && sent == 0 {
		return last
	}
	return nil
}
