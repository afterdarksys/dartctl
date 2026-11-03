package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/dnctl/internal/api"
	"github.com/afterdarksys/dnctl/internal/secretfile"
	"github.com/afterdarksys/dnctl/internal/webhook"
)

// Config is the monitor's JSON configuration. Secrets are file paths only.
type Config struct {
	APIBase   string `json:"api_base,omitempty"`
	TokenFile string `json:"token_file"`
	StateDir  string `json:"state_dir"`
	Interval  string `json:"interval,omitempty"` // reconcile period, default 15m

	Listen             string `json:"listen,omitempty"`               // receiver address, e.g. 127.0.0.1:8787
	Path               string `json:"path,omitempty"`                 // receiver path, default /dartnode/webhook
	SecretFile         string `json:"secret_file,omitempty"`          // current webhook secret
	PreviousSecretFile string `json:"previous_secret_file,omitempty"` // accepted during rotation

	Expect Expect       `json:"expect"`
	Sinks  []SinkConfig `json:"sinks"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.TokenFile == "" || c.StateDir == "" {
		return nil, errors.New("config needs token_file and state_dir")
	}
	if c.Path == "" {
		c.Path = "/dartnode/webhook"
	}
	if !strings.HasPrefix(c.Path, "/") || c.Path == "/healthz" {
		return nil, errors.New("path must start with / and not be /healthz")
	}
	if c.Listen != "" && c.SecretFile == "" {
		return nil, errors.New("listen needs secret_file: the receiver never runs without signature checks")
	}
	if _, err := c.interval(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) interval() (time.Duration, error) {
	if c.Interval == "" {
		return 15 * time.Minute, nil
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil || d < time.Minute {
		return 0, errors.New("interval must be a duration of at least 1m")
	}
	return d, nil
}

func (c *Config) Client() (*api.Client, error) {
	tok, err := secretfile.Read(c.TokenFile)
	if err != nil {
		return nil, err
	}
	return api.New(c.APIBase, tok)
}

func (c *Config) secrets() ([][]byte, error) {
	var out [][]byte
	for i, p := range []string{c.SecretFile, c.PreviousSecretFile} {
		if p == "" {
			continue
		}
		s, err := secretfile.Read(p)
		if err != nil {
			if i == 1 && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, []byte(s))
	}
	if len(out) == 0 {
		return nil, errors.New("no webhook secret")
	}
	return out, nil
}

// CheckOnce runs one reconcile pass, sends transitions, and returns the open
// findings. It is what `dnctl monitor check` and the serve loop both use.
func CheckOnce(ctx context.Context, c *Config, d *Dispatcher, st *Store, now time.Time) ([]Alert, error) {
	client, err := c.Client()
	if err != nil {
		return nil, err
	}
	current, unevaluated := Reconcile(ctx, client, c.Expect, now)
	// A pass cut short by shutdown says nothing about the account: never turn
	// "cancelled" into findings or alerts.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prev, err := st.Findings()
	if err != nil {
		return nil, err
	}
	send, next := Transition(prev, current, unevaluated, now)
	for _, a := range send {
		if err := d.Send(ctx, a); err != nil {
			// Keep the previous state so the next pass retries this alert.
			return current, fmt.Errorf("alert delivery failed: %w", err)
		}
	}
	return current, st.SaveFindings(next)
}

// Serve runs the webhook receiver (when configured) and the reconcile loop
// until ctx is cancelled.
func Serve(ctx context.Context, c *Config, d *Dispatcher, logf func(string, ...any)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := OpenStore(c.StateDir)
	if err != nil {
		return err
	}
	defer st.Close()
	every, _ := c.interval()
	wake := make(chan struct{}, 1)
	errc := make(chan error, 1)

	if c.Listen != "" {
		secrets, err := c.secrets()
		if err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		if ip := net.ParseIP(host); host == "" || (ip != nil && !ip.IsLoopback()) {
			logf("note: receiver listens on %s; terminate TLS in front of it (DartNode delivers to https only)", c.Listen)
		}
		srv := &http.Server{
			Addr:              c.Listen,
			Handler:           &Receiver{Path: c.Path, Secrets: secrets, Store: st, Notify: wake, Now: time.Now, Tolerance: webhook.DefaultTolerance, Log: logf},
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		// Bind before starting anything else, so a port conflict fails the
		// process (and systemd restarts it) instead of running without a receiver.
		ln, err := net.Listen("tcp", c.Listen)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		go func() {
			logf("receiver listening on %s%s", c.Listen, c.Path)
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
				cancel()
			}
		}()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(sctx)
		}()
	}

	var wg sync.WaitGroup
	// The inbox worker runs on its own so a slow reconcile pass never delays
	// a webhook alert.
	wg.Add(1)
	go func() {
		defer wg.Done()
		retry := time.NewTicker(time.Minute)
		defer retry.Stop()
		for {
			if err := DrainInbox(ctx, st, d, time.Now()); err != nil && ctx.Err() == nil {
				logf("inbox: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-retry.C:
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			open, err := CheckOnce(ctx, c, d, st, time.Now())
			switch {
			case ctx.Err() != nil:
				return
			case err != nil:
				logf("reconcile: %v", err)
			default:
				logf("reconcile: %d open finding(s)", len(open))
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	<-ctx.Done()
	cancel()
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}
