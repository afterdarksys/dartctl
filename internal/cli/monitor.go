package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/afterdarksys/dnctl/internal/monitor"
	"github.com/afterdarksys/dnctl/internal/secretfile"
	"github.com/afterdarksys/dnctl/internal/webhook"
)

func (e *env) monitor(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("usage: dnctl monitor check|serve|test-alert|send-test")
	}
	f := newFlags("monitor")
	cfgPath := f.fs.String("config", "", "")
	secretFile := f.fs.String("secret-file", "", "")
	target := f.fs.String("url", "", "")
	event := f.fs.String("event", "service.power.reboot", "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	logf := func(format string, a ...any) {
		fmt.Fprintf(e.errw, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
	}
	if args[0] == "send-test" {
		return e.sendTest(ctx, *secretFile, *target, *event)
	}
	if *cfgPath == "" {
		return usagef("usage: dnctl monitor %s --config FILE", args[0])
	}
	cfg, err := monitor.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	d, err := monitor.NewDispatcher(cfg.Sinks)
	if err != nil {
		return err
	}
	d.Log = logf
	switch args[0] {
	case "check":
		st, err := monitor.OpenStore(cfg.StateDir)
		if err != nil {
			return err
		}
		open, err := monitor.CheckOnce(ctx, cfg, d, st, time.Now())
		if open == nil {
			open = []monitor.Alert{}
		}
		if e.jsonOut || len(open) > 0 {
			e.print(open, nil)
		} else if err == nil {
			fmt.Fprintln(e.out, "no open findings")
		}
		if err != nil {
			return err
		}
		for _, a := range open {
			if a.Severity == monitor.Critical {
				return exitError(3)
			}
		}
		return nil
	case "serve":
		return monitor.Serve(ctx, cfg, d, logf)
	case "test-alert":
		return d.Send(ctx, monitor.Alert{Key: "test", Severity: monitor.Critical, Level: "critical", Title: "dnctl test alert", Detail: "If you can read this, alert delivery works.", Source: "test", Time: time.Now()})
	}
	return usagef("usage: dnctl monitor check|serve|test-alert|send-test")
}

// sendTest posts a correctly signed sample delivery to a receiver, so an
// operator can prove the whole path before registering with DartNode.
func (e *env) sendTest(ctx context.Context, secretFile, target, event string) error {
	if secretFile == "" || target == "" {
		return usagef("usage: dnctl monitor send-test --secret-file FILE --url URL [--event TYPE]")
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
		return usagef("--url must be https (or http on loopback)")
	}
	secret, err := secretfile.Read(secretFile)
	if err != nil {
		return err
	}
	id := "evt_dnctltest" + strconv.FormatInt(time.Now().UnixNano(), 36)
	body := []byte(fmt.Sprintf(`{"id":%q,"type":%q,"created_at":%q,"data":{"hostname":"dnctl-test","service_id":0}}`, id, event, time.Now().UTC().Format(time.RFC3339)))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dnctl-send-test")
	req.Header.Set("X-DartNode-Event", event)
	req.Header.Set("X-DartNode-Timestamp", ts)
	req.Header.Set("X-DartNode-Signature", webhook.Header([]byte(secret), ts, body))
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	fmt.Fprintf(e.out, "receiver answered HTTP %d for %s (%s)\n", resp.StatusCode, id, event)
	if resp.StatusCode != 200 {
		return exitError(1)
	}
	return nil
}
