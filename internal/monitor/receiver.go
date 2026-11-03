package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/afterdarksys/dnctl/internal/webhook"
)

// Receiver is the HTTP handler DartNode delivers webhooks to.
//
// Threats: refuses unsigned, tampered, stale, oversized or malformed
// deliveries with no detail in the response; dedupes on the event ID so a
// replay inside the signature window alerts once; stores before answering so
// a crash after 2xx does not lose the event. It does NOT protect against a
// leaked webhook secret (rotate it) or against floods of valid-looking junk
// from a network peer (put it behind a rate-limiting proxy).
type Receiver struct {
	Path      string
	Secrets   [][]byte
	Store     *Store
	Notify    chan<- struct{} // wakes the inbox worker; may be nil
	Now       func() time.Time
	Tolerance time.Duration
	Log       func(format string, args ...any)
}

func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path != rc.Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webhook.MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := rc.Now()
	if err := webhook.Verify(rc.Secrets, r.Header.Get("X-DartNode-Timestamp"), r.Header.Get("X-DartNode-Signature"), body, now, rc.Tolerance); err != nil {
		rc.Log("webhook refused: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil || !eventIDPattern.MatchString(e.ID) || e.Type == "" || len(e.Type) > 64 {
		rc.Log("webhook refused: malformed event body")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if h := r.Header.Get("X-DartNode-Event"); h != "" && h != e.Type {
		rc.Log("webhook refused: event header %q does not match body type %q", clip(h, 64), clip(e.Type, 64))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fresh, err := rc.Store.Accept(e, body, now)
	if err != nil {
		// Failing here makes DartNode retry, which is right: nothing was stored.
		rc.Log("webhook store failed: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if fresh && rc.Notify != nil {
		select {
		case rc.Notify <- struct{}{}:
		default:
		}
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

// DrainInbox alerts every stored event and removes it once a sink accepted it.
// An event whose alert fails stays in the inbox for the next pass.
func DrainInbox(ctx context.Context, st *Store, d *Dispatcher, now time.Time) error {
	paths, err := st.Pending()
	if err != nil {
		return err
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			d.Log("dropping unreadable inbox file %s", p)
			if err := st.Done(p); err != nil {
				return err
			}
			continue
		}
		if err := d.Send(ctx, AlertForEvent(e, now)); err != nil {
			return err
		}
		if err := st.Done(p); err != nil {
			return err
		}
	}
	return nil
}
