package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var eventIDPattern = regexp.MustCompile(`^evt_[A-Za-z0-9_-]{1,128}$`)

// Store keeps the monitor's durable state in a private directory:
//
//	inbox/<event id>.json  verified deliveries not yet alerted
//	seen.json              event IDs already accepted (dedupe), with time
//	findings.json          reconciler conditions currently open
type Store struct {
	dir string
	mu  sync.Mutex
}

const seenRetention = 14 * 24 * time.Hour

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "inbox"), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) readJSON(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSON replaces name atomically.
func (s *Store) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, name), b)
}

func atomicWrite(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Accept durably records a verified delivery. It returns false for an event ID
// already accepted, so a replayed or retried delivery alerts once.
func (s *Store) Accept(e Event, raw []byte, now time.Time) (bool, error) {
	if !eventIDPattern.MatchString(e.ID) {
		return false, fmt.Errorf("invalid event id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]time.Time{}
	if err := s.readJSON("seen.json", &seen); err != nil {
		return false, fmt.Errorf("read seen.json: %w", err)
	}
	if _, dup := seen[e.ID]; dup {
		return false, nil
	}
	// Inbox first: if the process dies after this, the event is still delivered.
	if err := atomicWrite(filepath.Join(s.dir, "inbox", e.ID+".json"), raw); err != nil {
		return false, err
	}
	for id, t := range seen {
		if now.Sub(t) > seenRetention {
			delete(seen, id)
		}
	}
	seen[e.ID] = now
	if err := s.writeJSON("seen.json", seen); err != nil {
		return false, err
	}
	return true, nil
}

// Pending lists inbox events oldest first.
func (s *Store) Pending() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "inbox"))
	if err != nil {
		return nil, err
	}
	type item struct {
		path string
		mod  time.Time
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{filepath.Join(s.dir, "inbox", e.Name()), info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.Before(items[j].mod) })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.path
	}
	return out, nil
}

func (s *Store) Done(path string) error { return os.Remove(path) }

// Findings are open reconciler conditions keyed by Alert.Key.
type Finding struct {
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Since    time.Time `json:"since"`
	Notified time.Time `json:"notified"`
}

func (s *Store) Findings() (map[string]Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := map[string]Finding{}
	return f, s.readJSON("findings.json", &f)
}

func (s *Store) SaveFindings(f map[string]Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeJSON("findings.json", f)
}
