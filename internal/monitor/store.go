package monitor

import (
	"crypto/sha256"
	"encoding/hex"
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
//	inbox/<sha256 of event id>.json  verified deliveries not yet alerted
//	inbox/failed/                    deliveries no sink accepted for a day
//	seen.json                        event IDs already accepted (dedupe)
//	findings.json                    reconciler conditions currently open
//	.lock                            held by the one process using the store
//
// Inbox files are named by hash so event IDs that differ only in case stay
// distinct on case-insensitive filesystems.
type Store struct {
	dir  string
	mu   sync.Mutex
	lock *os.File
}

const (
	seenRetention = 14 * 24 * time.Hour
	// QuarantineAfter moves an event no sink would accept out of the inbox, so
	// one bad event cannot block the rest forever.
	QuarantineAfter = 24 * time.Hour
)

// OpenStore creates or opens dir. It refuses an existing directory owned by
// another user (a mistyped state_dir must not chmod a system directory) and
// takes an exclusive lock, so two dnctl processes never share one store.
func OpenStore(dir string) (*Store, error) {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("state_dir %s is not a directory", dir)
		}
		if err := ownedByMe(info); err != nil {
			return nil, fmt.Errorf("state_dir %s: %w", dir, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "inbox", "failed"), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("state_dir %s is in use by another dnctl process (%v)", dir, err)
	}
	return &Store{dir: dir, lock: lock}, nil
}

// Close releases the store lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
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

func (s *Store) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, name), b)
}

// atomicWrite replaces path with b and syncs both the file and its directory,
// so the write survives a crash once this returns.
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func inboxName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:]) + ".json"
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
	path := filepath.Join(s.dir, "inbox", inboxName(e.ID))
	if err := atomicWrite(path, raw); err != nil {
		return false, err
	}
	// The file time records when the event was accepted; quarantine uses it.
	if err := os.Chtimes(path, now, now); err != nil {
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

// PendingItem is one inbox file awaiting delivery.
type PendingItem struct {
	Path     string
	Accepted time.Time
}

// Pending lists inbox events oldest first.
func (s *Store) Pending() ([]PendingItem, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "inbox"))
	if err != nil {
		return nil, err
	}
	var items []PendingItem
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, PendingItem{filepath.Join(s.dir, "inbox", e.Name()), info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Accepted.Before(items[j].Accepted) })
	return items, nil
}

func (s *Store) Done(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Quarantine moves an undeliverable inbox file to inbox/failed.
func (s *Store) Quarantine(path string) error {
	target := filepath.Join(s.dir, "inbox", "failed", filepath.Base(path))
	if err := os.Rename(path, target); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Finding is an open reconciler condition keyed by Alert.Key.
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
