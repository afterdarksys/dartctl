package webhook

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixture() (secret []byte, ts string, body []byte, now time.Time) {
	now = time.Unix(1_800_000_000, 0)
	return []byte("whsec_test_secret_value"), strconv.FormatInt(now.Unix(), 10), []byte(`{"id":"evt_1","type":"invoice.paid"}`), now
}

func TestVerifyAcceptsValid(t *testing.T) {
	secret, ts, body, now := fixture()
	if err := Verify([][]byte{secret}, ts, Header(secret, ts, body), body, now, DefaultTolerance); err != nil {
		t.Fatalf("valid delivery refused: %v", err)
	}
}

func TestVerifyAcceptsPreviousSecretDuringRotation(t *testing.T) {
	secret, ts, body, now := fixture()
	if err := Verify([][]byte{[]byte("new-secret"), secret}, ts, Header(secret, ts, body), body, now, DefaultTolerance); err != nil {
		t.Fatalf("previous secret refused: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	secret, ts, body, now := fixture()
	good := Header(secret, ts, body)
	cases := []struct {
		name    string
		secrets [][]byte
		ts, sig string
		body    []byte
		now     time.Time
		want    error
	}{
		{"tampered body", [][]byte{secret}, ts, good, []byte(`{"id":"evt_1","type":"invoice.past_due"}`), now, ErrBadSignature},
		{"wrong secret", [][]byte{[]byte("other")}, ts, good, body, now, ErrBadSignature},
		{"no secrets", nil, ts, good, body, now, ErrNoSecret},
		{"empty secret only", [][]byte{{}}, ts, good, body, now, ErrBadSignature},
		{"stale", [][]byte{secret}, ts, good, body, now.Add(6 * time.Minute), ErrStale},
		{"future", [][]byte{secret}, ts, good, body, now.Add(-6 * time.Minute), ErrStale},
		{"timestamp swapped", [][]byte{secret}, strconv.FormatInt(now.Unix()+1, 10), good, body, now, ErrBadSignature},
		{"missing signature", [][]byte{secret}, ts, "", body, now, ErrMissingHeader},
		{"missing timestamp", [][]byte{secret}, "", good, body, now, ErrMissingHeader},
		{"non-numeric timestamp", [][]byte{secret}, "12ab", good, body, now, ErrBadTimestamp},
		{"padded timestamp", [][]byte{secret}, "0" + ts, good, body, now, ErrBadTimestamp},
		{"negative timestamp", [][]byte{secret}, "-5", good, body, now, ErrBadTimestamp},
		{"no version prefix", [][]byte{secret}, ts, strings.TrimPrefix(good, "v1="), body, now, ErrBadSignature},
		{"wrong version", [][]byte{secret}, ts, "v2=" + strings.TrimPrefix(good, "v1="), body, now, ErrBadSignature},
		{"truncated signature", [][]byte{secret}, ts, good[:20], body, now, ErrBadSignature},
		{"non-hex signature", [][]byte{secret}, ts, "v1=" + strings.Repeat("zz", 32), body, now, ErrBadSignature},
		{"oversized", [][]byte{secret}, ts, good, make([]byte, MaxBody+1), now, ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Verify(c.secrets, c.ts, c.sig, c.body, c.now, DefaultTolerance); err != c.want {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
