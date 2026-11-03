// Package webhook verifies DartNode webhook deliveries.
//
// DartNode signs each delivery as
//
//	X-DartNode-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>
//	X-DartNode-Timestamp: <unix seconds>
//
// Threats: protects against forged deliveries (no secret), tampered bodies,
// replays outside the timestamp window, oversized bodies and malformed
// headers; comparison is constant time. It does NOT detect a replay inside the
// window (callers must dedupe on the event ID), and it cannot help if the
// webhook secret itself leaks.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// MaxBody is the largest delivery body accepted.
const MaxBody = 64 * 1024

// DefaultTolerance is the replay window DartNode's own examples use.
const DefaultTolerance = 5 * time.Minute

var (
	ErrMissingHeader = errors.New("missing signature or timestamp header")
	ErrBadTimestamp  = errors.New("malformed timestamp")
	ErrStale         = errors.New("timestamp outside the accepted window")
	ErrBadSignature  = errors.New("signature does not match")
	ErrTooLarge      = errors.New("body too large")
	ErrNoSecret      = errors.New("no webhook secret configured")
)

// Verify checks one delivery against every accepted secret (current and, during
// rotation, previous). It returns nil only when a secret matches.
func Verify(secrets [][]byte, timestamp, signature string, body []byte, now time.Time, tolerance time.Duration) error {
	if len(secrets) == 0 {
		return ErrNoSecret
	}
	if timestamp == "" || signature == "" {
		return ErrMissingHeader
	}
	if len(body) > MaxBody {
		return ErrTooLarge
	}
	if len(timestamp) > 12 {
		return ErrBadTimestamp
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || ts <= 0 || strconv.FormatInt(ts, 10) != timestamp {
		return ErrBadTimestamp
	}
	skew := now.Sub(time.Unix(ts, 0))
	if skew < -tolerance || skew > tolerance {
		return ErrStale
	}
	hexSig, ok := strings.CutPrefix(signature, "v1=")
	if !ok || len(hexSig) != sha256.Size*2 {
		return ErrBadSignature
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return ErrBadSignature
	}
	valid := false
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		if hmac.Equal(got, Sign(secret, timestamp, body)) {
			valid = true
		}
	}
	if !valid {
		return ErrBadSignature
	}
	return nil
}

// Sign returns the raw HMAC for a delivery. It is exported for tests and for
// tools that replay fixtures against a local receiver.
func Sign(secret []byte, timestamp string, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return mac.Sum(nil)
}

// Header formats a signature header value.
func Header(secret []byte, timestamp string, body []byte) string {
	return "v1=" + hex.EncodeToString(Sign(secret, timestamp, body))
}
