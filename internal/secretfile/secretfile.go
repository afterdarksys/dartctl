// Package secretfile reads and writes small secret files (API tokens, webhook
// secrets, sink credentials) with owner-only permissions.
//
// Threats: protects against secrets left readable by other local users and
// against a write silently replacing an existing secret. It does NOT protect
// against the file's owner or root reading the file, or against a secret
// copied elsewhere by the operator.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// MaxSize bounds every secret file read.
const MaxSize = 16 * 1024

// Read returns the trimmed contents of path. On Unix it refuses a file that
// group or other users can read or write, so a leaked mode fails closed.
func Read(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open secret file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is accessible by other users (mode %04o); run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	if err := ownerOK(info); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if info.Size() > MaxSize {
		return "", fmt.Errorf("%s is larger than %d bytes", path, MaxSize)
	}
	buf, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	if len(buf) > MaxSize {
		return "", fmt.Errorf("%s is larger than %d bytes", path, MaxSize)
	}
	value := strings.TrimSpace(string(buf))
	if value == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return value, nil
}

// WriteNew writes value to a new mode-0600 file. It refuses to overwrite an
// existing file, so a second registration cannot destroy the only copy of a
// secret that the provider shows once.
func WriteNew(path, value string) error {
	if value == "" {
		return errors.New("refusing to write an empty secret")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create secret file: %w", err)
	}
	// A half-written file would block a retry (O_EXCL), so remove it on failure.
	fail := func(what string, err error) error {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("%s secret file: %w", what, err)
	}
	if _, err := f.WriteString(value + "\n"); err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("close secret file: %w", err)
	}
	return nil
}
