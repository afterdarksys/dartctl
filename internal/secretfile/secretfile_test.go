package secretfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRefusesOpenModes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(p, []byte("dnt_x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable file accepted: %v", err)
	}
	os.Chmod(p, 0o600)
	if v, err := Read(p); err != nil || v != "dnt_x" {
		t.Fatalf("got %q %v", v, err)
	}
}

func TestReadRefusesEmptyOversizedAndDirectories(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte(" \n"), 0o600)
	big := filepath.Join(dir, "big")
	os.WriteFile(big, make([]byte, MaxSize+1), 0o600)
	os.Chmod(dir, 0o700)
	for _, p := range []string{empty, big, dir, filepath.Join(dir, "missing")} {
		if _, err := Read(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func TestWriteNewNeverOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := WriteNew(p, "first"); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(p, "second"); err == nil {
		t.Fatal("overwrote existing secret")
	}
	if v, _ := Read(p); v != "first" {
		t.Fatalf("got %q", v)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if err := WriteNew(filepath.Join(t.TempDir(), "e"), ""); err == nil {
		t.Fatal("empty secret written")
	}
}
