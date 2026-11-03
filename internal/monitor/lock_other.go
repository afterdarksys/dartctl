//go:build !unix

package monitor

import "os"

// Non-Unix platforms get no cross-process lock or owner check; run a single
// dartctl process per state_dir there.
func lockFile(*os.File) error { return nil }

func ownedByMe(os.FileInfo) error { return nil }
