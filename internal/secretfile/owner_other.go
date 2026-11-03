//go:build !unix

package secretfile

import "os"

func ownerOK(os.FileInfo) error { return nil }
