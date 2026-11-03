//go:build unix

package secretfile

import (
	"fmt"
	"os"
	"syscall"
)

// ownerOK refuses a secret file owned by anyone but the current user or root,
// so another user who can write to the directory cannot plant one.
func ownerOK(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Geteuid(); int(st.Uid) != uid && st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, not the current user (uid %d) or root", st.Uid, uid)
	}
	return nil
}
