//go:build unix

package applog

import (
	"io/fs"
	"os"
	"syscall"
)

// inodeOf identifies an open file so rotation can be detected. A path that
// suddenly points at a different inode is a rotated log, not a truncated one,
// and the new file has to be read from its start.
func inodeOf(f *os.File) uint64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return inodeOfStat(st)
}

func inodeOfStat(st fs.FileInfo) uint64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	// No inode available: fall back to size, which at least notices a
	// truncation-style rotation.
	return uint64(st.Size())
}
