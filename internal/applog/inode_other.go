//go:build !unix

package applog

import (
	"io/fs"
	"os"
)

// inodeOf has no portable equivalent off unix, so rotation is detected by the
// file shrinking — which is what a copy-truncate rotation looks like.
func inodeOf(f *os.File) uint64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return inodeOfStat(st)
}

func inodeOfStat(st fs.FileInfo) uint64 { return uint64(st.Size()) }
