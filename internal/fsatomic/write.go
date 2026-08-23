// Package fsatomic writes files atomically.
package fsatomic

import (
	"os"
	"path/filepath"
)

// WriteFile writes data to path atomically: it writes a temporary file in the
// same directory and renames it into place. A crash mid-write therefore leaves
// either the old file or the new one, never a truncated mix. Persisted ratchet
// state depends on this -- a half-written session file is unrecoverable.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
