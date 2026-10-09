package meilisearch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// The agent runs the server's Meilisearch program for temporary instances
// (Proof, Rewind) and to read its version. It runs it only when root owns
// the program and every folder above it, none of them writable by anyone
// else (so no other user could have replaced it), and always with a
// minimal environment: never the agent's own (bucket keys, the backup
// passphrase).

// trustAnyProgram is true only in tests (programs in a temporary folder).
var trustAnyProgram = false

// minimalEnv is the environment for every program the agent runs here.
func minimalEnv() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
}

// trustedProgram resolves bin (symbolic links followed) and checks the
// program and its folders; it returns the real path, which is what runs.
func trustedProgram(bin string) (string, error) {
	if !filepath.IsAbs(bin) {
		return "", fmt.Errorf("%q isn't an absolute path", bin)
	}
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return "", fmt.Errorf("the Meilisearch program %s: %w", bin, err)
	}
	if trustAnyProgram {
		return real, nil
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("the Meilisearch program %s isn't a regular file", real)
	}
	// The program, then every folder up to /, for the link and its target.
	for _, start := range []string{real, filepath.Dir(bin)} {
		for p := start; ; p = filepath.Dir(p) {
			if err := rootOnly(p); err != nil {
				return "", fmt.Errorf("Rowsafe doesn't run the Meilisearch program %s: %w. Run the Rowsafe installer on the server "+
					"again, or make root its only owner", bin, err)
			}
			if p == "/" {
				break
			}
		}
	}
	return real, nil
}

// rootOnly: path (not followed) is root's and nobody else can write to it.
func rootOnly(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("can't read its owner")
	}
	if sys.Uid != 0 {
		return fmt.Errorf("%s isn't owned by root", path)
	}
	if st.Mode()&os.ModeSymlink == 0 && st.Mode().Perm()&0o022 != 0 {
		if st.IsDir() && st.Mode()&os.ModeSticky != 0 {
			return fmt.Errorf("%s is a shared folder (sticky, writable by others)", path)
		}
		return fmt.Errorf("%s can be changed by users other than root", path)
	}
	return nil
}
