package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Setting data aside inside the data volume (Docker).
//
// On a native host a rewind in place renames the data directory next to
// itself. In Docker that is impossible: up to PostgreSQL 17 the data
// directory is the volume's root (a mount point can't be renamed), and in
// the 18+ images it sits in /var/lib/postgresql/18, which belongs to root.
// Copying elsewhere would be neither instant nor free. So in docker-sidecar
// mode the data directory itself stays where it is, with its owner and mode
// (what the image's entrypoint checks), and its *entries* move, one rename
// each, inside the same volume:
//
//	<data>/.rowsafe-rewind/<base>.before-rewind-<UTC>/   kept for Undo
//	<data>/.rowsafe-rewind/<base>.after-rewind-<UTC>/    set aside by Undo
//	<data>/.rowsafe-rewind/<base>.failed-rewind-<UTC>/   a failed restore (rollback)
//	<data>/.rowsafe-rewind/restore-<rewind id>/          pgbackrest restores here first
//
// While the data directory holds nothing but .rowsafe-rewind, the
// entrypoint of the postgres images refuses to initialize a new cluster
// there (initdb: "directory exists but is not empty"), so a container
// started by someone else in the middle can't bury the data. pgBackRest's
// backups exclude .rowsafe-rewind (see writeConfig), and PostgreSQL ignores
// it.
//
// A rename of each entry is atomic, but moving all of them is not: the
// recorded phase says which side holds what after a crash (rollbackRewind,
// rollbackUndo).

// asideDirName is the directory inside the data directory that holds data
// set aside in contents layout.
const asideDirName = ".rowsafe-rewind"

// contentsLayout reports whether rewinds in place move the data
// directory's entries (Docker) rather than the directory itself.
func (a *Agent) contentsLayout() bool { return a.cfg.Sidecar() }

// asideRootOf is where data is set aside for dataDir.
func asideRootOf(contents bool, dataDir string) string {
	if contents {
		return filepath.Join(dataDir, asideDirName)
	}
	return filepath.Dir(dataDir)
}

// inAsideRoot reports whether p lies in a contents-layout aside directory.
func inAsideRoot(p string) bool {
	return slices.Contains(strings.Split(filepath.Clean(p), string(filepath.Separator)), asideDirName)
}

// keptPath names a directory set aside for dataDir: kind is before, after
// or failed.
func keptPath(contents bool, dataDir, kind string) string {
	return filepath.Join(asideRootOf(contents, dataDir), filepath.Base(dataDir)+"."+kind+"-rewind-"+stampNow())
}

// stagingDir is where a contents-layout rewind restores before moving the
// restored entries into the data directory.
func stagingDir(dataDir, rewindID string) string {
	return filepath.Join(dataDir, asideDirName, "restore-"+rewindID)
}

// dataPresent reports whether the data directory holds data: it exists
// (native), or has entries besides .rowsafe-rewind (contents layout).
func dataPresent(contents bool, dataDir string) bool {
	if !contents {
		return exists(dataDir)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() != asideDirName })
}

// phaseBefore reports whether phase p comes before ref.
func phaseBefore(p, ref string) bool {
	order := []string{phasePreflight, phaseStopped, phaseMoved, phaseRestored, phaseRecovering, phaseStarted, phaseDone}
	return slices.Index(order, p) < slices.Index(order, ref)
}

// checkDataDirFor checks what a rewind in place needs of the data
// directory in either layout.
func checkDataDirFor(contents bool, dataDir string) (os.FileInfo, error) {
	if !contents {
		return checkDataDir(dataDir)
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || dataDir == "/" {
		return nil, fmt.Errorf("unexpected data directory %q", dataDir)
	}
	info, err := os.Lstat(dataDir)
	if err != nil {
		return nil, fmt.Errorf("PostgreSQL's data directory %s is not visible in the agent container (%v): mount the data volume "+
			"at the same path in both containers", dataDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("the data directory %s is not a plain directory; Rowsafe can't rewind it in place (restore a copy instead)", dataDir)
	}
	if fileUID(info) != os.Getuid() {
		return nil, fmt.Errorf("the data directory %s isn't owned by the agent's user (uid %d), so Rowsafe can't swap its data", dataDir, os.Getuid())
	}
	if !writable(dataDir) {
		return nil, fmt.Errorf("the PostgreSQL data volume is mounted read-only in the agent container, and rewinding the whole database "+
			"writes to it: in the rowsafe-agent service, mount it without \":ro\" (e.g. `- pgdata:%s`) and recreate the agent container "+
			"(or restore a copy and bring back rows instead)", volumeMountHint(dataDir))
	}
	if err := ensureAsideRoot(dataDir); err != nil {
		return nil, err
	}
	return info, nil
}

// volumeMountHint is where the postgres images mount the data volume.
func volumeMountHint(dataDir string) string {
	if parts := strings.Split(dataDir, "/"); len(parts) == 6 && strings.HasPrefix(dataDir, "/var/lib/postgresql/") && parts[5] == "docker" {
		return "/var/lib/postgresql" // 18+: /var/lib/postgresql/18/docker
	}
	return dataDir
}

// ensureAsideRoot creates <data>/.rowsafe-rewind (0700), or checks the one
// there is a real directory of the agent's.
func ensureAsideRoot(dataDir string) error {
	root := filepath.Join(dataDir, asideDirName)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return fmt.Errorf("Rowsafe can't write in the data directory %s: %w", dataDir, err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != os.Getuid() {
		return fmt.Errorf("%s is not a directory Rowsafe made; refusing to use it", root)
	}
	return nil
}

// removeEmptyAsideRoot removes <data>/.rowsafe-rewind once nothing is kept.
func removeEmptyAsideRoot(dataDir string) {
	_ = syscall.Rmdir(filepath.Join(dataDir, asideDirName)) // fails unless empty
}

// moveData moves src to dst: a rename, or in contents layout every entry of
// src into dst (dst created if missing, merged into otherwise; an entry
// present on both sides is an error, never overwritten). src, when it
// isn't the data directory, is removed once empty. Moving out of the data
// directory leaves .rowsafe-rewind where it is.
func moveData(contents bool, dataDir, src, dst string) error {
	if !contents {
		return os.Rename(src, dst)
	}
	if err := ensureAsideRoot(dataDir); err != nil {
		return err
	}
	sinfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !sinfo.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dst, sinfo.Mode().Perm()); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if src == dataDir && e.Name() == asideDirName {
			continue
		}
		to := filepath.Join(dst, e.Name())
		if _, err := os.Lstat(to); err == nil {
			return fmt.Errorf("both %s and %s have %s; Rowsafe won't overwrite either", src, dst, e.Name())
		}
		if err := os.Rename(filepath.Join(src, e.Name()), to); err != nil {
			if errors.Is(err, syscall.EXDEV) {
				return fmt.Errorf("%w: %s and %s are on different filesystems", err, src, dst)
			}
			return err
		}
	}
	if src != dataDir {
		return os.Remove(src)
	}
	return nil
}

// retargetRestore points the recovery settings pgBackRest wrote for a
// restore into staging (restore_command carries --pg1-path=<staging>) at
// the data directory the restored files were moved to.
func retargetRestore(dataDir, staging string) error {
	path := filepath.Join(dataDir, "postgresql.auto.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fixed := strings.ReplaceAll(string(data), "--pg1-path="+staging, "--pg1-path="+dataDir)
	if fixed == string(data) {
		return nil
	}
	return writeFileAtomic(path, []byte(fixed), 0o600)
}

// freshDir creates dir empty (0700), removing a leftover of an earlier
// attempt; dir must be a Rowsafe staging directory.
func freshDir(dir string) error {
	if !inAsideRoot(dir) || !strings.HasPrefix(filepath.Base(dir), "restore-") {
		return fmt.Errorf("refusing to recreate %s", dir)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.Mkdir(dir, 0o700)
}

// isAsidePath reports whether p is a directory of the given kind set aside
// for dataDir, in either layout.
func isAsidePath(dataDir, p, kind string) bool {
	d := filepath.Dir(p)
	return strings.HasPrefix(filepath.Base(p), filepath.Base(dataDir)+"."+kind+"-rewind-") &&
		(d == filepath.Dir(dataDir) || d == filepath.Join(dataDir, asideDirName))
}

// stopper names what stops and starts PostgreSQL, for task logs.
func (a *Agent) stopper() string {
	if a.cfg.Sidecar() {
		return "the container control service"
	}
	return "the root helper"
}

// backupExclude: in contents layout, data kept aside by a rewind sits
// inside the data directory and must never go into backups.
func (a *Agent) backupExclude() []string {
	if a.contentsLayout() {
		return []string{asideDirName}
	}
	return nil
}
