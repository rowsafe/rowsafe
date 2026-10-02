package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restores without Rowsafe (`rowsafe-agent clickhouse download-backup`):
// a backup's files are sealed and their names encrypted in the bucket, so
// these decrypt both into an ordinary folder ClickHouse can RESTORE from.

// BackupInfo is one finished backup of a database's folder.
type BackupInfo struct {
	Label     string
	Type      string // protocol.BackupFull or BackupDiff
	Base      string // the full backup a differential one needs
	Mark      string
	StoppedAt time.Time
	DataBytes int64
}

// Backups lists the finished backups in the folder of stanza, oldest
// first.
func Backups(ctx context.Context, env agent.EngineEnv, stanza string) ([]BackupInfo, error) {
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return nil, err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BackupInfo, 0, len(docs))
	for _, d := range docs {
		out = append(out, BackupInfo{Label: d.Label, Type: d.Type, Base: d.Base, Mark: d.Mark, StoppedAt: d.StoppedAt, DataBytes: d.DataBytes})
	}
	return out, nil
}

// DownloadBackup decrypts backup label of stanza into dir/<label>/ and, for
// a differential backup, its full backup into dir/<base>/. It returns the
// folders written, the full backup first. dir must be empty or missing.
// Run as root, it gives what it writes to the clickhouse user (when there
// is one), so ClickHouse can restore from it.
func DownloadBackup(ctx context.Context, env agent.EngineEnv, stanza, label, dir string, progress io.Writer) ([]string, error) {
	if !validLabel(label) {
		return nil, fmt.Errorf("%q isn't a backup label (like 20260925-101500F)", label)
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err == nil && len(ents) > 0 {
		return nil, fmt.Errorf("%s isn't empty", dir)
	}
	created := errors.Is(err, os.ErrNotExist)
	var d backupDoc
	if err := r.getJSON(ctx, backupKey(label, backupDocName), &d); err != nil {
		var se *objstore.S3Error
		if errors.As(err, &se) && se.Status == 404 {
			return nil, fmt.Errorf("there is no finished backup %s in this folder", label)
		}
		return nil, fmt.Errorf("reading backup %s: %w", label, err)
	}
	labels := []string{label}
	if d.Base != "" {
		labels = []string{d.Base, label}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	var dirs []string
	for _, l := range labels {
		out := filepath.Join(dir, l)
		if err := r.downloadOne(ctx, l, out, progress); err != nil {
			return nil, err
		}
		dirs = append(dirs, out)
	}
	if os.Geteuid() == 0 {
		owned := dirs
		if created {
			owned = []string{dir}
		}
		if who, err := giveToClickHouse(owned); err != nil {
			return dirs, fmt.Errorf("giving the files to the clickhouse user: %w", err)
		} else if who != "" {
			fmt.Fprintf(progress, "the files belong to %s, so ClickHouse can read them\n", who)
		}
	}
	return dirs, nil
}

// giveToClickHouse makes the clickhouse user (and group) own roots and
// everything in them; it returns "user:group", or "" when there is no
// clickhouse user.
func giveToClickHouse(roots []string) (string, error) {
	u, err := user.Lookup("clickhouse")
	if err != nil {
		return "", nil
	}
	gid := u.Gid
	if g, err := user.LookupGroup("clickhouse"); err == nil {
		gid = g.Gid
	}
	uid, err1 := strconv.Atoi(u.Uid)
	g, err2 := strconv.Atoi(gid)
	if err1 != nil || err2 != nil {
		return "", nil
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, g)
		})
		if err != nil {
			return "", err
		}
	}
	group := "clickhouse"
	if gr, err := user.LookupGroupId(gid); err == nil {
		group = gr.Name
	}
	return "clickhouse:" + group, nil
}

func (r *repo) downloadOne(ctx context.Context, label, out string, progress io.Writer) error {
	folder := backupDir(label)
	objs, err := r.st.List(ctx, folder)
	if err != nil {
		return err
	}
	var files, skipped int
	var bytes int64
	for _, o := range objs {
		if o.Key == backupKey(label, backupDocName) {
			continue // the agent's own description, not ClickHouse's
		}
		plain, err := s3gw.PlainName(r.pass, folder, o.Key)
		if errors.Is(err, s3gw.ErrNotAName) {
			// Not a file of the backup (Rowsafe's names are one encrypted
			// name per file, right under the backup's folder).
			fmt.Fprintf(progress, "skipped %s: not a file Rowsafe wrote for this backup\n", o.Key)
			skipped++
			continue
		}
		if err != nil {
			return fmt.Errorf("the name of %s can't be decrypted: wrong encryption passphrase, or it was altered", o.Key)
		}
		rel := strings.TrimPrefix(plain, folder)
		if rel == "" || filepath.IsAbs(rel) || !filepath.IsLocal(rel) {
			return fmt.Errorf("backup %s holds an unexpected file name %q", label, rel)
		}
		dst := filepath.Join(out, filepath.FromSlash(rel))
		n, err := r.downloadFile(ctx, o.Key, dst)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		files++
		bytes += n
	}
	if files == 0 {
		return fmt.Errorf("backup %s has no files", label)
	}
	note := ""
	if skipped > 0 {
		note = fmt.Sprintf(" (%d other files skipped)", skipped)
	}
	fmt.Fprintf(progress, "%s: %d files, %s, in %s%s\n", label, files, humanBytes(bytes), out, note)
	return nil
}

func (r *repo) downloadFile(ctx context.Context, key, dst string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return 0, err
	}
	rc, err := r.st.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	pr, err := objstore.Open(rc, r.pass)
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, pr)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, objstore.ErrBadPassphrase) {
		err = errors.New("can't be decrypted: wrong encryption passphrase, or the file was altered")
	}
	return n, err
}
