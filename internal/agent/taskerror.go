package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Explaining failed tasks: when a tool (pgBackRest, pg_ctl, ...) fails, the
// task's outcome carries a protocol.TaskError (a stable code, the end of the
// tool's output with secrets removed, and facts the agent found out), which
// the control plane turns into plain words and fix buttons.

// taskErrorOf explains err when a tool the agent ran caused it; nil
// otherwise.
func (a *Agent) taskErrorOf(err error) *protocol.TaskError {
	var ce *pgbackrest.CommandError
	if err == nil || !errors.As(err, &ce) {
		return nil
	}
	te := protocol.ClassifyToolFailure(ce.Tool, ce.ExitCode, string(ce.Output), a.secretValues()...)
	var fe *factsError
	if errors.As(err, &fe) {
		for k, v := range fe.facts {
			if te.Facts == nil {
				te.Facts = map[string]string{}
			}
			te.Facts[k] = v
		}
	}
	return &te
}

// secretValues are the secrets this agent knows (storage keys and
// passphrases), removed from task logs and errors before they leave the
// server, besides what protocol.Redact recognizes by itself.
func (a *Agent) secretValues() []string {
	var out []string
	for _, r := range []pgbackrest.Repo{a.cfg.Repo, a.cfg.Repo2} {
		out = append(out, r.Key, r.KeySecret, r.Token, r.CipherPass)
	}
	if c, _ := a.storage.get(); c != nil {
		out = append(out, c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
	}
	return out
}

// factsError adds facts (protocol.TaskFact*) to a tool's failure.
type factsError struct {
	err   error
	facts map[string]string
}

func (e *factsError) Error() string { return e.err.Error() }
func (e *factsError) Unwrap() error { return e.err }

// ---- The backup folder ----

// repoFolderPath holds the backup folder of a stanza when it isn't the
// stanza's name: a setup that found the usual folder taken started fresh
// in a new one (protocol.ExistingBackupsNewFolder).
func (c Config) repoFolderPath(stanza string) string {
	return filepath.Join(c.ConfigDir, stanza+".folder")
}

var folderRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)

// validFolder is f if it is a safe folder name, else "".
func validFolder(f string) string {
	f = strings.TrimSpace(f)
	if !folderRE.MatchString(f) || strings.Contains(f, "..") {
		return ""
	}
	return f
}

// repoFolder is stanza's backup folder, "" for the default (its name).
func (a *Agent) repoFolder(stanza string) string {
	data, err := os.ReadFile(a.cfg.repoFolderPath(stanza))
	if err != nil {
		return ""
	}
	return validFolder(string(data))
}

// newRepoFolder is a fresh folder for stanza: <stanza>-<UTC date>-<time>.
func newRepoFolder(stanza string, now time.Time) string {
	return stanza + "-" + now.UTC().Format("20060102-150405")
}

// ---- Whose backups are in the folder ----

// repoOwner says whose backups the stanza's folder holds, from pgBackRest's
// info: this database's (same PostgreSQL system identifier), another's, or
// unknown (no readable backup index). repoVersion is the PostgreSQL major
// version of the backups there, when known.
func (a *Agent) repoOwner(ctx context.Context, db protocol.DatabaseSpec) (belongs, repoVersion string) {
	stanzas, err := a.cli(db).Info(ctx)
	if err != nil {
		return protocol.RepoBelongsUnknown, ""
	}
	var cur *pgbackrest.StanzaDB
	for _, s := range stanzas {
		if s.Name != db.Stanza {
			continue
		}
		for i := range s.DB {
			if cur == nil || s.DB[i].ID > cur.ID {
				cur = &s.DB[i]
			}
		}
	}
	if cur == nil || cur.SystemID == 0 {
		return protocol.RepoBelongsUnknown, ""
	}
	sys, err := a.systemID(ctx, db)
	if err != nil || sys == "" {
		return protocol.RepoBelongsUnknown, cur.Version
	}
	if fmt.Sprint(cur.SystemID) == sys {
		return protocol.RepoBelongsThis, cur.Version
	}
	return protocol.RepoBelongsOther, cur.Version
}

// systemID is the running PostgreSQL's system identifier.
func (a *Agent) systemID(ctx context.Context, db protocol.DatabaseSpec) (string, error) {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx)
	var id string
	err = conn.QueryRow(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&id)
	return id, err
}

// repoFacts adds what the agent can find out about the backup folder to a
// failed stanza-create: whose backups are there, their version, and the
// folder itself.
func (a *Agent) repoFacts(ctx context.Context, db protocol.DatabaseSpec, in protocol.InspectResult, err error) error {
	te := a.taskErrorOf(err)
	if te == nil {
		return err
	}
	switch te.Code {
	case protocol.TaskErrPathNotEmpty, protocol.TaskErrStanzaMismatch, protocol.TaskErrCipherMismatch:
	default:
		return err
	}
	facts := map[string]string{protocol.TaskFactRepoFolder: a.repoPathOf(db)}
	if in.VersionNum > 0 {
		facts[protocol.TaskFactDBVersion] = fmt.Sprint(in.VersionNum / 10000)
	}
	belongs, ver := a.repoOwner(ctx, db)
	facts[protocol.TaskFactRepoBelongs] = belongs
	if ver != "" {
		facts[protocol.TaskFactRepoVersion] = ver
	}
	return &factsError{err: err, facts: facts}
}

// repoPathOf is repo1-path in db's configuration ("" if unknown).
func (a *Agent) repoPathOf(db protocol.DatabaseSpec) string {
	conf, err := os.ReadFile(a.cfg.configPath(db.Stanza))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(conf), "\n") {
		if v, ok := strings.CutPrefix(line, "repo1-path="); ok {
			return v
		}
	}
	return ""
}

// createStanza sets backups up for an adoption: in a new folder when asked
// to start fresh, continuing with this database's backups already in the
// folder when asked to use them.
func (a *Agent) createStanza(ctx context.Context, db protocol.DatabaseSpec, in protocol.InspectResult, choice string, tl *taskLog) error {
	cli := a.cli(db)
	out, err := cli.StanzaCreate(ctx)
	tl.Output("stanza-create", out)
	if err == nil {
		return nil
	}
	if choice == protocol.ExistingBackupsUse {
		belongs, ver := a.repoOwner(ctx, db)
		if belongs != protocol.RepoBelongsThis {
			tl.Printf("the backups in the folder are not this database's (or can't be read): Rowsafe left them alone")
			return a.repoFacts(ctx, db, in, err)
		}
		if in.VersionNum == 0 || ver == fmt.Sprint(in.VersionNum/10000) {
			tl.Printf("the backups in the folder are this database's, but pgBackRest can't continue with them: Rowsafe left them alone")
			return a.repoFacts(ctx, db, in, err)
		}
		// This database's backups, of another PostgreSQL version:
		// move the folder on to the running version.
		tl.Printf("the backups in the folder are this database's (PostgreSQL %s): continuing with them", ver)
		out, uerr := cli.StanzaUpgrade(ctx)
		tl.Output("stanza-upgrade", out)
		if uerr == nil {
			return nil
		}
		err = uerr
	}
	return a.repoFacts(ctx, db, in, err)
}

// prepareFolder applies an adoption's choice about the backup folder
// before the configuration is written: a fresh start picks a new folder,
// kept for every later command. It returns the folder in use ("" for the
// default).
func (a *Agent) prepareFolder(db protocol.DatabaseSpec, choice string, tl *taskLog) (string, error) {
	if choice != protocol.ExistingBackupsNewFolder {
		return a.repoFolder(db.Stanza), nil
	}
	old := a.repoPathOf(db)
	folder := newRepoFolder(db.Stanza, time.Now())
	if err := os.MkdirAll(a.cfg.ConfigDir, 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(a.cfg.repoFolderPath(db.Stanza), []byte(folder+"\n"), 0o600); err != nil {
		return "", err
	}
	if old != "" {
		tl.Printf("starting fresh in a new backup folder %s; the files in %s stay where they are (Rowsafe never deletes them)", folder, old)
	} else {
		tl.Printf("starting fresh in a new backup folder %s; the files in the old folder stay where they are (Rowsafe never deletes them)", folder)
	}
	return folder, nil
}

// containsLine reports whether log already has detail's first line.
func containsLine(log, detail string) bool {
	line, _, _ := strings.Cut(detail, "\n")
	return strings.Contains(log, line)
}
