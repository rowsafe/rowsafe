package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Backup passphrase (protocol.TaskBackupPassphrase): on a server Rowsafe
// created, the installer generated the backup passphrase on the server and
// nobody has a copy. The person who asks gets it sealed to their browser's
// key, exactly like a Databases & users password (dbadmin.go): the control
// plane only relays ciphertext. The passphrase is never logged, never put
// in an error and never in the task log.

// errNoBackupPassphrase: the agent has no passphrase in its settings.
var errNoBackupPassphrase = errors.New("this server has no backup passphrase in Rowsafe's settings (ROWSAFE_REPO_CIPHER_PASS is empty), so there is nothing to show")

// runBackupPassphrase decodes a backup_passphrase task and runs it, keeping
// a typed nil result out of the interface.
func (a *Agent) runBackupPassphrase(task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec) (any, error) {
	var p protocol.BackupPassphraseParams
	if len(task.Params) > 0 {
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid backup_passphrase params: %w", err)
		}
	}
	res, err := a.backupPassphrase(db, task.ID, p, tl)
	if res == nil {
		return nil, err
	}
	return res, err
}

// backupPassphrase seals db's backup passphrase (and the second copy's,
// when there is one) to the requester's key, bound to the task.
func (a *Agent) backupPassphrase(db protocol.DatabaseSpec, taskID string, p protocol.BackupPassphraseParams, tl *taskLog) (*protocol.BackupPassphraseResult, error) {
	if _, err := protocol.ParseSealKey(p.PublicKey); err != nil {
		return nil, err // checked first: never touch the passphrase for a request that can't be sealed
	}
	secret := protocol.BackupPassphraseSecret{Passphrase: a.cfg.Repo.CipherPass}
	if isPostgres(db) {
		// A standby uses the primary's repository (and passphrase).
		secret.Passphrase = a.repoFor(db).CipherPass
		if a.cfg.SecondCopy() {
			secret.SecondCopy = a.cfg.Repo2.CipherPass
		}
	}
	if strings.TrimSpace(secret.Passphrase) == "" {
		return nil, errNoBackupPassphrase
	}
	plain, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	sealed, err := protocol.Seal(p.PublicKey, []byte(taskID), plain)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("the backup passphrase couldn't be encrypted for you: %v", err)
	}
	res := &protocol.BackupPassphraseResult{Secret: sealed, SecondCopy: secret.SecondCopy != ""}
	if res.SecondCopy {
		tl.Printf("the backup passphrases (this storage and the second copy) were encrypted for the person who asked; Rowsafe can't read them")
	} else {
		tl.Printf("the backup passphrase was encrypted for the person who asked; Rowsafe can't read it")
	}
	return res, nil
}
