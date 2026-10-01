package permissions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteFixtures writes a paired owner, the agent's identity and signed
// requests for scripts/test-permissions.sh (only with
// ROWSAFE_PERMISSIONS_FIXTURES=DIR). They expire in five minutes.
func TestWriteFixtures(t *testing.T) {
	dir := os.Getenv("ROWSAFE_PERMISSIONS_FIXTURES")
	if dir == "" {
		t.Skip("ROWSAFE_PERMISSIONS_FIXTURES is not set")
	}
	now := time.Now()
	k := newTestKey(t, AlgES256)
	if err := WriteOwners(filepath.Join(dir, "owners"), []Owner{ownerFor(t, k)}); err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("agent.json", map[string]string{"host_id": testHost, "agent_token": "not-a-real-token"})
	s := &signer{t: t, key: k, rp: testRP, origin: testOrigin}
	ok := s.sign(newChange(now))
	write("request-ok.json", Request{ID: "task-1", Signed: ok})
	write("request-replay.json", Request{ID: "task-2", Signed: ok})
	other := &signer{t: t, key: newTestKey(t, AlgEdDSA), rp: testRP, origin: testOrigin}
	write("request-other-key.json", Request{ID: "task-3", Signed: other.sign(newChange(now))})
	c := newChange(now)
	c.HostID = "host_02"
	write("request-other-host.json", Request{ID: "task-4", Signed: s.sign(c)})
	write("request-fresh-1.json", Request{ID: "task-5", Signed: s.sign(newChange(now))})
	write("request-fresh-2.json", Request{ID: "task-6", Signed: s.sign(newChange(now))})
	write("request-fresh-3.json", Request{ID: "task-7", Signed: s.sign(newChange(now))})
	if err := os.WriteFile(filepath.Join(dir, "fingerprint"), []byte(ownerFor(t, k).Fingerprint+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
