package client

import (
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestSHA256Crypt(t *testing.T) {
	// openssl passwd -5 -salt saltstring 'Hello world!' (rounds 5000).
	if got := sha256Crypt([]byte("Hello world!"), []byte("saltstring"), 5000); got != "5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" {
		t.Errorf("sha256Crypt = %s", got)
	}
}

func TestCopyVerifiers(t *testing.T) {
	if NativePasswordHash("secret") != "*14E65567ABDB5135D0CFD9A70B3032C179A49EE7" {
		t.Errorf("native: %s", NativePasswordHash("secret"))
	}
	for _, e := range protocol.Engines {
		if !protocol.EngineHas(e, protocol.FeatureSafeCopies) {
			continue
		}
		pw, v, err := NewCopyPasswordFor(e)
		if err != nil || len(pw) != 24 || !protocol.ValidCopyVerifier(e, v) {
			t.Errorf("%s: %q %q %v", e, pw, v, err)
		}
		for _, other := range protocol.Engines {
			same := other == e || (other == protocol.EnginePostgreSQL && e == protocol.EngineMongoDB)
			if !same && protocol.ValidCopyVerifier(other, v) {
				t.Errorf("a %s verifier passes as %s", e, other)
			}
		}
	}
}
