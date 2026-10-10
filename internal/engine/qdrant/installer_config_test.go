package qdrant

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestInstallerConfig: the settings scripts/install.sh writes for a Qdrant
// it installs (qdrant_config) are valid YAML Qdrant reads, also where the
// server has a global IPv6 address and Qdrant listens on :: (a plain ::
// isn't a YAML value: Qdrant didn't start on such clouds' servers).
func TestInstallerConfig(t *testing.T) {
	src, err := os.ReadFile("../../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^qdrant_config\(\) \{\n.*?^\}\n`).Find(src)
	if fn == nil {
		t.Fatal("qdrant_config isn't in scripts/install.sh")
	}
	for _, c := range []struct{ host, tls, want string }{{"::", "true", "::"}, {"0.0.0.0", "true", "0.0.0.0"}, {"127.0.0.1", "false", "127.0.0.1"}} {
		script := "QDRANT_DATA=/var/lib/qdrant QDRANT_ENV_FILE=/etc/qdrant/env QDRANT_TLS_DIR=/etc/ssl/rowsafe-qdrant\n" + string(fn) +
			"qdrant_config '" + c.host + "' " + c.tls + "\n"
		out, err := exec.Command("sh", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", c.host, err, out)
		}
		var fc fileConfig
		if err := yaml.Unmarshal(out, &fc); err != nil {
			t.Fatalf("host %s: not YAML: %v\n%s", c.host, err, out)
		}
		if fc.Service.Host != c.want || fc.Service.EnableTLS == nil || (*fc.Service.EnableTLS != (c.tls == "true")) ||
			fc.Cluster.P2P.Host != "127.0.0.1" {
			t.Fatalf("host %s: %+v", c.host, fc.Service)
		}
		if c.host == "0.0.0.0" && !strings.Contains(string(out), "  host: 0.0.0.0\n") {
			t.Fatalf("an IPv4 host changed form (a re-run would restart Qdrant):\n%s", out)
		}
	}
}
