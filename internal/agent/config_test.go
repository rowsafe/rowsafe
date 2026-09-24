package agent

import "testing"

func TestConfigRepoTLSOptions(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Repo.SkipTLSVerify || cfg.Repo.Port != 0 || cfg.Repo.CAFile != "" {
		t.Errorf("defaults must verify TLS on the standard port: %+v", cfg.Repo)
	}

	t.Setenv("ROWSAFE_REPO_S3_VERIFY_TLS", "false")
	t.Setenv("ROWSAFE_REPO_S3_PORT", "9000")
	t.Setenv("ROWSAFE_REPO_S3_CA_FILE", "/etc/rowsafe/ca.crt")
	cfg, err = ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Repo.SkipTLSVerify || cfg.Repo.Port != 9000 || cfg.Repo.CAFile != "/etc/rowsafe/ca.crt" {
		t.Errorf("repo = %+v", cfg.Repo)
	}

	t.Setenv("ROWSAFE_REPO_S3_VERIFY_TLS", "nope")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("an unparseable ROWSAFE_REPO_S3_VERIFY_TLS must be an error, not silently off")
	}
}

func TestConfigAutoUpdate(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example")
	for value, want := range map[string]bool{
		"": true, "true": true, "1": true, "yes": true, "TRUE": true,
		"false": false, "0": false, "no": false, "off": false,
	} {
		t.Setenv("ROWSAFE_AUTO_UPDATE", value)
		cfg, err := ConfigFromEnv()
		if err != nil || cfg.AutoUpdate != want {
			t.Errorf("ROWSAFE_AUTO_UPDATE=%q: got %v, %v; want %v", value, cfg.AutoUpdate, err, want)
		}
	}
	// A typo must not silently leave auto-update on (or off).
	for _, bad := range []string{"flase", "disabled", "2"} {
		t.Setenv("ROWSAFE_AUTO_UPDATE", bad)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("ROWSAFE_AUTO_UPDATE=%q should be an error", bad)
		}
	}
}

func TestConfigDrillPreload(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.DrillPreload != DrillPreloadAuto {
		t.Fatalf("default = %q, %v", cfg.DrillPreload, err)
	}
	t.Setenv("ROWSAFE_DRILL_PRELOAD", "production")
	if cfg, err := ConfigFromEnv(); err != nil || cfg.DrillPreload != DrillPreloadProduction {
		t.Errorf("got %q, %v", cfg.DrillPreload, err)
	}
	t.Setenv("ROWSAFE_DRILL_PRELOAD", "always")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("unknown ROWSAFE_DRILL_PRELOAD must be an error")
	}
}

func TestConfigDefaultControlURL(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.ControlURL != "https://api.rowsafe.sh" {
		t.Fatalf("default control URL = %q, %v", cfg.ControlURL, err)
	}
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example/")
	if cfg, err := ConfigFromEnv(); err != nil || cfg.ControlURL != "https://rowsafe.example" {
		t.Fatalf("override = %q, %v", cfg.ControlURL, err)
	}
	t.Setenv("ROWSAFE_URL", "http://rowsafe.example")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("plain http to a remote host accepted")
	}
}
