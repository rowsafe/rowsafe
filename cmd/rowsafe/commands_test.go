package main

import "testing"

func TestInstallCommand(t *testing.T) {
	for url, want := range map[string]string{
		"https://api.rowsafe.sh":      "curl -fsSL https://rowsafe.sh | sudo sh -s rse_abc",
		"https://api.rowsafe.sh/":     "curl -fsSL https://rowsafe.sh | sudo sh -s rse_abc",
		"https://rowsafe.example.com": "curl -fsSL https://rowsafe.sh | sudo ROWSAFE_URL=https://rowsafe.example.com sh -s rse_abc",
		"http://127.0.0.1:8080":       "curl -fsSL https://rowsafe.sh | sudo ROWSAFE_URL=http://127.0.0.1:8080 sh -s rse_abc",
	} {
		if got := installCommand(url, "rse_abc"); got != want {
			t.Errorf("installCommand(%q):\n got %s\nwant %s", url, got, want)
		}
	}
}
