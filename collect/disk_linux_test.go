//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestDiskKindPartition(t *testing.T) {
	data := t.TempDir()
	var st syscall.Stat_t
	if err := syscall.Stat(data, &st); err != nil {
		t.Fatal(err)
	}
	dev := uint64(st.Dev) //nolint:unconvert
	major := (dev >> 8 & 0xfff) | (dev >> 32 & ^uint64(0xfff))
	minor := (dev & 0xff) | (dev >> 12 & ^uint64(0xff))

	old := sysRoot
	sysRoot = t.TempDir()
	t.Cleanup(func() { sysRoot = old })
	disk := filepath.Join(sysRoot, "devices", "vda")
	part := filepath.Join(disk, "vda1")
	for _, dir := range []string{filepath.Join(disk, "queue"), part, filepath.Join(sysRoot, "dev", "block")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(part, filepath.Join(sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor))); err != nil {
		t.Fatal(err)
	}
	if got := diskKind(data); got != "" {
		t.Errorf("without a rotational flag: %q", got)
	}
	if err := os.WriteFile(filepath.Join(disk, "queue", "rotational"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := diskKind(data); got != protocol.DiskSSD {
		t.Errorf("partition of an SSD: %q", got)
	}
}
