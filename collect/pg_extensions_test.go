package collect

import "testing"

func TestMissingLibraryRE(t *testing.T) {
	m := missingLibraryRE.FindStringSubmatch(`ERROR: could not access file "$libdir/timescaledb-2.30.1": No such file or directory (SQLSTATE 58P01)`)
	if m == nil || m[1] != "timescaledb" || m[2] != "2.30.1" {
		t.Fatalf("%q", m)
	}
	if missingLibraryRE.MatchString(`could not access file "$libdir/other-1.0"`) {
		t.Error("another library")
	}
}
