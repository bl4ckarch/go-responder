package db

import (
	"os"
	"path/filepath"
	"testing"
)

// A corrupt DB must be reported, not silently replaced by an empty list on the
// next Add().
func TestOpen_CorruptFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.db")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected an error for a corrupt credential DB")
	}
}

func TestOpen_MissingFileIsFine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("missing DB should not error: %v", err)
	}
	if d.Count() != 0 {
		t.Fatalf("fresh DB should be empty")
	}
	if err := d.Add(Entry{Username: "bob", Domain: "CORP", Hash: "x"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	reopened, err := Open(path)
	if err != nil || reopened.Count() != 1 || !reopened.HasUser("BOB", "corp") {
		t.Fatalf("round-trip failed: err=%v count=%d", err, reopened.Count())
	}
}
