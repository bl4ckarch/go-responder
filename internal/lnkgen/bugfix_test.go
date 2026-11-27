package lnkgen

import (
	"encoding/binary"
	"testing"
)

// The Shell Link header stores ShowCommand at offset 60.  It used to be
// written at 64, which left ShowCommand = SW_HIDE (0) and corrupted HotKey.
func TestBuildLNK_ShowCommand(t *testing.T) {
	data := BuildLNK(`\\10.0.0.1\share`)
	if len(data) < 76 {
		t.Fatalf("LNK too short: %d", len(data))
	}
	if sc := binary.LittleEndian.Uint32(data[60:64]); sc != 1 {
		t.Fatalf("ShowCommand = %d, want 1 (SW_SHOWNORMAL)", sc)
	}
	if hk := binary.LittleEndian.Uint32(data[64:68]); hk != 0 {
		t.Fatalf("HotKey/Reserved clobbered: %d", hk)
	}
}
