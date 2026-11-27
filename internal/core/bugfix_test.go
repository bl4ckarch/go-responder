package core

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
)

// FileTime must reflect the wall clock.  Computing it with
// time.Since(1601-01-01) saturates time.Duration (~292 years) and freezes the
// value at a bogus constant.
func TestFileTimeIsCurrent(t *testing.T) {
	got := FileTime(time.Now())
	want := uint64(time.Now().UnixNano()/100) + 116444736000000000
	diff := int64(got) - int64(want)
	if diff < -int64(5*time.Second/100) || diff > int64(5*time.Second/100) {
		t.Fatalf("FileTime off by %d (100ns ticks): got %d want ~%d", diff, got, want)
	}
	if got == 92233720368547758 {
		t.Fatal("FileTime returned the saturated time.Duration value")
	}
}

func TestBuildNTLMChallengeTimestampIsCurrent(t *testing.T) {
	var ch [8]byte
	msg := BuildNTLMChallenge(ch, "TEST.LOCAL", "WIN-TEST")
	if len(msg) < 48 {
		t.Fatalf("challenge too short: %d", len(msg))
	}
	tiLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(msg[44:48]))
	if tiOff+tiLen > len(msg) {
		t.Fatalf("target info out of range: off=%d len=%d total=%d", tiOff, tiLen, len(msg))
	}
	ti := msg[tiOff : tiOff+tiLen]

	var ft uint64
	for len(ti) >= 4 {
		id := binary.LittleEndian.Uint16(ti[0:2])
		l := int(binary.LittleEndian.Uint16(ti[2:4]))
		if 4+l > len(ti) {
			break
		}
		val := ti[4 : 4+l]
		if id == 0x0007 && l == 8 {
			ft = binary.LittleEndian.Uint64(val)
		}
		ti = ti[4+l:]
	}
	if ft == 0 {
		t.Fatal("no MsvAvTimestamp (0x0007) in target info")
	}
	got := time.Unix(0, int64(ft-116444736000000000)*100)
	if d := time.Since(got); d < -time.Minute || d > time.Minute {
		t.Fatalf("challenge timestamp is %v away from now (%v)", d, got)
	}
}

// PickFreePort must never hand back a port that is already bound.
func TestPickFreePortSkipsBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind loopback:", err)
	}
	busy := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	got := PickFreePort(net.ParseIP("127.0.0.1"), busy)
	if got == busy {
		t.Fatalf("PickFreePort returned the busy port %d", busy)
	}
	l2, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(got)))
	if err != nil {
		t.Fatalf("returned port %d is not bindable: %v", got, err)
	}
	l2.Close()
}

func TestHashcatModeKRB5PA(t *testing.T) {
	// We emit "$krb5pa$23$..." (RC4, etype 23) → mode 7500, not 19900 (etype 17).
	if got := hashcatMode("KRB5PA"); got != "-m 7500" {
		t.Fatalf("hashcatMode(KRB5PA) = %q, want -m 7500", got)
	}
}
