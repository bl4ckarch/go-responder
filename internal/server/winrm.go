package server

import (
	"fmt"
	"net"
	"net/http"

	"go-responder/internal/core"
)

func ServeWinRM(ifaceIP net.IP) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", HandleHTTPNTLM)

	addr := fmt.Sprintf("%s:5985", ifaceIP)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		core.LogError("WinRM listen %s - %v (need root?)", addr, err)
		return
	}
	core.LogInfo("WinRM listening on %s:5985", ifaceIP)
	http.Serve(ln, mux)
}
