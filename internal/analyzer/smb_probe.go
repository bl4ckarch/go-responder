package analyzer

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

// ProbeSMBSigning dials port 445 on ip, sends an SMB2 Negotiate, and returns
// the signing status read from the server's SecurityMode field.
func ProbeSMBSigning(ip net.IP) SigningStatus {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "445"), 3*time.Second)
	if err != nil {
		return SigningUnknown
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	neg := buildProbeNegotiate()
	hdr := []byte{0x00, byte(len(neg) >> 16), byte(len(neg) >> 8), byte(len(neg))}
	if _, err := conn.Write(append(hdr, neg...)); err != nil {
		return SigningUnknown
	}

	nbhdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, nbhdr); err != nil {
		return SigningUnknown
	}
	msgLen := int(nbhdr[1])<<16 | int(nbhdr[2])<<8 | int(nbhdr[3])
	if msgLen < 68 || msgLen > 65536 {
		return SigningUnknown
	}
	resp := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return SigningUnknown
	}

	// Verify SMB2 magic (\xFESMB)
	if len(resp) < 4 || resp[0] != 0xFE || resp[1] != 0x53 || resp[2] != 0x4D || resp[3] != 0x42 {
		return SigningUnknown
	}

	// SMB2 NEGOTIATE Response (MS-SMB2 §2.2.4):
	//   header (64 bytes) | StructureSize(2) | SecurityMode(2) | DialectRevision(2) | ...
	// SecurityMode is at byte offset 66 of the full SMB2 message.
	//   Bit 0 (0x0001): SMB2_NEGOTIATE_SIGNING_ENABLED
	//   Bit 1 (0x0002): SMB2_NEGOTIATE_SIGNING_REQUIRED
	if len(resp) < 68 {
		return SigningUnknown
	}
	secMode := binary.LittleEndian.Uint16(resp[66:68])
	if secMode&0x0002 != 0 {
		return SigningRequired
	}
	if secMode&0x0001 != 0 {
		return SigningEnabled
	}
	return SigningNotRequired
}

func buildProbeNegotiate() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300}

	// SMB2 header (64 bytes)
	hdr := make([]byte, 64)
	hdr[0] = 0xFE
	hdr[1] = 0x53
	hdr[2] = 0x4D
	hdr[3] = 0x42
	binary.LittleEndian.PutUint16(hdr[4:6], 64)   // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:14], 0)  // Command: NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[14:16], 31) // CreditRequest
	binary.LittleEndian.PutUint32(hdr[32:36], 0xFFFE) // ProcessId

	// NEGOTIATE Request body (MS-SMB2 §2.2.3)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 36)                  // StructureSize
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialects))) // DialectCount
	body = binary.LittleEndian.AppendUint16(body, 0x0001)              // SecurityMode: signing enabled
	body = binary.LittleEndian.AppendUint16(body, 0)                   // Reserved
	body = binary.LittleEndian.AppendUint32(body, 0x7F)                // Capabilities
	body = append(body, make([]byte, 16)...)                           // ClientGuid
	body = binary.LittleEndian.AppendUint64(body, 0)                   // NegotiateContextOffset / ClientStartTime
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	return append(hdr, body...)
}
