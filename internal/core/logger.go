package core

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go-responder/internal/db"
)

// ANSI colour codes.
const (
	CReset     = "\033[0m"
	CRed       = "\033[31m"
	CGreen     = "\033[32;1m"
	CYellow    = "\033[33m"
	CCyan      = "\033[36m"
	CBlue      = "\033[34m"
	CMagenta   = "\033[35m"
	CWhiteBold = "\033[1m"
	CDim       = "\033[2m"
)

// HashDB is the persistent credential store opened by main at startup.
// All SaveCapture / SaveCleartext calls write through it.
var HashDB *db.DB

// HashLog is kept for backward compatibility (in-session dedup).
var (
	HashLog []string
	hashMu  sync.Mutex
)

func ResetHashLog() {
	hashMu.Lock()
	HashLog = nil
	hashMu.Unlock()
}

func ts() string { return time.Now().Format("15:04:05") }

// ── plain log helpers ─────────────────────────────────────────────────────────

func LogInfo(f string, a ...interface{}) {
	fmt.Printf("%s[*]%s %s %s\n", CCyan, CReset, ts(), fmt.Sprintf(f, a...))
}

func LogSuccess(f string, a ...interface{}) {
	fmt.Printf("%s[+]%s %s %s\n", CGreen, CReset, ts(), fmt.Sprintf(f, a...))
}

func LogError(f string, a ...interface{}) {
	fmt.Printf("%s[-]%s %s %s\n", CRed, CReset, ts(), fmt.Sprintf(f, a...))
}

func LogVerbose(f string, a ...interface{}) {
	if !Verbose {
		return
	}
	fmt.Printf("%s[~]%s %s %s\n", CYellow, CReset, ts(), fmt.Sprintf(f, a...))
}

// ── capture output ────────────────────────────────────────────────────────────

// protocolColor returns an ANSI colour for each protocol label.
func protocolColor(proto string) string {
	switch strings.ToUpper(proto) {
	case "SMB":
		return "\033[36;1m" // bold cyan
	case "HTTP", "HTTPS":
		return "\033[34;1m" // bold blue
	case "FTP":
		return "\033[33;1m" // bold yellow
	case "SMTP", "POP3", "IMAP":
		return "\033[35;1m" // bold magenta
	case "LDAP":
		return "\033[32;1m" // bold green
	case "MSSQL":
		return "\033[31;1m" // bold red
	case "DCE-RPC", "DCERPC":
		return "\033[36m" // cyan
	case "KERBEROS":
		return "\033[33m" // yellow
	case "PROXY", "WINRM":
		return "\033[34m" // blue
	default:
		return CWhiteBold
	}
}

// hashcatMode returns the relevant hashcat -m flag for a version string.
func hashcatMode(version string) string {
	switch version {
	case "NTLMv2":
		return "-m 5600"
	case "NTLMv1":
		return "-m 5500"
	case "KRB5PA":
		return "-m 19900"
	default:
		return ""
	}
}

// printCapture renders one credential capture event to stdout.
func printCapture(protocol, source, username, domain, version, detail string, isNew bool) {
	tag := CGreen + "★ NEW  " + CReset
	if !isNew {
		tag = CYellow + "✓ KNOWN" + CReset
	}

	pc := protocolColor(protocol)
	sep := strings.Repeat("─", 64)

	// Header line
	fmt.Printf("\n%s%s%s  %s[%s]%s  %s  %s%s%s  %s\n",
		CDim, sep[:4], CReset,
		pc, protocol, CReset,
		tag,
		CDim, version, CReset,
		source)

	// Account
	if domain != "" {
		fmt.Printf("   %sAccount%s  %s%s\\%s%s\n",
			CDim, CReset, CWhiteBold, domain, username, CReset)
	} else {
		fmt.Printf("   %sAccount%s  %s%s%s\n",
			CDim, CReset, CWhiteBold, username, CReset)
	}

	// Hash / password
	mode := hashcatMode(version)
	if version == "CLEARTEXT" || version == "AS-REQ" {
		label := "Password"
		if version == "AS-REQ" {
			label = "Principal"
		}
		fmt.Printf("   %s%-8s%s  %s%s%s\n",
			CDim, label, CReset, CYellow, detail, CReset)
	} else {
		if mode != "" {
			fmt.Printf("   %sHashcat%s  %s %s%s\n", CDim, CReset, mode, OutFile, CReset)
		}
		fmt.Printf("   %sHash%s     %s%s%s\n", CDim, CReset, CYellow, detail, CReset)
	}

	fmt.Printf("%s%s%s\n", CDim, sep, CReset)
}

// SaveCapture is the primary entry point for all hash/credential captures.
// It deduplicates against the persistent DB, renders a capture card, writes
// to the hashcat-compatible text file (new hashes only), and updates the DB.
func SaveCapture(protocol, source, username, domain, version, hash string) {
	isNew := true
	if HashDB != nil {
		isNew = !HashDB.HasUser(username, domain)
	} else {
		// fall back to in-memory dedup when no DB is open
		hashMu.Lock()
		key := strings.ToLower(username + "@" + domain)
		for _, h := range HashLog {
			if h == key {
				isNew = false
				break
			}
		}
		if isNew {
			HashLog = append(HashLog, key)
		}
		hashMu.Unlock()
	}

	printCapture(protocol, source, username, domain, version, hash, isNew)

	if !isNew {
		return
	}

	// Persist to DB.
	if HashDB != nil {
		_ = HashDB.Add(db.Entry{
			Protocol: protocol,
			Source:   source,
			Username: username,
			Domain:   domain,
			Version:  version,
			Hash:     hash,
		})
	}

	// Write hashcat-compatible text file.
	if version != "CLEARTEXT" && version != "AS-REQ" {
		hashMu.Lock()
		f, err := os.OpenFile(OutFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			fmt.Fprintln(f, hash)
			f.Close()
		} else {
			LogError("write hash file: %v", err)
		}
		hashMu.Unlock()
	}
}

// SaveCleartext logs a cleartext credential capture (no hashcat line written).
func SaveCleartext(protocol, source, username, domain, password string) {
	isNew := true
	if HashDB != nil {
		isNew = !HashDB.HasUser(username, domain)
	}

	printCapture(protocol, source, username, domain, "CLEARTEXT", password, isNew)

	if isNew && HashDB != nil {
		_ = HashDB.Add(db.Entry{
			Protocol: protocol,
			Source:   source,
			Username: username,
			Domain:   domain,
			Version:  "CLEARTEXT",
			Hash:     password,
		})
	}
}

// SaveHash is kept for internal use only — prefer SaveCapture in new code.
func SaveHash(hash string) {
	hashMu.Lock()
	defer hashMu.Unlock()
	for _, h := range HashLog {
		if h == hash {
			return
		}
	}
	HashLog = append(HashLog, hash)
	f, err := os.OpenFile(OutFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		LogError("write hash file: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, hash)
}
