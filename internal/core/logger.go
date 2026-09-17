package core

import (
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	CReset  = "\033[0m"
	CRed    = "\033[31m"
	CGreen  = "\033[32;1m"
	CYellow = "\033[33m"
	CCyan   = "\033[36m"
	CBlue   = "\033[34m"
)

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
