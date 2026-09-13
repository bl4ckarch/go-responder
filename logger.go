package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	hashLog []string
	hashMu  sync.Mutex
)

const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cGreen  = "\033[32;1m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cBlue   = "\033[34m"
)

func ts() string { return time.Now().Format("15:04:05") }

func logInfo(f string, a ...interface{}) {
	fmt.Printf("%s[*]%s %s %s\n", cCyan, cReset, ts(), fmt.Sprintf(f, a...))
}

func logSuccess(f string, a ...interface{}) {
	fmt.Printf("%s[+]%s %s %s\n", cGreen, cReset, ts(), fmt.Sprintf(f, a...))
}

func logError(f string, a ...interface{}) {
	fmt.Printf("%s[-]%s %s %s\n", cRed, cReset, ts(), fmt.Sprintf(f, a...))
}

func logVerbose(f string, a ...interface{}) {
	if !verbose {
		return
	}
	fmt.Printf("%s[~]%s %s %s\n", cYellow, cReset, ts(), fmt.Sprintf(f, a...))
}

func saveHash(hash string) {
	hashMu.Lock()
	defer hashMu.Unlock()
	for _, h := range hashLog {
		if h == hash {
			return
		}
	}
	hashLog = append(hashLog, hash)
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logError("write hash file: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, hash)
}
