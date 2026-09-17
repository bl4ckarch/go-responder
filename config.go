package main

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
)

var (
	sessionMachineName string
	sessionDomain      string
	sessionDCERPCPort  int
	analyzeMode        bool
	globalChallenge    [8]byte
	lmMode             bool   // force NTLMv1 by removing Extended Session Security flag
	wpadEnabled        bool   // serve WPAD PAC file from HTTP server
	wpadProxyHost      string // proxy host:port to advertise in WPAD
)

func initSession(challengeHex string) {
	sessionMachineName = genMachineName()
	sessionDomain = genDomainName()
	sessionDCERPCPort = genPort()

	if challengeHex != "" {
		clean := strings.ReplaceAll(challengeHex, " ", "")
		b, err := hex.DecodeString(clean)
		if err == nil && len(b) == 8 {
			copy(globalChallenge[:], b)
			return
		}
	}
	rand.Read(globalChallenge[:])
}

func getChallenge() [8]byte { return globalChallenge }

func challengeHexStr() string {
	return strings.ToUpper(hex.EncodeToString(globalChallenge[:]))
}

func genMachineName() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 9)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return "WIN-" + string(b)
}

func genDomainName() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 4)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b) + ".LOCAL"
}

func genPort() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(30000))
	return int(n.Int64()) + 20000
}
