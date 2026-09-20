package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// Session state - set once at startup by main, read by all servers.
var (
	GlobalChallenge    [8]byte
	SessionMachineName string
	SessionDomain      string
	SessionDCERPCPort  int

	AnalyzeMode   bool
	LMMode        bool
	WPADEnabled   bool
	WPADProxyHost string
	Verbose       bool
	OutFile       string
	IfaceName     string

	// SelectiveMode: when true, poisoners skip hosts with SMB signing=required
	// (unless they are DCs), concentrating poisoning on high-value targets.
	SelectiveMode bool
)

func InitSession(challengeHex string) {
	SessionMachineName = GenMachineName()
	SessionDomain = GenDomainName()
	SessionDCERPCPort = GenPort()

	if challengeHex != "" {
		clean := strings.ReplaceAll(challengeHex, " ", "")
		b, err := hex.DecodeString(clean)
		if err == nil && len(b) == 8 {
			copy(GlobalChallenge[:], b)
			return
		}
	}
	rand.Read(GlobalChallenge[:])
}

func GetChallenge() [8]byte { return GlobalChallenge }

func NewChallenge() [8]byte { return GlobalChallenge }

func ChallengeHexStr() string {
	return strings.ToUpper(hex.EncodeToString(GlobalChallenge[:]))
}

func GenMachineName() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 9)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return "WIN-" + string(b)
}

func GenDomainName() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 4)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b) + ".LOCAL"
}

func GenPort() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(30000))
	return int(n.Int64()) + 20000
}

// GetIfaceLinkLocal returns the link-local IPv6 address of the named interface.
func GetIfaceLinkLocal(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no link-local IPv6 on interface %s", name)
}

// GetIfaceIP returns the first IPv4 address of the named interface.
func GetIfaceIP(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", name)
}
