package core

import (
	"net"
	"strings"
)

var (
	RespondToIPs     []net.IP
	DontRespondIPs   []net.IP
	RespondToNames   []string
	DontRespondNames []string
)

func ShouldRespond(src net.Addr, name string) bool {
	srcIP := AddrToIP(src)

	for _, ip := range DontRespondIPs {
		if srcIP != nil && ip.Equal(srcIP) {
			LogVerbose("Filter: skipping %s (DontRespondTo)", src)
			return false
		}
	}
	for _, n := range DontRespondNames {
		if strings.EqualFold(n, name) {
			LogVerbose("Filter: skipping '%s' (DontRespondToName)", name)
			return false
		}
	}
	if len(RespondToIPs) > 0 {
		found := false
		for _, ip := range RespondToIPs {
			if srcIP != nil && ip.Equal(srcIP) {
				found = true
				break
			}
		}
		if !found {
			LogVerbose("Filter: skipping %s (not in RespondTo)", src)
			return false
		}
	}
	if len(RespondToNames) > 0 {
		found := false
		for _, n := range RespondToNames {
			if strings.EqualFold(n, name) {
				found = true
				break
			}
		}
		if !found {
			LogVerbose("Filter: skipping '%s' (not in RespondToName)", name)
			return false
		}
	}
	return true
}

func AddrToIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return net.ParseIP(addr.String())
	}
	return net.ParseIP(host)
}

func ParseIPList(s string) []net.IP {
	var out []net.IP
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func ParseNameList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
