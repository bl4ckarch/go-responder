package main

import (
	"net"
	"strings"
)

var (
	respondToIPs    []net.IP // empty = all
	dontRespondIPs  []net.IP // never respond to these
	respondToNames  []string // empty = all names
	dontRespondNames []string // never respond to these names
)

// shouldRespond returns true if we should poison/respond to src for name.
func shouldRespond(src net.Addr, name string) bool {
	srcIP := addrToIP(src)

	for _, ip := range dontRespondIPs {
		if srcIP != nil && ip.Equal(srcIP) {
			logVerbose("Filter: skipping %s (in DontRespondTo list)", src)
			return false
		}
	}

	for _, n := range dontRespondNames {
		if strings.EqualFold(n, name) {
			logVerbose("Filter: skipping '%s' (in DontRespondToName list)", name)
			return false
		}
	}

	if len(respondToIPs) > 0 {
		found := false
		for _, ip := range respondToIPs {
			if srcIP != nil && ip.Equal(srcIP) {
				found = true
				break
			}
		}
		if !found {
			logVerbose("Filter: skipping %s (not in RespondTo list)", src)
			return false
		}
	}

	if len(respondToNames) > 0 {
		found := false
		for _, n := range respondToNames {
			if strings.EqualFold(n, name) {
				found = true
				break
			}
		}
		if !found {
			logVerbose("Filter: skipping '%s' (not in RespondToName list)", name)
			return false
		}
	}

	return true
}

func addrToIP(addr net.Addr) net.IP {
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

func parseIPList(s string) []net.IP {
	var out []net.IP
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip := net.ParseIP(part)
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func parseNameList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
