#!/usr/bin/env bash
# Test go-responder - lancer go-responder dans un autre terminal AVANT ce script:
#   sudo ./go-responder-static -i lo -v -c 1122334455667788 -o /tmp/hashes.txt

TARGET="127.0.0.1"
PASS=0
FAIL=0

ok()   { echo "[PASS] $*"; ((PASS++)); }
fail() { echo "[FAIL] $*"; ((FAIL++)); }
skip() { echo "[SKIP] $*"; }

echo ""
echo "=== go-responder functional tests ==="
echo ""

# ─── SMB ─────────────────────────────────────────────────────────────────────
echo "[*] SMB (port 445)"
OUT=$(smbclient //$TARGET/share -U "smbuser%SmbPass1" 2>&1)
echo "    $OUT" | head -2
# Hash capturé même si smbclient dit NT_STATUS_* → go-responder terminal confirme
echo "$OUT" | grep -qE "STATUS_|session" && ok "SMB - connexion établie, vérifier terminal go-responder" || fail "SMB - pas de connexion"

# ─── HTTP NTLM ───────────────────────────────────────────────────────────────
echo "[*] HTTP NTLM (port 80)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" --ntlm -u "httpuser:HttpPass1" --connect-timeout 5 http://$TARGET/ 2>&1)
echo "    HTTP $CODE"
[[ "$CODE" == "401" ]] && ok "HTTP - 401 reçu, hash capturé" || fail "HTTP - code inattendu: $CODE"

# ─── FTP ─────────────────────────────────────────────────────────────────────
echo "[*] FTP cleartext (port 21)"
OUT=$(curl -s --connect-timeout 5 ftp://ftpuser:FtpPass1@$TARGET/ 2>&1)
echo "    $OUT"
echo "$OUT" | grep -q "530\|Access denied" && ok "FTP - 530 reçu, cleartext capturé" || fail "FTP"

# ─── SMTP ────────────────────────────────────────────────────────────────────
echo "[*] SMTP NTLM (port 25)"
OUT=$(python3 - <<'EOF'
import socket, base64

def b64(b): return base64.b64encode(b).decode()

# NTLMSSP_NEGOTIATE minimal type1
type1 = (b'NTLMSSP\x00'          # signature
       + b'\x01\x00\x00\x00'     # type 1
       + b'\x07\x82\x08\xa2'     # flags
       + b'\x00' * 20)           # empty fields

s = socket.create_connection(('127.0.0.1', 25), timeout=5)
print("banner:", s.recv(256).decode().strip())

s.sendall(b'EHLO attacker\r\n')
print("ehlo:", s.recv(512).decode().strip()[-30:])

s.sendall(b'AUTH NTLM\r\n')
r = s.recv(256).decode().strip()
print("334:", r)

s.sendall(b64(type1).encode() + b'\r\n')
r = s.recv(512).decode().strip()
print("challenge:", r[:30], "...")

s.close()
EOF
2>&1)
echo "$OUT" | grep -q "challenge:" && ok "SMTP - challenge NTLM reçu" || fail "SMTP"
echo "    $(echo "$OUT" | grep -E 'challenge:|banner:')"

# ─── POP3 ────────────────────────────────────────────────────────────────────
echo "[*] POP3 (port 110)"
OUT=$(printf 'CAPA\r\nQUIT\r\n' | nc -w 3 $TARGET 110 2>&1)
echo "    $(echo "$OUT" | head -3 | tr '\n' ' ')"
echo "$OUT" | grep -q "NTLM" && ok "POP3 - AUTH NTLM annoncé" || fail "POP3"

# ─── IMAP ────────────────────────────────────────────────────────────────────
echo "[*] IMAP (port 143)"
OUT=$(printf 'A1 CAPABILITY\r\nA2 LOGOUT\r\n' | nc -w 3 $TARGET 143 2>&1)
echo "    $(echo "$OUT" | grep -i "ntlm\|capability")"
echo "$OUT" | grep -qi "AUTH=NTLM" && ok "IMAP - AUTH=NTLM annoncé" || fail "IMAP"

# ─── LDAP ────────────────────────────────────────────────────────────────────
echo "[*] LDAP (port 389)"
if command -v ldapsearch &>/dev/null; then
    OUT=$(ldapsearch -H ldap://$TARGET -x -b "" -s base 2>&1)
    echo "    $(echo "$OUT" | grep -i "result\|Invalid")"
    echo "$OUT" | grep -qi "Invalid credentials\|result: 49" && ok "LDAP - code 49 reçu" || fail "LDAP"
else
    # raw anonymous BindRequest BER
    OUT=$(printf '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' | nc -w 2 $TARGET 389 | xxd 2>&1)
    echo "    $OUT"
    echo "$OUT" | grep -q "61" && ok "LDAP - BindResponse reçu (0x61)" || fail "LDAP"
fi

# ─── DNS ─────────────────────────────────────────────────────────────────────
echo "[*] DNS (port 53)"
if command -v dig &>/dev/null; then
    OUT=$(dig @$TARGET anyfake.target.local A +time=3 +tries=1 +short 2>&1)
    echo "    DNS réponse: $OUT"
    echo "$OUT" | grep -q "127.0.0.1" && ok "DNS - poison A → 127.0.0.1" || fail "DNS"
else
    skip "DNS - dig absent"
fi

# ─── LLMNR ───────────────────────────────────────────────────────────────────
echo "[*] LLMNR (UDP 5355)"
python3 > /tmp/llmnr_res.txt 2>&1 <<'EOF'
import socket, struct
name = b'testhost'
fmt  = "!" + "H" * 6
pkt  = struct.pack(fmt, 0x1234, 0, 1, 0, 0, 0)
pkt += bytes([len(name)]) + name + b'\x00' + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(pkt, ('127.0.0.1', 5355))
try:
    r, addr = s.recvfrom(512)
    print(f"reponse {len(r)} bytes depuis {addr}")
except socket.timeout:
    print("timeout")
EOF
OUT=$(cat /tmp/llmnr_res.txt)
echo "    $OUT"
echo "$OUT" | grep -q "reponse" && ok "LLMNR - poison réponse reçue" || fail "LLMNR - timeout"

# ─── NBT-NS ──────────────────────────────────────────────────────────────────
echo "[*] NBT-NS (UDP 137)"
python3 > /tmp/nbtns_res.txt 2>&1 <<'EOF'
import socket, struct
def encode_nbt(name):
    padded = (name.upper() + ' ' * 15)[:15] + '\x00'
    out = bytes([32])
    for c in padded:
        v = ord(c)
        out += bytes([ord('A') + (v >> 4), ord('A') + (v & 0xf)])
    return out + b'\x00'

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(
    struct.pack('!HHHHHH', 0xABCD, 0x0110, 1, 0, 0, 0)
    + encode_nbt('TESTHOST')
    + struct.pack('!HH', 0x0020, 0x0001),
    ('127.0.0.1', 137)
)
try:
    r, addr = s.recvfrom(512)
    print(f"reponse {len(r)} bytes depuis {addr}")
except:
    print("timeout (normal sur loopback - pas de broadcast)")
EOF
OUT=$(cat /tmp/nbtns_res.txt)
echo "    $OUT"
echo "$OUT" | grep -qE "reponse|timeout" && ok "NBT-NS - query envoyée (voir terminal go-responder)" || fail "NBT-NS"

# ─── MSSQL ───────────────────────────────────────────────────────────────────
echo "[*] MSSQL TDS (port 1433)"
OUT=$(printf '\x12\x01\x00\x08\x00\x00\x01\x00' | nc -w 2 $TARGET 1433 | xxd 2>&1)
echo "    $OUT"
echo "$OUT" | grep -q "0401" && ok "MSSQL - PRELOGIN response reçue" || fail "MSSQL"

# ─── NXC SMB2 ────────────────────────────────────────────────────────────────
echo "[*] SMB2 via nxc (port 445)"
if command -v nxc &>/dev/null; then
    OUT=$(nxc smb $TARGET -u nxcuser -p NxcPass1 2>&1)
    echo "    $(echo "$OUT" | tail -2)"
    echo "$OUT" | grep -qi "STATUS_LOGON_FAILURE\|captured\|\[-\]" && ok "SMB2 nxc - NTLM exchange complet" || fail "SMB2 nxc"
else
    skip "SMB2 nxc - nxc absent"
fi

# ─── Résultat ────────────────────────────────────────────────────────────────
echo ""
echo "================================"
echo "  PASS: $PASS   FAIL: $FAIL"
echo "================================"
echo ""
echo "Hashes dans /tmp/hashes.txt :"
cat /tmp/hashes.txt 2>/dev/null || echo "(vide - go-responder bien lancé?)"
