#!/usr/bin/env bash
# =============================================================================================
#  pqc_scan.sh v2 - PQC cryptographic discovery (Kali, CLI only)
#
#  Give it one or more list files. Each list gets its own folder named after the file
#  (serverip.txt -> serverip/, switchip.txt -> switchip/, applications.txt -> applications/).
#  Inside: one folder per IP (or per website host for URL entries), with one text file per area:
#    00_SUMMARY.txt                  PQC summary for this target + index of the files below
#    01_ports_services_nmap.txt      open ports, service versions, OS, all nmap crypto scripts
#    10_tls_<port>.txt               TLS: handshake, versions, cipher suites, ML-KEM/PQC key exchange
#    11_certificates_<port>.txt      certificate chain decoded (PEM files in certs/)
#    12_http_<port>.txt              HTTP(S) headers: redirects, HSTS (per URL when URLs are given)
#    13_tls_wrapped_<port>_<svc>.txt TLS inside another protocol (RDP, MSSQL...) as seen by nmap
#    14_testssl_<port>.txt           testssl.sh output (only with -t)
#    20_ssh_<port>.txt               SSH key exchange (incl. mlkem/sntrup), host keys, ciphers, MACs
#    30_rdp_ / 31_smb_ / 32_vnc_<port>.txt   RDP security layer, SMB dialects, VNC security types
#    40_other_<port>_<svc>.txt       cleartext / not observable / unknown services
#    50_ike_udp500.txt               IKE / IPsec VPN proposals (root only)
#    51_udp_services.txt             UDP services (SNMP, IKE/IPsec, OpenVPN, NTP, RADIUS...) - root only
#  plus per list: 00_LIST_SUMMARY.txt (with a RUN REPORT), summary.csv, scan.log, MANIFEST_SHA256.txt,
#  unreachable.txt (hosts that were down/unreachable) and not_resolved.txt - both ready to re-run.
#
#  List file lines ('#' comments ok):
#    10.10.1.5   app01.corp.local   10.10.2.0/24   10.10.1.9:8443          -> folder per IP
#    https://portal.client.com/login   http://10.10.1.20:8080/            -> folder per website host
#  The same IP or host given several times is merged into one folder.
#
#  Only standard handshakes and banner reads - no exploitation, no brute force.
#  Scan only in-scope targets.
#
#  Usage : ./pqc_scan.sh -i serverip.txt [-i switchip.txt -i applications.txt] [options]
#    -i  list file (repeat -i for several lists)
#    -o  base folder where the list folders are created   (default: current folder)
#    -p  nmap TCP port spec, e.g. 22,443 or 1-65535 or - for all   (default: top 1000; -p- = every port)
#    -A  for URL entries, also scan all services of that host   (default: URL ports + 80 only)
#    -j  hosts scanned in parallel (each host is one nmap)  (default 4; raise for many robust hosts)
#    -t  also run testssl.sh on every TLS port            (slower, very detailed)
#    -n  skip all UDP scanning (SNMP, IKE/IPsec, OpenVPN, NTP, RADIUS...)
#    -F  fast: scan only ~48 common service ports (web/mail/dir/DB/mgmt/RDP/VNC) - best for
#        rate-limiting firewalls that drop probes and make a wide scan take an hour
#    -R  skip the reachability pre-check (scan every host, even one that looks down)
#    -T  timeout per handshake in seconds                 (default 8)
#  Env : OPENSSL_BIN=/path/to/openssl  (default: openssl on PATH; 3.5+ needed for ML-KEM tests)
#  Reachability: a host answering neither ICMP nor ~200 common TCP ports (after retries) is marked
#    UNREACHABLE and skipped to save time, and written to unreachable.txt. Slow / rate-limited hosts
#    get a second, slower probe first so they are not wrongly called down. Tune with env
#    REACH_T1 / REACH_T2 (probe host-timeouts), REACH_R1 / REACH_R2 (retries), NMAP_RETRIES, HOST_TIMEOUT.
#  Ports: default top 1000 TCP (fast, covers common services). -p 22,443,1433,... for a targeted set,
#    -p- for every port. A FILTERED port will not show whatever the range - it means the firewall/path
#    blocks it, not that the range was too small. UDP scans a curated service-port list (set UDP_PORTS).
#  Speed: the TCP scan runs in two phases - a fast sweep for open ports, then service + crypto
#    enumeration on the open ports only. A progress line prints every PROGRESS_EVERY seconds (default 15).
#    Timing is adaptive by default (nmap backs off on packet loss - safe on fragile / IPS-protected paths).
#    Fragile / IPS path (host goes unreachable when the scan starts): go gentle, e.g.
#        NMAP_TIMING=-T2 MAXRATE=100 sudo -E bash pqc_scan.sh -R -j 1 -p 22,443,3389,1433,3306,5432 -i hosts
#    Env: NMAP_TIMING (e.g. -T2), MAXRATE (cap pkts/sec), MINRATE (force a floor = faster on robust nets but
#    can overwhelm an IPS/fragile path), SWEEP_RETRIES (default 2), PROGRESS_EVERY.
# =============================================================================================

VERSION="2.4"
LISTS=(); BASE="."; PORTSPEC="--top-ports 1000"; JOBS=4; TESTSSL=0; UDP=1; TMO=8; ALLURL=0; REACHCHK=1
FASTPORTS="21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,1830,2049,2375,2376,3268,3269,3306,3389,5432,5433,5900,5985,5986,6379,7001,8000,8008,8080,8081,8443,8888,9000,9090,9200,9443,10000,27017"  # -F fast service set
usage() { sed -n '2,58p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while getopts "i:o:p:j:tnRFT:Ah" opt; do
  case "$opt" in
    i) LISTS+=("$OPTARG") ;; o) BASE="$OPTARG" ;; p) PORTSPEC="-p $OPTARG" ;; j) JOBS="$OPTARG" ;;
    t) TESTSSL=1 ;; n) UDP=0 ;; R) REACHCHK=0 ;; F) PORTSPEC="-p $FASTPORTS" ;; T) TMO="$OPTARG" ;; A) ALLURL=1 ;; *) usage ;;
  esac
done
[ ${#LISTS[@]} -gt 0 ] || usage
for l in "${LISTS[@]}"; do [ -f "$l" ] || { echo "list file not found: $l"; exit 1; }; done
mkdir -p "$BASE" && BASE="$(cd "$BASE" && pwd)" || exit 1

OSSL="${OPENSSL_BIN:-openssl}"
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
trap 'echo; echo "[!] interrupted - stopping all scans" >&2; kill $(jobs -p) 2>/dev/null; pkill -P $$ 2>/dev/null; exit 130' INT TERM
: > "$TMPD/openssl.cnf"
export OPENSSL_CONF="$TMPD/openssl.cnf"          # OS openssl.cnf must not hide legacy protocols
LOG="$TMPD/start.log"
BAR="=================================================================================================="

log() {
  local m
  m="[$(date +%H:%M:%S)] $*"
  echo "$m" >> "$LOG" 2>/dev/null
  if [ -t 2 ]; then printf '\r\033[K%s\n' "$m" >&2; else echo "$m" >&2; fi
}
have() { command -v "$1" >/dev/null 2>&1; }

for t in nmap "$OSSL" curl timeout awk; do have "$t" || { echo "missing required tool: $t"; exit 1; }; done
ROOT=0; [ "$(id -u)" -eq 0 ] && ROOT=1
if [ $ROOT -eq 1 ]; then NMAPSCAN="-sS -O --osscan-limit"; PROBESCAN="-sS"; else NMAPSCAN="-sT"; PROBESCAN="-sT"; fi
NMAPRETRY="${NMAP_RETRIES:-2}"
# per-host scan cap: a full -p- (all 65535 ports) gets 60m to finish; a focused/top-ports scan is capped at 20m so a rate-limiting host cannot hang. Override with HOST_TIMEOUT.
if [ "$PORTSPEC" = "-p -" ]; then HOSTTMO="${HOST_TIMEOUT:-60m}"; else HOSTTMO="${HOST_TIMEOUT:-20m}"; fi
TMG="${NMAP_TIMING:--T4}"   # nmap timing template; NMAP_TIMING=-T2 to go gentle on a fragile / IPS path
CAP=""; [ -n "$MAXRATE" ] && CAP="--max-rate $MAXRATE"   # cap packets/sec (gentle); no forced min-rate by default
UDPPORTS="${UDP_PORTS:-53,67,69,123,137,161,162,500,514,520,623,1194,1434,1645,1646,1701,1812,1813,4500,5353}"  # important UDP service ports
SSHAUDIT=""; have ssh-audit && SSHAUDIT="ssh-audit"
TESTSSLBIN=""; have testssl && TESTSSLBIN="testssl"; have testssl.sh && TESTSSLBIN="testssl.sh"
IKESCAN=""; have ike-scan && IKESCAN="ike-scan"
KEYSCAN=""; have ssh-keyscan && have ssh-keygen && KEYSCAN="ssh-keyscan"
LEGACY=""; "$OSSL" s_client -help 2>&1 | grep -q -- '-legacy_server_connect' && LEGACY="-legacy_server_connect"
SSL3=0; "$OSSL" s_client -help 2>&1 | grep -qE '^ *-ssl3 ' && SSL3=1
OSSLVER="$("$OSSL" version 2>&1)"
NMAPVER="$(nmap --version 2>/dev/null | head -1)"
CIPHERS='ALL:COMPLEMENTOFALL:@SECLEVEL=0'

PQ_GROUPS="X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 MLKEM512 MLKEM768 MLKEM1024"
CL13_GROUPS="X25519 X448 P-256 P-384 P-521 ffdhe2048 ffdhe3072 ffdhe4096"
CL12_GROUPS="X25519 X448 P-256 P-384 P-521"
group_ok() { ! "$OSSL" s_client -groups "$1" -connect 127.0.0.1:9 </dev/null 2>&1 | grep -qE 'cannot be set|SSL_CONF_cmd|Error with command'; }
PQ_OK=""; for g in $PQ_GROUPS; do group_ok "$g" && PQ_OK="$PQ_OK $g"; done
CL13_OK=""; for g in $CL13_GROUPS; do group_ok "$g" && CL13_OK="$CL13_OK $g"; done
CL12_OK=""; for g in $CL12_GROUPS; do group_ok "$g" && CL12_OK="$CL12_OK $g"; done
PQCAP="yes"; [ -z "$PQ_OK" ] && PQCAP="NO (openssl < 3.5 - ML-KEM cannot be tested; set OPENSSL_BIN)"

NSE="ssl-enum-ciphers,ssl-cert,sslv2,ssh2-enum-algos,ssh-hostkey,rdp-enum-encryption,smb-protocols,smb2-security-mode,vnc-info"
CLEAR_SVCS="^(telnet|ftp|http|http-alt|http-proxy|pop3|imap|smtp|submission|ldap|mysql|postgresql|redis|mongodb|memcache|nntp|irc|login|shell|exec|rsh|rlogin|finger|tftp|snmp|vnc|x11|cassandra|elasticsearch|amqp|mqtt|zookeeper|rtsp|sip)$"
MANUAL_SVCS="^(microsoft-ds|netbios-ssn|msrpc|ms-sql-s|oracle-tns|oracle|kerberos-sec|kerberos|domain|nfs|rpcbind|kpasswd5|globalcatLDAP|mountd|nlockmgr)$"
NOTLS_SVCS="^(ssh|ms-wbt-server|vnc|microsoft-ds|netbios-ssn|msrpc|domain|kerberos-sec|rpcbind|telnet|nfs)$"

# ---------------------------------------------------------------------------------------------
safe_name() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
hp() { case "$1" in *:*) echo "[$1]:$2" ;; *) echo "$1:$2" ;; esac; }
is_ipv4() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# sc <ip> <port> <sni|-> <starttls|-> [extra s_client args]  -> prints s_client output
sc() {
  local ip="$1" port="$2" sni="$3" st="$4"; shift 4
  local a=(-connect "$(hp "$ip" "$port")")
  if [ "$sni" != "-" ]; then a+=(-servername "$sni"); else a+=(-noservername); fi
  [ "$st" != "-" ] && a+=(-starttls "$st")
  [ -n "$LEGACY" ] && a+=("$LEGACY")
  timeout "$TMO" "$OSSL" s_client "${a[@]}" "$@" </dev/null 2>&1
}
hs_ok()     { grep -q 'Cipher is ' <<<"$1" && ! grep -qE 'Cipher is \(NONE\)|Cipher is 0000' <<<"$1"; }
hs_proto()  { grep -m1 -E '^ *Protocol *:' <<<"$1" | awk -F: '{gsub(/ /,"",$2); print $2}'; }
hs_cipher() { grep -m1 -oE 'Cipher is [^ ]+' <<<"$1" | awk '{print $3}'; }
hs_group()  { local g; g=$(grep -m1 -oE 'Negotiated TLS1\.3 group: [^ ]+' <<<"$1" | awk '{print $4}')
              [ -z "$g" ] && g=$(grep -m1 -E '(Server|Peer) Temp Key:' <<<"$1" | sed 's/.*Temp Key: //'); echo "$g"; }

# rdp_neg <ip> <port> <requestedProtocols byte, hex>  -> response bytes as hex (X.224 + RDP_NEG, MS-RDPBCGR 2.2.1.1)
rdp_neg() {
  timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2 && printf '\\x03\\x00\\x00\\x13\\x0e\\xe0\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x08\\x00\\x$3\\x00\\x00\\x00' >&3 && head -c 19 <&3" 2>/dev/null | od -An -tx1 | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'
}
rdp_meaning() {   # <hex response>
  local b; read -r -a b <<<"$1"
  if [ ${#b[@]} -lt 11 ]; then echo "no response"; return; fi
  if [ ${#b[@]} -lt 19 ]; then echo "no negotiation data (legacy server - Standard RDP Security only)"; return; fi
  if [ "${b[11]}" = "02" ]; then
    case "${b[15]}" in 00) echo "selected: Standard RDP Security (RC4)" ;; 01) echo "selected: TLS (no NLA)" ;;
      02) echo "selected: CredSSP / NLA over TLS" ;; 04) echo "selected: RDSTLS" ;; 08) echo "selected: CredSSP with Early User Auth" ;;
      *) echo "selected: protocol 0x${b[15]}" ;; esac
  elif [ "${b[11]}" = "03" ]; then
    case "${b[15]}" in 01) echo "refused: SSL/TLS required by server" ;; 02) echo "refused: SSL not allowed by server" ;;
      05) echo "refused: NLA (CredSSP) required by server" ;; 06) echo "refused: SSL with user auth required" ;; *) echo "refused: code 0x${b[15]}" ;; esac
  else echo "unexpected response"; fi
}

# ssh_kexinit <ip> <port>  -> server identification + the 10 algorithm name-lists of its SSH_MSG_KEXINIT
# (RFC 4253 s7.1). One TCP connection: read the server banner + first packet, nothing else is negotiated.
ssh_kexinit() {
  timeout 10 bash -c "exec 3<>/dev/tcp/$1/$2 && printf 'SSH-2.0-PQC_Inventory_Scanner\r\n' >&3 && timeout 3 cat <&3" 2>/dev/null \
  | od -An -v -tx1 | awk '
    function h2d(x,  i, v) { v = 0; for (i = 1; i <= length(x); i++) v = v * 16 + index("0123456789abcdef", substr(x, i, 1)) - 1; return v }
    { for (i = 1; i <= NF; i++) b[n++] = $i }
    END {
      s = -1
      for (i = 0; i < n - 3; i++) if (b[i] == "53" && b[i+1] == "53" && b[i+2] == "48" && b[i+3] == "2d") { s = i; break }
      if (s < 0) exit 1
      p = -1; ban = ""
      for (i = s; i < n; i++) { if (b[i] == "0a") { p = i + 1; break } if (b[i] != "0d") ban = ban sprintf("%c", h2d(b[i])) }
      if (p < 0 || p + 22 > n) exit 1
      plen = h2d(b[p] b[p+1] b[p+2] b[p+3])
      if (b[p+5] != "14" || plen > 35000) exit 1
      split("kex_algorithms server_host_key_algorithms encryption_algorithms_client_to_server encryption_algorithms_server_to_client mac_algorithms_client_to_server mac_algorithms_server_to_client compression_algorithms_client_to_server compression_algorithms_server_to_client languages_client_to_server languages_server_to_client", nm, " ")
      print "server_identification: " ban
      q = p + 6 + 16
      for (k = 1; k <= 10; k++) {
        if (q + 4 > n) exit 1
        L = h2d(b[q] b[q+1] b[q+2] b[q+3]); q += 4; str = ""
        if (q + L > n) exit 1
        for (j = 0; j < L; j++) str = str sprintf("%c", h2d(b[q+j]))
        q += L; print nm[k] ": " str
      }
    }'
}

starttls_for() {   # <port> <service>
  case "$2" in smtp|submission) echo smtp; return ;; pop3) echo pop3; return ;; imap) echo imap; return ;;
    ftp) echo ftp; return ;; ldap) echo ldap; return ;; xmpp*|jabber) echo xmpp; return ;;
    postgresql) echo postgres; return ;; mysql) echo mysql; return ;; nntp) echo nntp; return ;; esac
  case "$1" in 25|587|2525) echo smtp ;; 110) echo pop3 ;; 143) echo imap ;; 21) echo ftp ;; 389|3268) echo ldap ;;
    5222) echo xmpp ;; 5432) echo postgres ;; 3306) echo mysql ;; 119) echo nntp ;; *) echo "" ;; esac
}

# nse_block <port> <nmap normal output>  -> that port's lines (port row + script output)
nse_block() {
  awk -v p="$1/tcp" '$1==p {f=1; print; next}
    f && (/^[0-9]+\/(tcp|udp)/ || /^(Service Info|Host script|OS |Device type|Running|Network Distance|TRACEROUTE|Aggressive OS|No exact OS|OS details|MAC Address)/) {f=0}
    f {print}' "$2"
}

# decode one PEM certificate -> compact evidence + sets C_* vars
cert_decode() {
  local t; t=$("$OSSL" x509 -in "$1" -noout -text -fingerprint -sha256 -nameopt RFC2253 2>/dev/null)
  C_SUBJ=$(grep -m1 -E '^ *Subject:' <<<"$t" | sed 's/^ *Subject: *//')
  C_ISS=$(grep -m1 -E '^ *Issuer:' <<<"$t" | sed 's/^ *Issuer: *//')
  C_SER=$(grep -A1 -m1 'Serial Number' <<<"$t" | tr -d '\n' | sed 's/.*Serial Number: *//; s/ \{2,\}/ /g')
  C_NB=$(grep -m1 'Not Before' <<<"$t" | sed 's/.*Not Before *: *//')
  C_NA=$(grep -m1 'Not After' <<<"$t" | sed 's/.*Not After *: *//')
  C_PKA=$(grep -m1 'Public Key Algorithm' <<<"$t" | sed 's/.*Algorithm: *//')
  C_BITS=$(grep -m1 -oE 'Public-Key: \([0-9]+ bit\)' <<<"$t" | grep -oE '[0-9]+')
  C_CURVE=$(grep -m1 -E 'NIST CURVE|ASN1 OID' <<<"$t" | sed 's/.*: *//')
  C_SIG=$(grep -m1 'Signature Algorithm' <<<"$t" | sed 's/.*Algorithm: *//')
  C_SAN=$(grep -A1 -m1 'Subject Alternative Name' <<<"$t" | tail -1 | sed 's/^ *//')
  C_KU=$(grep -A1 -m1 'X509v3 Key Usage' <<<"$t" | tail -1 | sed 's/^ *//')
  C_EKU=$(grep -A1 -m1 'Extended Key Usage' <<<"$t" | tail -1 | sed 's/^ *//')
  C_CA=$(grep -q 'CA:TRUE' <<<"$t" && echo yes || echo no)
  C_FP=$(grep -m1 -i 'sha256 Fingerprint' <<<"$t" | sed 's/.*=//')
  C_DAYS=""; local e; e=$(date -d "$C_NA" +%s 2>/dev/null) && { C_DAYS=$(( (e - $(date +%s)) / 86400 )); C_NA=$(date -u -d "$C_NA" +%Y-%m-%d); }
  case "$C_PKA" in rsaEncryption) C_KT="RSA" ;; rsassaPss) C_KT="RSA-PSS" ;; id-ecPublicKey) C_KT="EC" ;;
    ED25519) C_KT="Ed25519" ;; ED448) C_KT="Ed448" ;; dsaEncryption) C_KT="DSA" ;; *) C_KT="$C_PKA" ;; esac
  C_KEY=$(echo "$C_KT ${C_BITS:+$C_BITS-bit} $C_CURVE" | xargs)
  printf '    Subject            : %s\n    Issuer             : %s\n    Serial             : %s\n' "$C_SUBJ" "$C_ISS" "$C_SER"
  printf '    Valid              : %s  ->  %s  (%s days left)\n' "$C_NB" "$C_NA" "${C_DAYS:-?}"
  printf '    Public key         : %s\n    Signature algorithm: %s\n' "$C_KEY" "$C_SIG"
  printf '    SAN                : %s\n    Key usage          : %s | EKU: %s | CA: %s\n    SHA-256 fingerprint: %s\n' \
    "${C_SAN:--}" "${C_KU:--}" "${C_EKU:--}" "$C_CA" "$C_FP"
}

# sorted issue list: High, Medium, PQC, Low, Info
print_flags() {   # <indent> <flag lines...>
  local ind="$1"; shift
  [ $# -eq 0 ] && return
  printf '%s\n' "$@" | awk 'BEGIN{o["[High]"]=1;o["[Medium]"]=2;o["[PQC]"]=3;o["[Low]"]=4;o["[Info]"]=5} {split($1,a," "); print o[a[1]] "\t" $0}' \
    | sort -n -s -k1,1 | cut -f2- | sed "s/^/$ind/"
}

file_desc() {
  case "$1" in
    00_*) echo "PQC summary for this target and this index" ;;
    01_*) echo "nmap: open ports, versions, OS, crypto scripts for all ports" ;;
    10_tls_*handshake_failed*) echo "TLS port where no handshake completed (alert received)" ;;
    10_tls_*) echo "TLS: handshake, protocol versions, cipher suites, key exchange incl. ML-KEM" ;;
    11_*) echo "certificate chain decoded (PEM files in certs/)" ;;
    12_*) echo "HTTP(S) response headers: redirects, HSTS" ;;
    13_*) echo "TLS inside another protocol, as seen by nmap" ;;
    14_*) echo "testssl.sh full output" ;;
    20_*) echo "SSH: key exchange, host keys, ciphers, MACs (+ ssh-audit)" ;;
    30_*) echo "RDP security layer / NLA" ;;
    31_*) echo "SMB dialects and signing" ;;
    32_*) echo "VNC security types" ;;
    40_*) echo "cleartext / not observable / unknown service" ;;
    50_*) echo "IKE / IPsec VPN proposals (UDP 500)" ;;
    51_*) echo "UDP services: SNMP, IKE/IPsec, OpenVPN, NTP, RADIUS (nmap -sU)" ;;
    certs) echo "PEM certificate files as sent by the servers" ;;
    *) echo "" ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------
# reach_check <ip> <detail-file>  ->  echoes "up" or "down" and writes a one-line reason to the file.
#   Stage 1: fast ICMP + common-TCP probe. Stage 2 (only if stage 1 said down): a slower, higher-
#   retry probe, so a slow or rate-limited device is not wrongly called down.
reach_check() {
  local ip="$1" det="$2" res
  local P1="-PE -PP -PS21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,5985,5986,8080,8443,9443 -PA80,443,3389"
  # shellcheck disable=SC2086
  res=$(nmap -sn -n $P1 --host-timeout "${REACH_T1:-40s}" --max-retries "${REACH_R1:-2}" -oG - "$ip" 2>/dev/null)
  if grep -q 'Status: Up' <<<"$res"; then
    echo " Reachability    : reachable (fast ICMP / TCP probe)" > "$det"; echo up; return
  fi
  # shellcheck disable=SC2086
  res=$(nmap -Pn -n $PROBESCAN --top-ports 200 -T3 --open --host-timeout "${REACH_T2:-150s}" --max-retries "${REACH_R2:-4}" -oG - "$ip" 2>/dev/null)
  if grep -qE '[0-9]+/open/' <<<"$res"; then
    echo " Reachability    : reachable (answered on a common TCP port during the slower confirm probe)" > "$det"; echo up; return
  fi
  {
    echo " Reachability    : UNREACHABLE - no reply to ICMP or ~200 common TCP ports after retries"
    echo "   fast probe    : ICMP + 30 common TCP ports, host-timeout ${REACH_T1:-40s}, retries ${REACH_R1:-2}"
    echo "   confirm probe : top-200 TCP, host-timeout ${REACH_T2:-150s}, retries ${REACH_R2:-4}"
  } > "$det"
  echo down
}

scan_target() {   # <key>  - everything for this target goes into ONE folder
  local key="$1"
  local ip="${TIP[$key]}" names="${NAMES[$key]}" inputs="${SRC[$key]}" urls="${URLS[$key]}" sni="-" portspec extra="${EXTRA[$key]}"
  [ -n "$names" ] && sni="${names%% *}"
  if [ "${FULL[$key]}" = 1 ]; then portspec="$PORTSPEC"; else portspec="-p $extra"; extra=""; fi
  local fname; fname=$(safe_name "$key")
  local D="$LISTDIR/$fname" T="$LISTDIR/$fname/.tmp"; mkdir -p "$D/certs" "$T"
  local S="$T/summary.txt" C="$T/rows.csv"; : > "$S"; : > "$C"
  local started; started=$(date '+%Y-%m-%d %H:%M:%S')
  date +%s > "$T/started_epoch"
  phase() { echo "$1" > "$T/phase"; }
  phase "starting"
  log "start  $key$([ "$key" != "$ip" ] && echo " ($ip)")"

  {
    echo "$BAR"; echo " PQC CRYPTOGRAPHIC SCAN - $key"; echo "$BAR"
    echo " List / folder   : $LISTNAME / $fname"
    echo " IP address      : $ip"
    echo " Hostname / SNI  : ${names:--}$( [ "$(wc -w <<<"$names")" -gt 1 ] && echo "   (TLS tested with SNI $sni)")"
    echo " URL(s)          : ${urls:--}"
    echo " From input line : $inputs"
    echo " Reverse DNS     : $(getent hosts "$ip" | awk '{print $2}' | head -1)"
    echo " Scan started    : $started"
    echo " Scanner         : $(hostname) | pqc_scan.sh $VERSION | $NMAPVER | $OSSLVER"
    echo " PQC KEX testing : $PQCAP"
    local pshow="${portspec#-p }"; pshow="${pshow/--top-ports /top }"; [ "$pshow" = "-" ] || [ "$pshow" = "-p-" ] && pshow="all 65535 TCP ports"
    echo " Port scope      : ${pshow}${extra:+  + ports from input: $extra}"
  } > "$T/head.txt"

  # ---- reachability pre-check: skip the heavy scan on hosts that are down / unreachable ----------
  if [ "$REACHCHK" -eq 1 ]; then
    phase "reachability check"
    local rstate; rstate=$(reach_check "$ip" "$T/reach.txt")
    if [ "$rstate" = down ]; then
      echo UNREACHABLE > "$T/state.txt"
      printf '%s\n' "${inputs%%;*}" > "$T/reinput.txt"
      {
        cat "$T/head.txt"; echo
        echo "$BAR"; echo " RESULT: HOST UNREACHABLE / DOWN - cryptographic scan skipped"; echo "$BAR"
        cat "$T/reach.txt"; echo
        echo " Listed in unreachable.txt for this list. To force a full scan anyway"
        echo " (for example a host that only listens on an unusual port), re-run:"
        echo "     ./pqc_scan.sh -R -i unreachable.txt"
        echo; echo " Scan finished: $(date '+%Y-%m-%d %H:%M:%S')"
      } > "$D/00_SUMMARY.txt"
      rmdir "$D/certs" 2>/dev/null
      {
        echo "--------------------------------------------------------------------------------------------------"
        echo " $key$([ "$key" != "$ip" ] && echo "  (IP $ip)")  |  UNREACHABLE / host down (not scanned)  |  folder: $fname/"
      } > "$T/line.txt"
      echo "\"$key\",\"$ip\",\"$names\",\"\",\"\",\"-\",\"UNREACHABLE / host down\",\"\",\"\",\"\",\"\",\"\",\"\",\"U\",\"\",\"\",\"not scanned - no response\",\"$fname/00_SUMMARY.txt\"" > "$C"
      log "UNREACHABLE $key ($ip) - skipped (host down)"
      return
    fi
    echo " Reachability    : reachable (pre-check)" >> "$T/head.txt"
  fi

  # ---- nmap, two phases (fast): 1) sweep for open ports, 2) service+crypto on open ports only -----
  local NM="$T/nmap.txt" NF="$D/01_ports_services_nmap.txt" DG="$T/disc.gnmap"; : > "$NM"
  local plabel="${portspec#-p }"; plabel="${plabel/--top-ports /top }"; [ "$plabel" = "-" ] || [ "$plabel" = "-p-" ] && plabel="all 65535 TCP"
  phase "discovering open ports ($plabel)"
  { cat "$T/head.txt"; echo "$BAR"; echo " NMAP phase 1 - fast port discovery; phase 2 - service versions + crypto scripts on open ports"; echo "$BAR"; } > "$NF"
  # phase 1: pure SYN/connect sweep, no version/scripts - fast even when every port is filtered
  local sweep="-sS"; [ $ROOT -eq 0 ] && sweep="-sT"
  local rate="$CAP"; [ -n "$MINRATE" ] && [ "$MINRATE" != 0 ] && rate="$rate --min-rate $MINRATE"   # default adaptive (nmap backs off on packet loss - safe on IPS/fragile paths); MINRATE forces speed
  echo "\$ nmap -Pn $sweep $portspec --max-retries ${SWEEP_RETRIES:-2} $rate $TMG --host-timeout $HOSTTMO -oG <file> $ip   (phase 1: find open ports)" >> "$NF"
  # run in the background with periodic stats so we can show nmap's own % during a long sweep
  # shellcheck disable=SC2086
  nmap -Pn $sweep $portspec --max-retries "${SWEEP_RETRIES:-2}" $rate $TMG --stats-every "${PROGRESS_EVERY:-10}s" --host-timeout "$HOSTTMO" -oG "$DG" "$ip" > "$T/sweep_stats.txt" 2>>"$T/nmap.err" &
  local spid=$! pc
  while kill -0 "$spid" 2>/dev/null; do
    pc=$(grep -oE 'About [0-9.]+% done' "$T/sweep_stats.txt" 2>/dev/null | tail -1)
    phase "discovering open ports${pc:+ - $pc}"
    sleep 3
  done
  wait "$spid"
  local OPEN; OPEN=$(awk -F'Ports: ' '/Ports:/{n=split($2,a,",");for(i=1;i<=n;i++){split(a[i],b,"/");if(b[2]~/open/){gsub(/ /,"",b[1]);print b[1]}}}' "$DG" 2>/dev/null | sort -un | paste -sd, -)
  [ -n "$extra" ] && OPEN="${OPEN:+$OPEN,}$extra"
  OPEN=$(tr ',' '\n' <<<"$OPEN" | grep -E '^[0-9]+$' | sort -un | paste -sd, -)
  if [ -z "$OPEN" ]; then
    echo >> "$NF"; echo "Nmap scan report for $ip" >> "$NF"
    grep -oE 'Not shown: [0-9]+ [a-z-]+ (tcp )?ports? \([a-z-]+\)|[0-9]+/[a-z]+.*' "$DG" >> "$NF" 2>/dev/null
    echo "No open TCP ports found in the scanned range." >> "$NF"
    : > "$T/ports.txt"
  else
    # phase 2: version + crypto scripts, only on the open ports (fast)
    phase "service + crypto scripts on $(tr ',' '\n' <<<"$OPEN" | grep -c .) open port(s): $OPEN"
    echo "\$ nmap -Pn $NMAPSCAN -sV --version-light $TMG -p $OPEN --max-retries $NMAPRETRY $CAP --script $NSE --script-timeout 5m --host-timeout $HOSTTMO -oN <file> $ip   (phase 2)" >> "$NF"
    echo >> "$NF"
    # shellcheck disable=SC2086
    nmap -Pn $NMAPSCAN -sV --version-light $TMG -p "$OPEN" --max-retries "$NMAPRETRY" $CAP --script "$NSE" --script-timeout 5m --host-timeout "$HOSTTMO" -oN "$NM" "$ip" >/dev/null 2>>"$T/nmap.err"
    grep -v '^# Nmap' "$NM" >> "$NF" 2>/dev/null
  fi
  [ -s "$T/nmap.err" ] && { echo; echo "nmap stderr:"; cat "$T/nmap.err"; } >> "$NF"

  # accuracy retry: open ports were found but the service scan errored out with no parsed results
  if [ -n "$OPEN" ] && ! grep -qE '^[0-9]+/tcp +open ' "$NM" && [ -s "$T/nmap.err" ]; then
    { echo; echo "\$ retry (slower, more retries) on open ports $OPEN"; } >> "$NF"
    # shellcheck disable=SC2086
    nmap -Pn $NMAPSCAN -sV --version-light -T3 -p "$OPEN" --max-retries 4 --script "$NSE" --script-timeout 5m --host-timeout "$HOSTTMO" -oN "$NM" "$ip" >/dev/null 2>>"$T/nmap.err"
    grep -v '^# Nmap' "$NM" >> "$NF" 2>/dev/null
  fi

  local OSGUESS; OSGUESS=$(grep -m1 -E '^(OS details|Running|Service Info: OS)' "$NM" | sed 's/^[^:]*: *//')
  awk '/^[0-9]+\/tcp +open /{split($1,a,"/"); s=$3; $1=$2=$3=""; sub(/^ +/,""); print a[1]"|"s"|"$0}' "$NM" > "$T/ports.txt"

  local n_enc=0 n_pq=0 n_nt=0 n_d=0 n_clear=0 p svc prod
  while IFS='|' read -r p svc prod <&3; do
    [ -z "$p" ] && continue
    phase "crypto checks: port $p ($svc)"
    local blk; blk=$(nse_block "$p" "$NM")
    local base="${svc#ssl/}"; base="${base%\?}"; local st="" layer="" protos="" pqc="n/a" groups="" certtxt="" ciphers="" macs="" cls="" flags=() o
    local tlsok=0 wrapped=0 o_direct=""
    local PB="$T/port.txt" CB="$T/cert.txt" HB="$T/http.txt" TS="$T/testssl.txt"; : > "$PB"; : > "$CB"; : > "$HB"; : > "$TS"

    # ---- TLS (direct, then STARTTLS) ----------------------------------------------------------
    if ! [[ "$base" =~ $NOTLS_SVCS ]]; then
      o=$(sc "$ip" "$p" "$sni" - -cipher "$CIPHERS" -showcerts); o_direct="$o"
      if hs_ok "$o"; then tlsok=1; layer="TLS"
      else
        st=$(starttls_for "$p" "$base")
        if [ -n "$st" ]; then
          o=$(sc "$ip" "$p" "$sni" "$st" -cipher "$CIPHERS" -showcerts)
          hs_ok "$o" && { tlsok=1; layer="STARTTLS ($st)"; }
        fi
      fi
    fi
    [ -z "$st" ] && st="-"

    if [ $tlsok -eq 1 ]; then
      n_enc=$((n_enc + 1))
      {
        echo "--- 1. Default TLS handshake ---"
        echo "\$ openssl s_client -connect $(hp "$ip" "$p") $([ "$sni" != "-" ] && echo "-servername $sni" || echo -noservername) $([ "$st" != "-" ] && echo "-starttls $st") -cipher '$CIPHERS' -showcerts $LEGACY"
        grep -E 'Protocol *:|Cipher is|Temp Key|Negotiated TLS1\.3 group|Peer signature|Peer signing|Verify return|Secure Renegotiation|^ *[0-9]+ s:|^ *i:|^depth' <<<"$o"
      } >> "$PB"
      local dproto dcipher dgroup; dproto=$(hs_proto "$o"); dcipher=$(hs_cipher "$o"); dgroup=$(hs_group "$o")
      [ -n "$dcipher" ] && ciphers="$dcipher (default negotiated; full list in 10_tls_$p.txt)"
      local verify; verify=$(grep -m1 'Verify return code' <<<"$o" | sed 's/.*code: //')

      # certificates -> 11_certificates_<port>.txt + certs/<port>_certN.pem
      { echo "--- Certificate chain as sent by the server on port $p (SNI: $([ "$sni" = "-" ] && echo none || echo "$sni")) ---"
        echo "    PEM files: certs/${p}_cert1.pem (leaf), certs/${p}_cert2.pem ..."; echo; } >> "$CB"
      awk '/-----BEGIN CERTIFICATE-----/{n++; f=1} f{print > (d"/cert" n ".pem")} /-----END CERTIFICATE-----/{f=0}' d="$T" <<<"$o"
      local i=0 leafkey="" leafsig="" leafexp="" leafdays="" leafkt="" leafbits="" leafself=0 cf
      for cf in $(ls "$T"/cert*.pem 2>/dev/null | sort -V); do
        i=$((i + 1))
        echo "  [cert $i]$([ $i -eq 1 ] && echo ' LEAF')   file: certs/${p}_cert$i.pem" >> "$CB"
        cert_decode "$cf" >> "$CB"; echo >> "$CB"
        if [ $i -eq 1 ]; then
          leafkey="$C_KEY"; leafsig="$C_SIG"; leafexp="$C_NA"; leafdays="$C_DAYS"; leafkt="$C_KT"; leafbits="$C_BITS"
          [ "$C_SUBJ" = "$C_ISS" ] && leafself=1
        else
          [ "$C_SUBJ" != "$C_ISS" ] && grep -qiE 'sha1With|md5With' <<<"$C_SIG" && flags+=("[Medium] Intermediate CA signed with $C_SIG")
        fi
        mv "$cf" "$D/certs/${p}_cert$i.pem"
      done
      [ $i -eq 0 ] && echo "    (no certificate presented)" >> "$CB"
      echo "--- 2. Certificate chain: see 11_certificates_$p.txt ($i certificate(s)) ---" >> "$PB"

      # protocol versions
      echo "--- 3. Protocol versions (one handshake per version) ---" >> "$PB"
      local pv label vlist=() acc=()
      for pv in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        case $pv in ssl3) label="SSL 3.0"; [ $SSL3 -eq 0 ] && { echo "    SSL 3.0 : not testable with this openssl build (nmap sslv2/ssl-enum-ciphers cover it)" >> "$PB"; continue; } ;;
          tls1) label="TLS 1.0" ;; tls1_1) label="TLS 1.1" ;; tls1_2) label="TLS 1.2" ;; tls1_3) label="TLS 1.3" ;; esac
        o=$(sc "$ip" "$p" "$sni" "$st" -"$pv" -cipher "$CIPHERS")
        if hs_ok "$o"; then acc+=("$label"); echo "    $label : ACCEPTED  ($(hs_cipher "$o"))" >> "$PB"
        else echo "    $label : rejected" >> "$PB"; fi
      done
      protos=$(IFS=,; echo "${acc[*]}" | sed 's/,/, /g')
      for v in "SSL 3.0" "TLS 1.0" "TLS 1.1"; do [[ " ${acc[*]} " == *"$v"* ]] && vlist+=("$v"); done
      [ ${#vlist[@]} -gt 0 ] && flags+=("[$( [[ " ${vlist[*]} " == *"SSL 3.0"* ]] && echo High || echo Medium)] Deprecated protocol enabled: $(IFS=,; echo "${vlist[*]}" | sed 's/,/, /g')")

      # key exchange groups
      echo "--- 4. Key-exchange groups (one handshake per group; ML-KEM = post-quantum) ---" >> "$PB"
      local g gacc=() pqacc=()
      if [[ "$protos" == *"TLS 1.3"* ]]; then
        for g in $PQ_OK $CL13_OK; do
          o=$(sc "$ip" "$p" "$sni" "$st" -tls1_3 -groups "$g")
          if hs_ok "$o"; then gacc+=("$g"); [[ "$g" == *MLKEM* ]] && pqacc+=("$g"); echo "    TLS 1.3 $g : ACCEPTED" >> "$PB"
          else echo "    TLS 1.3 $g : rejected" >> "$PB"; fi
        done
        for g in $PQ_GROUPS; do [[ " $PQ_OK " == *" $g "* ]] || echo "    TLS 1.3 $g : not testable (scanner openssl lacks it)" >> "$PB"; done
        if [ -n "$PQ_OK" ]; then
          o=$(sc "$ip" "$p" "$sni" "$st" -groups "X25519MLKEM768:X25519:P-256:P-384")
          echo "    Server preference when client offers X25519MLKEM768:X25519:P-256:P-384 -> $(hs_group "$o")" >> "$PB"
        fi
      else
        echo "    TLS 1.3 not supported - ML-KEM hybrid key exchange is impossible on this port" >> "$PB"
      fi
      if [[ "$protos" == *"TLS 1.2"* ]]; then
        for g in $CL12_OK; do
          o=$(sc "$ip" "$p" "$sni" "$st" -tls1_2 -groups "$g" -cipher 'ECDHE:@SECLEVEL=0')
          if hs_ok "$o"; then echo "    TLS 1.2 ECDHE $g : ACCEPTED" >> "$PB"; [[ " ${gacc[*]} " == *" $g "* ]] || gacc+=("$g")
          else echo "    TLS 1.2 ECDHE $g : rejected" >> "$PB"; fi
        done
      fi
      groups=$(IFS=,; echo "${gacc[*]}" | sed 's/,/, /g')
      if [ ${#pqacc[@]} -gt 0 ]; then pqc="YES ($(IFS=,; echo "${pqacc[*]}" | sed 's/,/, /g'))"; n_pq=$((n_pq + 1))
        flags+=("[Info] Hybrid post-quantum key exchange supported: ${pqacc[*]}")
      elif [[ "$protos" != *"TLS 1.3"* ]]; then pqc="NO (no TLS 1.3)"; flags+=("[PQC] Quantum-vulnerable key exchange - no TLS 1.3, so no ML-KEM")
      elif [ -z "$PQ_OK" ]; then pqc="NOT TESTED (scanner openssl < 3.5)"; n_nt=$((n_nt + 1)); flags+=("[PQC] Key exchange classical as far as tested - ML-KEM not tested")
      else pqc="NO"; flags+=("[PQC] Quantum-vulnerable key exchange - ML-KEM hybrid not supported (only: ${groups:-classical})"); fi

      # certificate findings
      if [ -n "$leafkt" ]; then
        if [[ "$leafkt" =~ ^(RSA|RSA-PSS)$ ]] && [ -n "$leafbits" ] && [ "$leafbits" -lt 2048 ]; then flags+=("[High] Weak certificate key: $leafkey")
        elif [ "$leafkt" = "DSA" ]; then flags+=("[High] DSA certificate key")
        elif [[ "$leafkt" =~ ^(RSA|RSA-PSS|EC|Ed25519|Ed448)$ ]]; then flags+=("[PQC] Quantum-vulnerable certificate key: $leafkey")
        fi
        grep -qiE 'sha1With|md5With|ecdsa-with-SHA1' <<<"$leafsig" && flags+=("[Medium] Certificate signed with $leafsig")
        if [ -n "$leafdays" ]; then
          if [ "$leafdays" -lt 0 ]; then flags+=("[High] Certificate EXPIRED ($leafexp)")
          elif [ "$leafdays" -le 30 ]; then flags+=("[Medium] Certificate expires in $leafdays days ($leafexp)"); fi
        fi
        [ $leafself -eq 1 ] && flags+=("[Low] Self-signed certificate")
        [ -n "$verify" ] && [[ "$verify" != 0* ]] && [ $leafself -eq 0 ] && flags+=("[Low] Certificate not trusted by scanner: $verify")
        certtxt="$leafkey, $leafsig, expires $leafexp (${leafdays:-?} d)"
      fi
      grep -q 'Secure Renegotiation IS NOT supported' <<<"$(sc "$ip" "$p" "$sni" "$st" -cipher "$CIPHERS" -tls1_2)" && [[ "$protos" == *"TLS 1.2"* ]] && flags+=("[Low] Secure renegotiation (RFC 5746) not supported")
      echo "--- 5. Default negotiation: $dproto / $dcipher / ${dgroup:-?} ---" >> "$PB"
      echo "--- 6. All accepted cipher suites per TLS version: nmap ssl-enum-ciphers output at the top of this file ---" >> "$PB"
    fi

    # ---- cipher-suite weaknesses from nmap ssl-enum-ciphers (also covers RDP/MSSQL wrapped TLS) ----
    if grep -q 'ssl-enum-ciphers' <<<"$blk"; then
      if [ $tlsok -eq 0 ]; then
        wrapped=1; layer="TLS (protocol-wrapped - seen by nmap only)"; [[ "$base" == ms-wbt-server || "$p" == 3389 ]] || n_enc=$((n_enc + 1))
        protos=$(grep -oE '^\|   (SSLv3|TLSv1\.[0-3]):' <<<"$blk" | sed 's/^|   //; s/://; s/TLSv/TLS /; s/SSLv3/SSL 3.0/' | paste -sd, - | sed 's/,/, /g')
        pqc="not testable (wrapped TLS)"; flags+=("[PQC] Key exchange classical as far as visible (wrapped TLS - ML-KEM not testable)")
        [[ "$protos" =~ (SSL\ 3.0|TLS\ 1\.0|TLS\ 1\.1) ]] && flags+=("[Medium] Deprecated protocol enabled (nmap): $protos")
        certtxt=$(grep -E 'Public Key type|Public Key bits|Signature Algorithm|Not valid after' <<<"$blk" | sed 's/^|[ _]*//' | paste -sd';' -)
      fi
      local wk; wk=$(grep -oE 'TLS_[A-Z0-9_]+' <<<"$blk" | grep -E 'RC4|3DES|_DES_|NULL|EXPORT|_anon_' | sort -u)
      [ -n "$wk" ] && flags+=("[$(grep -qE 'NULL|EXPORT|_anon_' <<<"$wk" && echo High || echo Medium)] Weak cipher suites accepted: $(echo "$wk" | wc -l) ($(echo "$wk" | head -4 | paste -sd' ' -)...)")
      local rsa; rsa=$(grep -oE 'TLS_RSA_WITH_[A-Z0-9_]+' <<<"$blk" | sort -u | wc -l)
      [ "$rsa" -gt 0 ] && flags+=("[Medium] Static RSA key exchange - no forward secrecy ($rsa suites)")
      grep -qE '\(dh (512|768|1024)\)' <<<"$blk" && flags+=("[Medium] Weak DH group (<= 1024-bit)")
      local least; least=$(grep -oE 'least strength: [A-F]' <<<"$blk" | awk '{print $3}')
      [ -n "$least" ] && echo "    nmap ssl-enum-ciphers overall grade (least strength): $least" >> "$PB"
    fi
    grep -q 'sslv2' <<<"$blk" && grep -q 'SSLv2 supported' <<<"$blk" && flags+=("[High] SSLv2 supported")

    # ---- HTTP / HTTPS headers -> 12_http_<port>.txt (one block per URL given for this port) --------
    local ulist="" u
    for u in $urls; do
      if [[ "$u" =~ ^(https?)://([^/:?#]+)(:([0-9]+))?([/?#].*)?$ ]]; then
        local up="${BASH_REMATCH[4]}"; [ -z "$up" ] && { [ "${BASH_REMATCH[1]}" = https ] && up=443 || up=80; }
        [ "$up" = "$p" ] && ulist="$ulist $u"
      fi
    done
    if [ -n "$ulist" ] || [[ "$base" =~ http || "$p" =~ ^(80|443|8080|8443|8000|8888|9443)$ ]]; then
      local h hdr allhdr="" url uh; [ "$sni" != "-" ] && h="$sni" || h="$ip"
      if [ -z "$ulist" ]; then if [ $tlsok -eq 1 ]; then ulist="https://$h:$p/"; else ulist="http://$h:$p/"; fi; fi
      for url in $ulist; do
        uh=$(sed -E 's|^https?://([^/:?#]+).*|\1|' <<<"$url")
        local ra=(); is_ipv4 "$uh" || ra=(--resolve "$uh:$p:$ip")
        hdr=$(curl -sk --noproxy '*' -L --max-redirs 5 -o /dev/null -D - --max-time "$TMO" "${ra[@]}" "$url" 2>&1 | tr -d '\r')
        { echo "--- HTTP response headers (redirects followed) ---"; echo "\$ curl -sk -L -D - $url"; echo "${hdr:-(no response)}" | head -60; echo; } >> "$HB"
        allhdr="$allhdr"$'\n'"$hdr"
      done
      if [ $tlsok -eq 1 ]; then
        grep -qi '^strict-transport-security' <<<"$allhdr" || { [ -n "$(tr -d '\n' <<<"$allhdr")" ] && flags+=("[Low] HSTS header not set"); }
      elif [ -n "$(tr -d '\n' <<<"$allhdr")" ] && grep -qE '^HTTP/' <<<"$allhdr"; then
        layer="None (cleartext HTTP)"
        if grep -qiE '^location: *https://' <<<"$allhdr"; then flags+=("[Low] HTTP listener (redirects to HTTPS)")
        else flags+=("[Medium] Content served over cleartext HTTP"); fi
      fi
    fi

    # ---- SSH ----------------------------------------------------------------------------------
    if [[ "$base" == ssh ]] || grep -q 'ssh2-enum-algos' <<<"$blk"; then
      layer="SSH"; n_enc=$((n_enc + 1)); protos="SSH-2"
      # algorithm lists: read the server's KEXINIT ourselves (works with every SSH version), nmap as fallback
      local kx="" try kex allalg src
      for try in 1 2 3 4; do kx=$(ssh_kexinit "$ip" "$p"); [ -n "$kx" ] && break; [ $try -lt 4 ] && sleep $((try * 5)); done
      # host keys and sizes: ssh-keyscan (speaks every modern key exchange), nmap ssh-hostkey as fallback
      local hk="" ksout="" kfp=""
      if [ -n "$KEYSCAN" ]; then
        for try in 1 2 3; do
          ksout=$(timeout 30 ssh-keyscan -T 8 -p "$p" -t rsa,ecdsa,ed25519 "$ip" 2>/dev/null </dev/null)
          [ "$(grep -vc '^#' <<<"$ksout")" -ge 1 ] && [ -n "$ksout" ] && break; [ $try -lt 3 ] && sleep $((try * 5))
        done
        kfp=$(ssh-keygen -lf - <<<"$ksout" 2>/dev/null)
        hk=$(awk 'NF>=3{t=$NF; gsub(/[()]/,"",t); print t" "$1}' <<<"$kfp" | paste -sd, - | sed 's/,/, /g')
      fi
      local sa_out=""
      [ -n "$SSHAUDIT" ] && sa_out=$(timeout 60 "$SSHAUDIT" -n -p "$p" "$ip" </dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
      if [ -n "$kx" ]; then
        src="scanner KEXINIT read"
        kex=$(grep '^kex_algorithms:' <<<"$kx" | sed 's/^[^:]*: //' | tr ',' '\n')
        allalg=$(grep -vE '^(server_identification|languages)' <<<"$kx" | sed 's/^[^:]*: //' | tr ',' '\n' | grep -v '^$' | sort -u)
        protos="SSH-2 ($(grep '^server_identification:' <<<"$kx" | sed 's/^[^:]*: //; s/^SSH-2.0-//'))"
      elif grep -qE '^\(kex\) ' <<<"$sa_out"; then
        src="ssh-audit"
        kex=$(grep -oE '^\(kex\) [^ ]+' <<<"$sa_out" | awk '{print $2}')
        allalg=$(grep -oE '^\((kex|key|enc|mac)\) [^ ]+' <<<"$sa_out" | awk '{print $2}' | sort -u)
      else
        src="nmap ssh2-enum-algos"
        kex=$(awk '/kex_algorithms:/{f=1;next} /server_host_key_algorithms:/{f=0} f' <<<"$blk" | sed 's/^|[ _]*//' | grep -v '^$')
        allalg=$(sed 's/^|[ _]*//' <<<"$blk")
      fi
      if [ -n "$kx" ]; then
        svc="ssh"; prod=$(grep '^server_identification:' <<<"$kx" | sed 's/^[^:]*: //; s|^SSH-2.0-||; s/_/ /')
        ciphers=$(grep '^encryption_algorithms_server_to_client:' <<<"$kx" | sed 's/^[^:]*: //; s/,/, /g')
        macs=$(grep '^mac_algorithms_server_to_client:' <<<"$kx" | sed 's/^[^:]*: //; s/,/, /g')
      elif [ "$src" = ssh-audit ]; then
        svc="ssh"; prod=$(grep -m1 '^(gen) software:' <<<"$sa_out" | sed 's/^[^:]*: //')
        ciphers=$(grep -oE '^\(enc\) [^ ]+' <<<"$sa_out" | awk '{print $2}' | paste -sd, - | sed 's/,/, /g')
        macs=$(grep -oE '^\(mac\) [^ ]+' <<<"$sa_out" | awk '{print $2}' | paste -sd, - | sed 's/,/, /g')
      fi
      { echo "--- 1. SSH algorithms offered by the server (source: $src) ---"
        echo "\$ (connect $ip:$p, send identification string, read SSH_MSG_KEXINIT - RFC 4253 s7.1; no key exchange, no login)"
        echo "${kx:-    (scanner could not read KEXINIT after 4 attempts - algorithms taken from $src)}"; } >> "$PB"
      groups=$(grep -vE 'ext-info|kex-strict|^$' <<<"$kex" | paste -sd, - | sed 's/,/, /g')
      if [ -z "$groups" ]; then
        pqc="UNKNOWN (no SSH algorithm data received)"; n_nt=$((n_nt + 1))
        flags+=("[Info] SSH algorithm list could not be read - the server may be rate-limiting connections (sshd MaxStartups); re-run this host")
      else
        if grep -qE 'mlkem|sntrup' <<<"$kex"; then pqc="YES ($(grep -E 'mlkem|sntrup' <<<"$kex" | paste -sd, - | sed 's/,/, /g'))"; n_pq=$((n_pq + 1))
          flags+=("[Info] SSH offers post-quantum hybrid key exchange")
        else pqc="NO"; flags+=("[PQC] SSH key exchange quantum-vulnerable - no mlkem768x25519 / sntrup761x25519"); fi
        local sw sl
        sw=$(grep -xE 'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|ssh-rsa|ssh-dss|.*-cbc(@.*)?|3des.*|arcfour.*|blowfish.*|cast128.*|hmac-md5.*|rijndael-cbc.*' <<<"$allalg" | sort -u | paste -sd' ' -)
        sl=$(grep -xE 'hmac-sha1.*|umac-64.*' <<<"$allalg" | sort -u | paste -sd' ' -)
        [ -n "$sw" ] && flags+=("[Medium] Weak SSH algorithms offered: $sw")
        [ -n "$sl" ] && flags+=("[Low] Legacy SSH MACs offered (SHA-1 / 64-bit tag): $sl")
        grep -qx 'diffie-hellman-group14-sha256' <<<"$allalg" && flags+=("[Low] SSH offers diffie-hellman-group14-sha256 (2048-bit group, ~112-bit strength) - prefer group16/18 or ML-KEM")
        if ! grep -q 'kex-strict-s' <<<"$allalg" && grep -qE 'chacha20-poly1305|etm@openssh.com' <<<"$allalg"; then
          flags+=("[Medium] Terrapin (CVE-2023-48795) exposure - strict KEX not advertised"); fi
      fi
      [ -z "$hk" ] && hk=$(grep -oE '^\|[ _]+[0-9]+ [A-Za-z0-9:+/=]+ \([A-Z0-9-]+\)' <<<"$blk" | sed 's/^|[ _]*//' | awk '{print $3" "$1}' | tr -d '()' | paste -sd, - | sed 's/,/, /g')
      { echo; echo "--- 2. SSH host keys ---"
        echo "\$ ssh-keyscan -T 8 -p $p -t rsa,ecdsa,ed25519 $ip | ssh-keygen -lf -"
        echo "${kfp:-    (ssh-keyscan not available or no answer - nmap ssh-hostkey used if it had data)}"
        echo "    Host keys: ${hk:-not determined}"; } >> "$PB"
      certtxt="host keys: ${hk:-not determined}"
      grep -qE 'RSA (512|768|1024)( |,|$)' <<<"$hk" && flags+=("[High] Weak SSH RSA host key (<2048)")
      if [ -n "$hk" ]; then flags+=("[PQC] Quantum-vulnerable SSH host key(s): $hk")
      else flags+=("[PQC] SSH host keys could not be read - treat as classical (RSA / ECDSA / Ed25519) unless the owner confirms otherwise"); fi
      if [ -n "$SSHAUDIT" ]; then
        { echo; echo "--- 3. ssh-audit ---"; echo "\$ $SSHAUDIT -n -p $p $ip"; echo "$sa_out"; } >> "$PB"
      fi
    fi

    # ---- RDP / SMB / VNC ----------------------------------------------------------------------
    if [[ "$base" == ms-wbt-server || "$p" == 3389 ]]; then
      local r0 r1 m0 m1
      r1=$(rdp_neg "$ip" "$p" 0b); m1=$(rdp_meaning "$r1")
      r0=$(rdp_neg "$ip" "$p" 00); m0=$(rdp_meaning "$r0")
      { echo "--- RDP security negotiation (X.224 Connection Request + RDP_NEG_REQ) ---"
        echo "    Request TLS|CredSSP|HYBRID_EX (0x0b) -> $m1"; echo "      received: ${r1:-nothing}"
        echo "    Request Standard RDP only   (0x00) -> $m0"; echo "      received: ${r0:-nothing}"; } >> "$PB"
      layer="RDP (${m1#selected: })${layer:+ + $layer}"; n_enc=$((n_enc + 1))
      [[ "$m0" == *"Standard RDP"* || "$m0" == *legacy* ]] && flags+=("[High] RDP accepts Standard RDP Security (RC4, no TLS)")
      [[ "$m1" == *"TLS (no NLA)"* ]] && flags+=("[Medium] RDP does not enforce NLA (CredSSP) - server chose plain TLS")
      grep -qE 'RC4: SUCCESS' <<<"$blk" && flags+=("[High] RDP RC4 encryption levels accepted (nmap)")
      [[ "$m1" == selected:* && "$m1" != *"Standard"* ]] && pqc="not testable (RDP-wrapped TLS)" && \
        flags+=("[PQC] RDP TLS key exchange cannot be tested for ML-KEM through RDP - treat as classical unless vendor confirms")
    fi
    if grep -q 'smb-protocols' <<<"$blk" || [[ "$base" =~ ^(microsoft-ds|netbios-ssn)$ ]]; then
      layer="SMB (not observable)"
      grep -qE 'NT LM 0\.12|SMBv1' <<<"$blk" && flags+=("[High] SMBv1 enabled")
      grep -qiE 'signing enabled but not required' <<<"$blk" && flags+=("[Low] SMB signing not required")
      flags+=("[Info] SMB3 encryption not visible on the network - verify EncryptData / RejectUnencryptedAccess in config")
    fi
    if grep -q 'vnc-info' <<<"$blk"; then
      layer="VNC"; protos=$(grep -m1 'Protocol version' <<<"$blk" | sed 's/.*: *//')
      grep -qE 'None \(1\)' <<<"$blk" && flags+=("[High] VNC allows connection with NO authentication / no encryption")
      if grep -qE 'VNC Authentication \(2\)' <<<"$blk" && ! grep -qE 'VeNCrypt|TLS \(18\)' <<<"$blk"; then
        flags+=("[High] VNC session not encrypted (VNC Authentication / DES challenge only)"); fi
    fi

    # ---- TLS port where no handshake completed (TLS alert received) ------------------------------
    if [ -z "$layer" ] && grep -qE 'alert handshake failure|SSL alert number|alert protocol version|alert insufficient' <<<"$o_direct"; then
      layer="TLS (handshake failed)"
      { echo "--- TLS handshake failed (server answered with a TLS alert) ---"; grep -E 'alert|error' <<<"$o_direct" | head -5; } >> "$PB"
      if [ -z "$PQ_OK" ]; then
        flags+=("[Info] Speaks TLS but no handshake completed - server may require ML-KEM-only groups or an ML-DSA certificate that this openssl cannot do; re-run with openssl 3.5+")
      else
        flags+=("[Info] Speaks TLS but no handshake completed - may require a client certificate, a specific SNI hostname, or algorithms the scanner lacks")
      fi
    fi

    # ---- not encrypted / not observable / unknown ---------------------------------------------
    if [ -z "$layer" ]; then
      if [[ "$base" =~ $MANUAL_SVCS ]]; then layer="Not observable by scan ($base)"
        flags+=("[Info] Encryption not visible on the network for $base - collect configuration from owner")
      elif [[ "$base" =~ $CLEAR_SVCS ]]; then layer="None (cleartext $base)"
        flags+=("[$([[ "$base" =~ ^(telnet|ftp|login|shell|exec|rsh|rlogin|tftp|redis|memcache|mongodb)$ ]] && echo High || echo Medium)] Cleartext service - no encryption in transit ($base)$([ -n "$(starttls_for "$p" "$base")" ] && echo ' - STARTTLS not offered')")
      else layer="Unknown"; flags+=("[Info] Service not identified / no TLS - confirm with owner ($svc)"); fi
    fi
    [[ "$layer" == None* ]] && n_clear=$((n_clear + 1))

    # ---- optional testssl.sh --------------------------------------------------------------------
    if [ $TESTSSL -eq 1 ] && [ -n "$TESTSSLBIN" ] && { [ $tlsok -eq 1 ] || [ $wrapped -eq 1 ]; }; then
      local tt="$ip:$p" ta=(); [ "$sni" != "-" ] && tt="$sni:$p"; [ "$st" != "-" ] && ta=(-t "$st")
      { echo "\$ $TESTSSLBIN --quiet --color 0 --warnings off -p -s -f -P -S ${ta[*]} --ip $ip $tt"
        timeout 900 "$TESTSSLBIN" --quiet --color 0 --warnings off -p -s -f -P -S "${ta[@]}" --ip "$ip" "$tt" </dev/null 2>&1; } >> "$TS"
    fi

    # ---- class ----------------------------------------------------------------------------------
    local fl; fl=$(printf '%s\n' "${flags[@]}")
    if grep -qE '^\[(High|Medium)\]' <<<"$fl" || [[ "$layer" == None* ]]; then cls="B"
    elif [[ "$pqc" == YES* ]] && ! grep -q '^\[PQC\]' <<<"$fl"; then cls="D"
    elif grep -q '^\[PQC\]' <<<"$fl"; then cls="A"
    else cls="U"; fi
    [ "$cls" = "D" ] && n_d=$((n_d + 1))

    # ---- write this port's files ----------------------------------------------------------------
    local b; b=$(safe_name "$base"); local pf
    case "$layer" in
      RDP*) pf="30_rdp_$p.txt" ;; SSH) pf="20_ssh_$p.txt" ;; SMB*) pf="31_smb_$p.txt" ;; VNC*) pf="32_vnc_$p.txt" ;;
      "TLS (protocol-wrapped"*) pf="13_tls_wrapped_${p}_$b.txt" ;; "TLS (handshake failed)") pf="10_tls_${p}_handshake_failed.txt" ;;
      TLS|STARTTLS*) pf="10_tls_$p.txt" ;; *) pf="40_other_${p}_$b.txt" ;;
    esac
    local ph; ph=$(
      echo "$BAR"; echo " $key  -  PORT $p/tcp  -  $svc${prod:+  -  $prod}"; echo "$BAR"
      echo " IP / SNI        : $ip / $([ "$sni" = "-" ] && echo none || echo "$sni")"
      echo " Encryption      : $layer"
      echo " Protocols       : ${protos:--}"
      [ -n "$groups" ] && echo " Key exchange    : $groups"
      [ -n "$ciphers" ] && echo " Ciphers         : $ciphers"
      [ -n "$macs" ] && echo " MACs            : $macs"
      echo " PQC key exchange: $pqc"
      [ -n "$certtxt" ] && echo " Cert / host key : $certtxt"
      echo " Class           : $cls   (B = weak today, A = quantum-vulnerable, D = post-quantum, U = unknown)"
      echo " Issues          :"; print_flags "     " "${flags[@]}"
      echo " Scanned         : $(date '+%Y-%m-%d %H:%M:%S')"
      echo "$BAR")
    { echo "$ph"; echo; echo "--- nmap result for this port (service detection + crypto scripts) ---"
      echo "${blk:-  (no nmap output for this port)}"; echo; cat "$PB"; } > "$D/$pf"
    [ -s "$CB" ] && { echo "$ph"; echo; cat "$CB"; } > "$D/11_certificates_$p.txt"
    [ -s "$HB" ] && { echo "$ph"; echo; cat "$HB"; } > "$D/12_http_$p.txt"
    [ -s "$TS" ] && { echo "$ph"; echo; cat "$TS"; } > "$D/14_testssl_$p.txt"

    {
      printf '  %-9s %-16s %-30s PQC-KEX: %s\n' "$p/tcp" "${svc:0:16}" "${layer:0:30}" "$pqc"
      printf '            Protocols: %s\n' "${protos:--}"
      [ -n "$groups" ] && printf '            Key exchange: %s\n' "$groups"
      [ -n "$ciphers" ] && printf '            Ciphers: %s\n' "$ciphers"
      [ -n "$macs" ] && printf '            MACs: %s\n' "$macs"
      [ -n "$certtxt" ] && printf '            Cert/keys: %s\n' "$certtxt"
      printf '            Class: %s    Files: %s%s%s\n' "$cls" "$pf" "$([ -s "$CB" ] && echo ", 11_certificates_$p.txt")" "$([ -s "$HB" ] && echo ", 12_http_$p.txt")"
      print_flags "              " "${flags[@]}"
    } >> "$S"
    local q='"'; esc() { echo "$1" | tr '\n' ';' | sed "s/$q/'/g; s/;$//"; }
    echo "\"$key\",\"$ip\",\"$names\",\"$p\",\"$svc\",\"$(esc "$prod")\",\"$(esc "$layer")\",\"$(esc "$protos")\",\"$(esc "$pqc")\",\"$(esc "$groups")\",\"$(esc "$ciphers")\",\"$(esc "$macs")\",\"$(esc "$certtxt")\",\"$cls\",\"$(grep -c '^\[High\]' <<<"$fl")/$(grep -c '^\[Medium\]' <<<"$fl")\",\"$(esc "$(grep '^\[PQC\]' <<<"$fl")")\",\"$(esc "$(grep -E '^\[(High|Medium|Low)\]' <<<"$fl")")\",\"$fname/$pf\"" >> "$C"
  done 3< "$T/ports.txt"

  # ---- UDP service scan (curated important ports) -> 51_udp_services.txt + rows -------------------
  if [ "$UDP" -eq 1 ] && [ "$ROOT" -eq 1 ]; then
    phase "UDP service scan"
    local UNM="$T/udp.txt"
    # shellcheck disable=SC2086
    nmap -Pn -sU -sV --version-light -T4 -p "$UDPPORTS" --script "ike-version,snmp-info,ntp-info" --script-timeout 3m --host-timeout "$HOSTTMO" -oN "$UNM" "$ip" >/dev/null 2>>"$T/nmap.err"
    {
      cat "$T/head.txt"; echo "$BAR"; echo " NMAP UDP - important service ports ($UDPPORTS)"; echo "$BAR"
      echo "\$ nmap -Pn -sU -sV -p $UDPPORTS --script ike-version,snmp-info,ntp-info -oN <file> $ip"; echo
      grep -v '^# Nmap' "$UNM" 2>/dev/null; echo
      echo "Note: full UDP (all 65535 ports) is not run - it takes hours per host and is unreliable."
      echo "      Set env UDP_PORTS to scan a different set. IKE detail is in 50_ike_udp500.txt."
    } > "$D/51_udp_services.txt"
    local up usvc ulayer upqc ucls uflag
    while IFS='|' read -r up usvc; do
      [ -z "$up" ] && continue
      case "$up" in
        161|162) ulayer="SNMP (UDP)"; upqc="n/a (symmetric)"; ucls="U"; uflag="[Info] SNMP in use - confirm SNMPv3 with authPriv (AES / SHA); SNMPv1 / v2c have no encryption" ;;
        500|4500) ulayer="IKE / IPsec VPN (UDP)"; upqc="classical DH unless ML-KEM configured"; ucls="A"; uflag="[PQC] IKE / IPsec key exchange is classical unless ML-KEM (RFC 9370) is configured - see 50_ike_udp500.txt" ;;
        1194) ulayer="OpenVPN (UDP)"; upqc="TLS-based (not observable here)"; ucls="U"; uflag="[Info] OpenVPN detected - confirm the TLS version and PQC support from the device configuration" ;;
        1812|1813|1645|1646) ulayer="RADIUS (UDP)"; upqc="n/a"; ucls="U"; uflag="[Info] RADIUS in use - confirm RadSec / IPsec protection; native RADIUS has weak protection" ;;
        123) ulayer="NTP (UDP)"; upqc="n/a"; ucls="U"; uflag="[Info] NTP in use - unauthenticated time is a resilience risk (not a PQC item)" ;;
        623) ulayer="IPMI / BMC (UDP)"; upqc="n/a"; ucls="U"; uflag="[Info] IPMI / BMC exposed - confirm it is restricted to the management network" ;;
        *) ulayer="UDP service ($usvc)"; upqc="not observable"; ucls="U"; uflag="[Info] UDP service $usvc - confirm the encryption in use from the configuration" ;;
      esac
      { printf '  %-9s %-16s %-30s PQC-KEX: %s\n' "$up/udp" "${usvc:0:16}" "${ulayer:0:30}" "$upqc"
        print_flags "              " "$uflag"; } >> "$S"
      echo "\"$key\",\"$ip\",\"$names\",\"$up/udp\",\"$usvc\",\"\",\"$ulayer\",\"\",\"$upqc\",\"\",\"\",\"\",\"\",\"$ucls\",\"0/0\",\"$(grep -o '^\[PQC\].*' <<<"$uflag")\",\"$uflag\",\"$fname/51_udp_services.txt\"" >> "$C"
    done < <(awk '/^[0-9]+\/udp +open/ && !/open\|filtered/{split($1,a,"/"); svc=$3; for(i=4;i<=NF;i++) svc=svc" "$i; print a[1]"|"$3}' "$UNM" 2>/dev/null)
  fi

  # ---- IKE / IPsec on UDP 500 -> 50_ike_udp500.txt -------------------------------------------------
  if [ $UDP -eq 1 ] && [ $ROOT -eq 1 ] && [ -n "$IKESCAN" ]; then
    phase "IKE / IPsec check (UDP 500)"
    local ik1 ik2 sa=""; ik1=$(timeout 30 $IKESCAN -M "$ip" 2>&1); ik2=$(timeout 30 $IKESCAN -2 -M "$ip" 2>&1)
    # a real responder returns a non-zero responder cookie and ONE chosen proposal (a single DH group)
    if grep -qE 'Handshake returned' <<<"$ik1$ik2" && ! grep -q 'CKY-R=0000000000000000' <<<"$ik1$ik2"; then
      sa=$(grep -ohE 'SA=\([^)]*\)' <<<"$ik1$ik2" | awk '{ if (gsub(/DH_Group=|Group=/,"&") <= 1) print }' | head -2 | paste -sd' ' -)
    fi
    local iflags=() icls="-"
    if [ -n "$sa" ]; then
      iflags=("[PQC] IKE/IPsec uses classical Diffie-Hellman - quantum-vulnerable")
      grep -qE '3DES|DES|MD5|SHA1|modp768|modp1024|Group=1:|Group=2:|Group=5:' <<<"$sa" && iflags+=("[Medium] Weak IKE proposal accepted: $sa")
      icls="A"; [ ${#iflags[@]} -gt 1 ] && icls="B"; n_enc=$((n_enc + 1))
    fi
    {
      echo "$BAR"; echo " $key  -  IKE / IPsec VPN (UDP 500)"; echo "$BAR"
      echo " Result          : $([ -n "$sa" ] && echo "VPN responder found - proposal: $sa" || echo "no IKE responder (or response ignored)")"
      echo " Class           : $icls"; echo " Issues          :"; print_flags "     " "${iflags[@]}"; echo "$BAR"; echo
      echo "\$ $IKESCAN -M $ip      (IKEv1 main mode, default proposals)"; echo "$ik1"; echo
      echo "\$ $IKESCAN -2 -M $ip   (IKEv2)"; echo "$ik2"; echo
      grep -qE 'Handshake returned' <<<"$ik1$ik2" && [ -z "$sa" ] && echo "Note: response ignored - zero responder cookie / echoed proposal list (not a real IKE responder)"
      echo "Note: an ML-KEM additional key exchange (RFC 9370) happens after IKE_SA_INIT and is not visible here - confirm with the VPN configuration."
    } > "$D/50_ike_udp500.txt"
    if [ -n "$sa" ]; then
      { printf '  %-9s %-16s %-30s PQC-KEX: %s\n' "500/udp" "isakmp" "IKE/IPsec VPN" "NO (classical DH)"
        printf '            Proposal: %s\n            Class: %s    Files: 50_ike_udp500.txt\n' "$sa" "$icls"; print_flags "              " "${iflags[@]}"; } >> "$S"
      echo "\"$key\",\"$ip\",\"$names\",\"500/udp\",\"isakmp\",\"\",\"IKE/IPsec VPN\",\"IKE\",\"NO (classical DH)\",\"$sa\",\"\",\"$icls\",\"\",\"${iflags[0]}\",\"${iflags[1]:-}\",\"$fname/50_ike_udp500.txt\"" >> "$C"
    fi
  fi

  # ---- 00_SUMMARY.txt ------------------------------------------------------------------------------
  local nports; nports=$(grep -c . "$T/ports.txt")
  local ready
  if [ "$nports" -eq 0 ]; then ready="Not assessed - no open TCP ports found (host down, filtered or closed)"
  elif [ $n_enc -eq 0 ] && [ $n_clear -gt 0 ]; then ready="No encryption in use - cleartext services only"
  elif [ $n_enc -eq 0 ]; then ready="Not determined - no observable encryption"
  elif [ $n_pq -eq $n_enc ] && [ $n_d -eq $n_enc ]; then ready="QUANTUM-SAFE as observed - PQC key exchange and no quantum-vulnerable keys on all $n_enc encrypted services"
  elif [ $n_pq -eq $n_enc ]; then ready="PQC key exchange on ALL encrypted services ($n_pq/$n_enc) - some certificates/host keys still classical"
  elif [ $n_pq -gt 0 ]; then ready="MIXED - PQC key exchange on $n_pq of $n_enc encrypted services$([ $n_nt -gt 0 ] && echo " ($n_nt not determined - see port files)")"
  elif [ $n_nt -gt 0 ]; then ready="NOT DETERMINED for $n_nt service(s) - PQC key exchange could not be tested (see port files); other $((n_enc - n_nt)) encrypted service(s) classical"
  else ready="NOT quantum-safe - classical key exchange only on all $n_enc encrypted services"; fi
  rmdir "$D/certs" 2>/dev/null
  {
    cat "$T/head.txt"
    echo " OS (nmap guess) : ${OSGUESS:-not determined$([ $ROOT -eq 0 ] && echo ' (run as root for OS detection)')}"
    echo " Open TCP ports  : $nports"
    local filt; filt=$(grep -oE 'Not shown: [0-9]+ (filtered|closed|filtered|closed-filtered)' "$NM" 2>/dev/null | head -1)
    [ -n "$filt" ] && echo " Port note       : $filt (-p- scanned all 65535). If a known service is missing, the path/firewall may be filtering it - confirm scope with the owner."
    echo " PQC READINESS   : $ready"
    echo
    echo "$BAR"
    echo " PQC SUMMARY per port"
    echo "    Class : B = weak/broken today   A = quantum-vulnerable (rate with Mosca X+Y vs Z)   D = post-quantum   U = unknown"
    echo "    Tags  : [High] [Medium] [Low] = weakness today   [PQC] = quantum-vulnerable   [Info] = note / positive"
    echo "$BAR"
    if [ -s "$S" ]; then cat "$S"; else echo "  No open TCP ports found in the scanned range."; fi
    echo
    echo "$BAR"; echo " FILES IN THIS FOLDER"; echo "$BAR"
    local f; for f in $(ls "$D" | sort); do printf '  %-40s %s\n' "$f" "$(file_desc "$f")"; done
    printf '  %-40s %s\n' "00_SUMMARY.txt" "$(file_desc 00_SUMMARY.txt)"
    echo; echo " Scan finished: $(date '+%Y-%m-%d %H:%M:%S')"
  } > "$T/sum.txt"
  mv "$T/sum.txt" "$D/00_SUMMARY.txt"
  {
    echo "--------------------------------------------------------------------------------------------------"
    echo " $key$([ "$key" != "$ip" ] && echo "  (IP $ip)")  |  open TCP ports: $nports  |  folder: $fname/"
    echo " PQC READINESS: $ready"
    [ -s "$S" ] && cat "$S"
  } > "$T/line.txt"
  [ -s "$C" ] || echo "\"$key\",\"$ip\",\"$names\",\"\",\"\",\"x\",\"No open TCP ports\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"$fname/00_SUMMARY.txt\"" > "$C"
  echo "$([ "$nports" -eq 0 ] && echo NOPORTS || echo SCANNED)" > "$T/state.txt"
  [ -s "$T/nmap.err" ] && echo 1 > "$T/warn"
  log "done   $key - $nports open ports - $ready"
}

# ---------------------------------------------------------------------------------------------
# add_target <key> <ip> <hostname|""> <port|""> <input line> <url|"">
add_target() {
  local key="$1" ip="$2" name="$3" port="$4" src="$5" url="$6"
  if [ -z "${SRC[$key]+x}" ]; then KEYS+=("$key"); SRC[$key]="$src"; TIP[$key]="$ip"; NAMES[$key]=""; FULL[$key]=0; EXTRA[$key]=""; URLS[$key]=""
  elif [[ "; ${SRC[$key]}; " != *"; $src; "* ]]; then SRC[$key]="${SRC[$key]}; $src"; fi
  if [ -n "$name" ] && [[ " ${NAMES[$key]} " != *" $name "* ]]; then NAMES[$key]="${NAMES[$key]:+${NAMES[$key]} }$name"; fi
  if [ -n "$url" ] && [[ " ${URLS[$key]} " != *" $url "* ]]; then URLS[$key]="${URLS[$key]:+${URLS[$key]} }$url"; fi
  if [ -n "$port" ]; then [[ ",${EXTRA[$key]}," == *",$port,"* ]] || EXTRA[$key]="${EXTRA[$key]:+${EXTRA[$key]},}$port"
  else FULL[$key]=1; fi
}

log "pqc_scan.sh $VERSION | lists: ${LISTS[*]} | parallel $JOBS | root=$ROOT | ports: $PORTSPEC | base folder: $BASE"
log "openssl: $OSSLVER | PQC KEX testing: $PQCAP | ssh-audit: ${SSHAUDIT:-no} | testssl: ${TESTSSLBIN:-no} | ike-scan: ${IKESCAN:-no} | ssh-keyscan: ${KEYSCAN:-no}"
[ $ROOT -eq 0 ] && log "not root: TCP connect scan, no OS detection, no UDP/IKE check (run with sudo for those)"

# ---------------------------------------------------------------------------------------------
# progress_monitor <total> : prints a progress line every PROGRESS_EVERY seconds while a list runs
progress_monitor() {
  local total="$1" fin running disc crypto other k d ph start el pct filled i bar line tty=0
  [ -t 2 ] && tty=1
  start=$(date +%s)
  while :; do
    sleep "${PROGRESS_EVERY:-10}"
    fin=0; running=0; disc=0; crypto=0; other=0
    for k in "${KEYS[@]}"; do
      d="$LISTDIR/$(safe_name "$k")/.tmp"
      if [ -f "$d/state.txt" ]; then fin=$((fin + 1))
      elif [ -f "$d/phase" ]; then
        running=$((running + 1)); ph=$(cat "$d/phase" 2>/dev/null)
        case "$ph" in discover*|reach*|start*) disc=$((disc + 1)) ;; crypto*|service*) crypto=$((crypto + 1)) ;; *) other=$((other + 1)) ;; esac
      fi
    done
    el=$(( $(date +%s) - start )); pct=$(( total > 0 ? fin * 100 / total : 100 )); filled=$(( fin * 30 / (total > 0 ? total : 1) ))
    local now=""
    for k in "${KEYS[@]}"; do
      d="$LISTDIR/$(safe_name "$k")/.tmp"
      [ ! -f "$d/state.txt" ] && [ -f "$d/phase" ] && { now="$k: $(cat "$d/phase" 2>/dev/null)"; break; }
    done
    bar=""; for ((i = 0; i < 30; i++)); do [ "$i" -lt "$filled" ] && bar+="#" || bar+="-"; done
    line=$(printf '[%s] %d/%d (%d%%)  running %d (scan %d, crypto %d)  elapsed %d:%02d%s' \
      "$bar" "$fin" "$total" "$pct" "$running" "$((disc + other))" "$crypto" "$((el / 60))" "$((el % 60))" "${now:+  | $now}")
    if [ $tty -eq 1 ]; then printf '\r\033[K%s' "$line" >&2
    else echo "[$(date +%H:%M:%S)] progress: $line" >> "$LOG" 2>/dev/null; fi
    [ "$fin" -ge "$total" ] && break
  done
  [ $tty -eq 1 ] && printf '\r\033[K' >&2
}

for LISTFILE in "${LISTS[@]}"; do
  LISTNAME=$(basename "$LISTFILE"); LISTNAME=$(safe_name "${LISTNAME%.*}")
  LISTDIR="$BASE/$LISTNAME"; [ -e "$LISTDIR" ] && LISTDIR="${LISTDIR}_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$LISTDIR" || exit 1
  LISTNAME=$(basename "$LISTDIR"); LOG="$LISTDIR/scan.log"
  unset TIP NAMES FULL EXTRA SRC URLS
  declare -A TIP NAMES FULL EXTRA SRC URLS
  KEYS=(); UNRES=()
  log "list $LISTFILE -> folder $LISTDIR"

  while IFS= read -r line <&4 || [ -n "$line" ]; do
    line="${line%%#*}"; line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$line" ] && continue
    if [[ "$line" =~ ^(https?)://([^/:?#]+)(:([0-9]+))?([/?#].*)?$ ]]; then          # URL -> folder per website host
      scheme="${BASH_REMATCH[1]}"; host="${BASH_REMATCH[2],,}"; port="${BASH_REMATCH[4]}"
      [ -z "$port" ] && { [ "$scheme" = https ] && port=443 || port=80; }
      if is_ipv4 "$host"; then rip="$host"; hname=""; else rip=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}'); hname="$host"; fi
      if [ -z "$rip" ]; then UNRES+=("$line"); log "not resolved: $line"; continue; fi
      add_target "$host" "$rip" "$hname" "$port" "$line" "$line"
      [ "$scheme" = https ] && add_target "$host" "$rip" "" "80" "$line" ""      # HTTP -> HTTPS redirect check
      [ $ALLURL -eq 1 ] && FULL[$host]=1
      continue
    fi
    if [[ "$line" == */* ]]; then                                                       # CIDR -> live hosts
      log "host discovery on range $line (nmap -sn)"
      live=$(nmap -sn -n "$line" -oG - 2>/dev/null | awk '/Status: Up/{print $2}')
      echo "$line : $(echo "$live" | grep -c .) live hosts" >> "$LISTDIR/ranges.txt"
      for h in $live; do add_target "$h" "$h" "" "" "$line" ""; done
      continue
    fi
    host="$line"; port=""
    if [[ "$line" =~ ^([^:/]+):([0-9]+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; fi
    if is_ipv4 "$host"; then add_target "$host" "$host" "" "$port" "$line" ""                # IP -> folder per IP
    else
      rip=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}')                               # hostname -> folder per IP
      if [ -n "$rip" ]; then add_target "$rip" "$rip" "$host" "$port" "$line" ""; else UNRES+=("$line"); log "not resolved: $line"; fi
    fi
  done 4< "$LISTFILE"

  log "$LISTNAME: ${#KEYS[@]} targets (${#UNRES[@]} not resolved)"
  pids=(); progress_monitor "${#KEYS[@]}" & MONPID=$!
  for key in "${KEYS[@]}"; do
    scan_target "$key" & pids+=("$!")
    while [ "$(jobs -rp | grep -vFx "$MONPID" | wc -l)" -ge "$JOBS" ]; do wait -n; done
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  kill "$MONPID" 2>/dev/null; wait "$MONPID" 2>/dev/null
  [ -t 2 ] && printf '\r\033[K' >&2

  # ---- run accounting: classify every target, build unreachable.txt / not_resolved.txt ----------
  n_scanned=0; n_noport=0; n_unreach=0; n_warn=0; : > "$LISTDIR/unreachable.txt"
  for key in "${KEYS[@]}"; do
    kd="$LISTDIR/$(safe_name "$key")/.tmp"
    [ -f "$kd/warn" ] && n_warn=$((n_warn + 1))
    case "$(cat "$kd/state.txt" 2>/dev/null)" in
      UNREACHABLE) n_unreach=$((n_unreach + 1)); cat "$kd/reinput.txt" >> "$LISTDIR/unreachable.txt" 2>/dev/null ;;
      NOPORTS)     n_noport=$((n_noport + 1)) ;;
      *)           n_scanned=$((n_scanned + 1)) ;;
    esac
  done
  [ -s "$LISTDIR/unreachable.txt" ] || rm -f "$LISTDIR/unreachable.txt"
  [ ${#UNRES[@]} -gt 0 ] && printf '%s\n' "${UNRES[@]}" > "$LISTDIR/not_resolved.txt"

  {
    echo "$BAR"
    echo " PQC SCAN SUMMARY - list: $LISTNAME  |  $(date '+%Y-%m-%d %H:%M')  |  ${#KEYS[@]} targets (one folder each)  |  input: $LISTFILE"
    echo " Scanner: $(hostname) | $NMAPVER | $OSSLVER | PQC KEX testing: $PQCAP"
    echo " Class: B = weak today, A = quantum-vulnerable (rate with Mosca), D = post-quantum, U = unknown"
    echo "$BAR"
    echo " RUN REPORT - every target accounted for:"
    echo "   Targets in list          : $(( ${#KEYS[@]} + ${#UNRES[@]} ))"
    echo "   Reachable & scanned      : $n_scanned"
    echo "   Reachable, no open ports : $n_noport"
    echo "   Unreachable / host down  : $n_unreach$([ "$n_unreach" -gt 0 ] && echo "   -> unreachable.txt  (re-run: ./pqc_scan.sh -R -i unreachable.txt)")"
    echo "   Name not resolved        : ${#UNRES[@]}$([ ${#UNRES[@]} -gt 0 ] && echo "   -> not_resolved.txt")"
    [ "$n_warn" -gt 0 ] && echo "   Scans with nmap warnings : $n_warn   (see 01_ports_services_nmap.txt in those folders)"
    echo "   Accounted for            : $(( n_scanned + n_noport + n_unreach + ${#UNRES[@]} )) of $(( ${#KEYS[@]} + ${#UNRES[@]} ))"
    echo "$BAR"
    [ -f "$LISTDIR/ranges.txt" ] && { echo " Ranges (only live hosts scanned):"; sed 's/^/   /' "$LISTDIR/ranges.txt"; }
    for key in "${KEYS[@]}"; do cat "$LISTDIR/$(safe_name "$key")/.tmp/line.txt" 2>/dev/null; done
    if [ ${#UNRES[@]} -gt 0 ]; then
      echo "--------------------------------------------------------------------------------------------------"
      echo " NOT SCANNED - name could not be resolved: ${UNRES[*]}"
    fi
  } > "$LISTDIR/00_LIST_SUMMARY.txt"
  {
    echo '"Target","IP","Hostname(s)","Port","Service","Product/Version","Encryption","Protocols","PQC Key Exchange","Key Exchange Groups/KEX","Ciphers","MACs","Certificate/Host Keys","Class","High/Medium count","PQC issues","Weaknesses","Evidence file"'
    for key in "${KEYS[@]}"; do cat "$LISTDIR/$(safe_name "$key")/.tmp/rows.csv" 2>/dev/null; done
    for u in "${UNRES[@]}"; do echo "\"$u\",\"\",\"\",\"\",\"\",\"\",\"Not scanned - name not resolved\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\",\"\""; done
  } > "$LISTDIR/summary.csv"
  for key in "${KEYS[@]}"; do rm -rf "$LISTDIR/$(safe_name "$key")/.tmp"; done
  log "finished list $LISTNAME - ${#KEYS[@]} target folders in $LISTDIR"
  ( cd "$LISTDIR" && find . -type f ! -name MANIFEST_SHA256.txt | sort | xargs -d '\n' sha256sum > MANIFEST_SHA256.txt )
done
