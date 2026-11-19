# pqc_scan.sh v2 - README

PQC (post-quantum cryptography) discovery scanner for Kali Linux, command line only.
You give it one or more list files (IPs, ranges, hostnames, URLs). For every target it
collects the cryptography that can be seen on the network and writes everything to text
files: one folder per list, one folder per IP or website, one file per crypto area.

It only performs normal connections, TLS/SSH handshakes and banner reads.
No exploitation, no password guessing. Scan only targets that are in the signed scope.


-----------------------------------------------------------------------------------------
## 1. Quick start
-----------------------------------------------------------------------------------------

    chmod +x pqc_scan.sh
    sudo ./pqc_scan.sh -i serverip.txt -i switchip.txt -i applications.txt

Result (in the folder you ran it from):

    serverip/        one folder per server IP
    switchip/        one folder per switch IP
    applications/    one folder per website / URL host

Start reading at `<list>/00_LIST_SUMMARY.txt`, then open the target's `00_SUMMARY.txt`.


-----------------------------------------------------------------------------------------
## 2. Requirements
-----------------------------------------------------------------------------------------

Required (all present on a standard Kali):

    nmap, openssl, curl, timeout, awk, bash

Optional (used automatically when installed):

    ssh-audit     extra SSH algorithm analysis        (apt install ssh-audit)
    ike-scan      VPN / IPsec check on UDP 500        (apt install ike-scan)
    testssl.sh    very detailed TLS report, with -t   (apt install testssl.sh)

Check before you start:

    openssl version      # must be 3.5 or newer to test post-quantum (ML-KEM) key exchange
    nmap --version
    id -u                # 0 = root. Use sudo for OS detection and the VPN check

If openssl is older than 3.5 the scan still works, but PQC key exchange shows
"NOT TESTED". A newer openssl elsewhere on the box can be used with:

    sudo OPENSSL_BIN=/opt/openssl-3.5/bin/openssl ./pqc_scan.sh -i serverip.txt


-----------------------------------------------------------------------------------------
## 3. Putting the script on the Kali box (copy-paste only)
-----------------------------------------------------------------------------------------

    cat > pqc_scan.sh <<'PQC_EOF'
    ...paste the whole script here...
    PQC_EOF
    chmod +x pqc_scan.sh

Check that the paste is complete:

    wc -l pqc_scan.sh      # 689
    md5sum pqc_scan.sh     # 38e7c2a5793e997ecfa78df56e3fc79c

If the numbers differ, part of the paste was lost - paste again.
If you see  $'\r': command not found  the file has Windows line endings. Fix once with:

    sed -i 's/\r$//' pqc_scan.sh


-----------------------------------------------------------------------------------------
## 4. Preparing the list files
-----------------------------------------------------------------------------------------

One entry per line. Lines starting with # and text after # are ignored.
The file name becomes the output folder name (serverip.txt -> serverip/).

serverip.txt

    # application and database servers
    10.10.1.5
    10.10.1.6
    db01.corp.local          # hostname: resolved to its IP, also used as TLS SNI name
    10.10.1.9:8443           # only add/scan this extra port for that IP

switchip.txt

    # network devices
    10.20.0.1
    10.20.5.0/24             # range: only hosts that answer a ping sweep are scanned

applications.txt

    # web applications and APIs
    https://portal.client.com/login
    https://portal.client.com/api/health      # same website -> same folder
    https://api.client.com:8443/
    http://10.10.1.20:8080/

How entries are grouped:

| Entry type                  | Folder name          | What is scanned                              |
|-----------------------------|----------------------|----------------------------------------------|
| IP                          | the IP               | top 1000 TCP ports (or -p)                   |
| hostname                    | the IP it resolves to| same as IP, TLS tested with the hostname     |
| ip:port                     | the IP               | that port (added to the IP's scan)           |
| range (CIDR)                | each live IP         | live hosts only, same as IP                  |
| URL (http:// or https://)   | the website host     | the URL's port + port 80 (all ports with -A) |

The same IP or website listed several times is merged into ONE folder.
Names that cannot be resolved get no folder; they are listed as "NOT SCANNED" in
00_LIST_SUMMARY.txt and summary.csv.


-----------------------------------------------------------------------------------------
## 5. Options
-----------------------------------------------------------------------------------------

    -i <file>   list file. Repeat for several lists:  -i a.txt -i b.txt -i c.txt
    -o <dir>    base folder where list folders are created   (default: current folder)
    -p <ports>  nmap ports for IP entries, e.g.  -p 1-65535  or  -p 22,443,8443
                (default: nmap top 1000 TCP ports)
    -A          for URL entries, also scan all services of that host
                (default: only the URL's port and 80)
    -j <n>      targets scanned in parallel                   (default 4)
    -t          also run testssl.sh on every TLS port          (much slower)
    -n          skip the UDP 500 IKE / VPN check
    -T <sec>    timeout per handshake                          (default 8)

Examples:

    # all three lists, defaults
    sudo ./pqc_scan.sh -i serverip.txt -i switchip.txt -i applications.txt

    # critical servers: every TCP port, 2 at a time, output under /root/pqc
    sudo ./pqc_scan.sh -i critical.txt -p 1-65535 -j 2 -o /root/pqc

    # applications, including every service running on those hosts
    sudo ./pqc_scan.sh -i applications.txt -A

    # slow WAN link: longer timeout, fewer parallel targets
    sudo ./pqc_scan.sh -i branches.txt -T 20 -j 2

If a list folder already exists (for example serverip/), the new run goes to
serverip_<date_time>/ so earlier results are never overwritten.

Long scans: run inside tmux or screen so a dropped session does not stop the scan:

    tmux new -s pqc
    sudo ./pqc_scan.sh -i serverip.txt
    (detach: Ctrl-b then d      re-attach later: tmux attach -t pqc)


-----------------------------------------------------------------------------------------
## 6. What is collected
-----------------------------------------------------------------------------------------

| Area                 | What the script collects                                         | Tool                     |
|----------------------|------------------------------------------------------------------|--------------------------|
| Ports and services   | open TCP ports, service name and version, OS guess (root)        | nmap -sV -O              |
| TLS                  | SSL 3.0 to TLS 1.3 support, every accepted cipher suite, grade   | nmap ssl-enum-ciphers    |
| TLS key exchange     | each group tested: X25519MLKEM768 and other ML-KEM hybrids,      | openssl s_client         |
|                      | X25519, P-256/384/521, ffdhe; server preference when PQC offered |                          |
| Certificates         | full chain: key type and size, signature, expiry, SAN, issuer,   | openssl x509             |
|                      | fingerprint; PEM files saved                                     |                          |
| STARTTLS             | SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL             | openssl -starttls        |
| HTTP(S)              | response headers, redirect chain, HSTS, per URL path             | curl                     |
| SSH                  | key exchange (incl. mlkem768x25519, sntrup761), host keys,       | nmap ssh2-enum-algos,    |
|                      | ciphers, MACs, Terrapin check                                    | ssh-audit                |
| RDP                  | Standard RDP Security (RC4) accepted?, NLA enforced?             | built-in RDP probe       |
| SMB                  | SMB dialects (SMBv1), signing                                    | nmap smb scripts         |
| VNC                  | security types (none / DES password / TLS)                       | nmap vnc-info            |
| VPN / IPsec          | IKEv1 and IKEv2 proposal: encryption, hash, DH group (root)      | ike-scan                 |
| Other ports          | cleartext services (telnet, ftp, http...), services whose        | nmap, banner             |
|                      | encryption is not visible on the network, unknown services       |                          |


-----------------------------------------------------------------------------------------
## 7. Output files
-----------------------------------------------------------------------------------------

    <list>/
      00_LIST_SUMMARY.txt          every target of this list, readiness + issues per port
      summary.csv                  one row per target and port (open in Excel)
      scan.log                     timestamped run log
      ranges.txt                   live-host count per range (only if ranges were used)
      MANIFEST_SHA256.txt          SHA-256 of every file (evidence integrity)
      <ip or website>/
        00_SUMMARY.txt             PQC readiness, per-port summary, index of files
        01_ports_services_nmap.txt full nmap output for all ports
        10_tls_<port>.txt          TLS: handshake, versions, ciphers, key exchange incl. ML-KEM
        10_tls_<port>_handshake_failed.txt   TLS port where no handshake completed
        11_certificates_<port>.txt certificate chain decoded
        12_http_<port>.txt         HTTP(S) headers, redirects, HSTS
        13_tls_wrapped_<port>_<svc>.txt      TLS inside another protocol (seen by nmap)
        14_testssl_<port>.txt      testssl.sh output (only with -t)
        20_ssh_<port>.txt          SSH algorithms (+ ssh-audit)
        30_rdp_<port>.txt          RDP security negotiation
        31_smb_<port>.txt          SMB dialects and signing
        32_vnc_<port>.txt          VNC security types
        40_other_<port>_<svc>.txt  cleartext / not observable / unknown service
        50_ike_udp500.txt          VPN / IPsec check (root only)
        certs/<port>_certN.pem     certificate files as sent by the server

Every port file starts with a short header (encryption, protocols, PQC key exchange,
class, issues). Below it is the raw evidence: the nmap output for that port, then every
openssl test with the exact command that was run.


-----------------------------------------------------------------------------------------
## 8. Reading the results
-----------------------------------------------------------------------------------------

Class (per port):

    B   weak or broken today: SSL 3.0 / TLS 1.0 / 1.1, RC4, 3DES, NULL ciphers, SHA-1 or
        MD5 signatures, RSA < 2048, static RSA key exchange, weak SSH algorithms,
        cleartext service
    A   quantum-vulnerable: RSA, ECDHE, ECDSA, EdDSA, DH. Fine today, broken by a future
        quantum computer. Rate with Mosca: X (years data must stay secret) +
        Y (years to migrate) compared with Z (years until a quantum computer)
    D   post-quantum: ML-KEM hybrid key exchange (and ML-DSA certificates)
    U   unknown or not visible on the network - confirm with the owner

Issue tags:

    [High] [Medium] [Low]   weakness that exists today, indicative severity
    [PQC]                   quantum-vulnerable cryptography (rate with Mosca)
    [Info]                  note or positive finding (e.g. PQC supported)

PQC READINESS (per target):

    QUANTUM-SAFE as observed     PQC key exchange and no quantum-vulnerable keys anywhere
    PQC key exchange on ALL      key exchange protected, certificates / host keys classical
    MIXED                        PQC key exchange on some encrypted services only
    NOT quantum-safe             classical key exchange only
    NOT DETERMINED               scanner openssl < 3.5, ML-KEM could not be tested
    No encryption in use         only cleartext services found
    Not assessed                 no open ports (host down, filtered or closed)

Useful commands on the Kali box:

    less serverip/00_LIST_SUMMARY.txt               # whole list
    less serverip/10.10.1.5/00_SUMMARY.txt           # one target
    grep -rh "PQC READINESS" serverip/*/00_SUMMARY.txt | sort | uniq -c
    grep -rl "\[High\]" serverip/*/ | sort           # files with High issues
    grep -h "PQC-KEX: YES" -r serverip/              # ports that support ML-KEM

Getting results out (copy-paste only): `cat` the file and copy it from the terminal.
The smallest useful files to copy out are 00_LIST_SUMMARY.txt and summary.csv.

Proving the evidence was not changed after the scan:

    cd serverip && sha256sum -c MANIFEST_SHA256.txt


-----------------------------------------------------------------------------------------
## 9. How long it takes
-----------------------------------------------------------------------------------------

Rough guide only - it depends on the network, firewalls and how many TLS ports exist:

    per host, top 1000 ports      about 1 to 3 minutes for the port scan
    per TLS port                  about 30 to 60 seconds of handshake tests
    100 IPs with -j 4             roughly 1 to 2 hours
    -p 1-65535                    several times longer - use it for critical hosts only

Hosts behind firewalls that drop packets are the slowest. Raise -j carefully: more
parallel targets means more load on the client network.


-----------------------------------------------------------------------------------------
## 10. Troubleshooting
-----------------------------------------------------------------------------------------

| Problem                                   | Cause / fix                                                    |
|-------------------------------------------|----------------------------------------------------------------|
| "PQC KEX testing: NO" in the log          | openssl older than 3.5. Use OPENSSL_BIN=/path/to/newer/openssl |
| "not root" in the log                     | run with sudo (needed for OS detection and VPN check)          |
| Host shows "Not assessed - no open ports" | host down, firewall, or not reachable from the Kali box        |
| "TLS (handshake failed)"                  | server needs a client certificate, a specific hostname (put    |
|                                           | the hostname or URL in the list), or algorithms the scanner    |
|                                           | lacks - ask the owner                                          |
| Only the default certificate is seen      | one IP serves several websites: list the URLs in               |
|                                           | applications.txt so each is tested with its own name           |
| SSH host keys "see nmap output"           | nmap could not read the host keys; check 20_ssh_<port>.txt     |
|                                           | and the ssh-audit section                                      |
| Scan stops when the session drops         | run inside tmux or screen (section 5)                          |
| $'\r': command not found                  | Windows line endings: sed -i 's/\r$//' pqc_scan.sh             |
| "missing required tool"                   | install it: sudo apt install nmap curl                         |


-----------------------------------------------------------------------------------------
## 11. Limits (state these in the report)
-----------------------------------------------------------------------------------------

- Network view only. Data-at-rest encryption, crypto inside application code, HSM / KMS
  keys, internal PKI and similar must come from the client (see the information
  request list).
- Only what the Kali box can reach. Zones behind firewalls need a scan from inside them.
- TCP ports plus the UDP 500 VPN check. QUIC, DTLS, SNMPv3 and other UDP services are
  not covered.
- A load balancer, WAF or CDN shows its own crypto, not the back-end server's.
- ML-KEM cannot be tested inside RDP or MSSQL; those ports are marked "not testable".
- The VPN check sees only the first proposal. An ML-KEM add-on for IKEv2 (RFC 9370)
  is only visible in the VPN configuration.
