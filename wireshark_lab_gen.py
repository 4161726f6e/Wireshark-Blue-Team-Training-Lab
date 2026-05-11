#!/usr/bin/env python3
"""
PCAP-only blue-team lab generator (seeded variants).

Generates:
- enterprise_attack.pcap (enterprise noise + 1 successful chain + 3 failed chains)
- ctfd_challenges.txt (Wireshark step-by-step challenge descriptions)
- ctfd_hints.txt (tiered hints with costs)
- instructor_answers.txt (answers + points)
- validation_report.txt (PASS/FAIL per question)
- metadata.json (repro config)

Key features:
- --seed produces unique answers per run, while investigation steps remain identical
- --duration spreads traffic across a realistic capture timeline
- --stealth adds deceptive lookalike traffic (decoy bulk TLS, decoy POSTs) while keeping answers unambiguous
- Validation parses the PCAP directly and confirms each answer is present and uniquely derivable

Dependencies:
  pip install scapy

Usage examples:
  python generate_pcap_only_lab.py --seed 100 --noise high --duration 3600 --output lab_100
  python generate_pcap_only_lab.py --seed 101 --noise high --duration 3600 --stealth --output lab_101_stealth
"""

import argparse
import json
import os
import random
import struct
import time
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, wrpcap, rdpcap, RandShort

# ----------------------------
# Templates / constants
# ----------------------------
COMMON_SNI_DOMAINS = [
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "teams.microsoft.com",
    "outlook.office.com",
    "www.google.com",
    "www.youtube.com",
    "cdn.jsdelivr.net",
    "api.github.com",
    "assets.adobe.com",
    "update.googleapis.com",
]

PHISH_DOMAIN_TEMPLATES = [
    "secure-{brand}-login.com",
    "{brand}-auth-portal.com",
    "{brand}-sso-verify.com",
    "account-{brand}-secure.com",
]
BRANDS = ["login365", "microsoft", "office", "signin", "auth", "idp"]

URI_TEMPLATES = [
    "/auth/login",
    "/signin/submit",
    "/account/validate",
    "/session/create",
    "/login/confirm",
]

PAYLOAD_DOMAIN_TEMPLATES = [
    "cdn-{noun}-check.com",
    "{noun}-cdn-updates.com",
    "assets-{noun}-delivery.com",
    "cdn-{noun}-static.com",
]
NOUNS = ["update", "patch", "sync", "verify", "delivery", "telemetry"]

PAYLOAD_FILES = [
    "update.exe",
    "patcher.exe",
    "security_fix.exe",
    "chrome_update.exe",
    "teams_installer.exe",
    "vpn_update.exe",
]

FAILED_DOMAIN_TEMPLATES = [
    "cdn-{noun}-upgrade.net",
    "{noun}-security-check.net",
    "ms-{noun}-verify.net",
    "{noun}-delivery-hub.net",
]

POINTS = [25, 25, 40, 50, 50, 60, 60, 70, 60, 60]


# ----------------------------
# Utility helpers
# ----------------------------
def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def ts_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def pick_ip(rng, subnet_prefix, lo, hi, avoid=None):
    avoid = avoid or set()
    while True:
        last = rng.randint(lo, hi)
        ip = f"{subnet_prefix}{last}"
        if ip not in avoid:
            return ip

def rand_public_ip(rng):
    return f"{rng.randint(23, 200)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"

def set_pkt_time(pkt, base_epoch, offset_seconds):
    pkt.time = float(base_epoch + offset_seconds)
    return pkt

def _u16(x): return struct.pack("!H", x)
def _u24(x): return x.to_bytes(3, "big")

def randbytes(rng, n):
    # Deterministic bytes from RNG (stable across platforms)
    return bytes(rng.getrandbits(8) for _ in range(n))


# ----------------------------
# Raw TLS builders (NO scapy.layers.tls)
# ----------------------------
def tls_record(content_type: int, version_bytes: bytes, payload: bytes) -> bytes:
    # TLS record header: type(1) + version(2) + length(2)
    return bytes([content_type]) + version_bytes + _u16(len(payload)) + payload

def build_tls_client_hello_with_sni(server_name: str, rng: random.Random) -> bytes:
    """
    Build a minimal TLS ClientHello (TLS 1.2) containing a plaintext SNI extension.
    Wireshark will dissect:
      - tls.handshake.type == 1
      - tls.handshake.extensions_server_name
    """
    sni_host = server_name.encode("utf-8")

    # ClientHello body
    legacy_version = b"\x03\x03"  # TLS 1.2 in ClientHello
    random_bytes = randbytes(rng, 32)

    session_id = randbytes(rng, rng.randint(8, 24))
    session_id_len = bytes([len(session_id)])

    # A small cipher list (enough for Wireshark to parse)
    cipher_suites = b"\x13\x01\x13\x02\xc0\x2f"  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256-ish
    cipher_suites_len = _u16(len(cipher_suites))

    compression_methods = b"\x01\x00"  # len=1, method=null

    # SNI extension (type 0x0000)
    # ServerNameList: list_len(2) + name_type(1=0) + name_len(2) + name
    server_name_list = _u16(1 + 2 + len(sni_host)) + b"\x00" + _u16(len(sni_host)) + sni_host
    sni_ext = _u16(0x0000) + _u16(len(server_name_list)) + server_name_list

    # Padding extension (type 0x0015) to vary sizes and look realistic
    pad_len = rng.randint(12, 64)
    padding_ext = _u16(0x0015) + _u16(pad_len) + (b"\x00" * pad_len)

    extensions = sni_ext + padding_ext
    extensions_len = _u16(len(extensions))

    client_hello_body = (
        legacy_version +
        random_bytes +
        session_id_len + session_id +
        cipher_suites_len + cipher_suites +
        compression_methods +
        extensions_len + extensions
    )

    # Handshake header: type(1)=ClientHello, length(3)
    handshake = b"\x01" + _u24(len(client_hello_body)) + client_hello_body

    # Record header: type(0x16 handshake), version(0x0301 for compatibility), length
    # (Wireshark happily dissects ClientHello with record version 0x0301 or 0x0303)
    return tls_record(0x16, b"\x03\x01", handshake)

def build_tls_appdata(rng: random.Random, size: int) -> bytes:
    """
    TLS ApplicationData record (opaque). Wireshark labels as TLS even without keys.
    """
    payload = randbytes(rng, size)
    return tls_record(0x17, b"\x03\x03", payload)


# ----------------------------
# Other packet builders
# ----------------------------
def make_dns_query(src_ip, qname, dns_server="8.8.8.8"):
    return IP(src=src_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))

def make_http_req(src_ip, dst_ip, method, host, uri, body=b""):
    lines = [
        f"{method} {uri} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0",
        "Accept: */*",
        "Connection: keep-alive",
    ]
    if body:
        lines.append(f"Content-Length: {len(body)}")
        lines.append("Content-Type: application/x-www-form-urlencoded")
    payload = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=80, flags="PA") / Raw(load=payload)

def make_http_resp(src_ip, dst_ip, status_code=200, content_type="application/octet-stream", body=b""):
    reason = {200: "OK", 404: "Not Found", 403: "Forbidden"}.get(status_code, "OK")
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: keep-alive",
    ]
    payload = ("\r\n".join(headers) + "\r\n\r\n").encode() + body
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=80, dport=RandShort(), flags="PA") / Raw(load=payload)

def make_tls_client_hello_pkt(src_ip, dst_ip, sni, rng):
    data = build_tls_client_hello_with_sni(sni, rng)
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=443, flags="PA") / Raw(load=data)

def make_tls_appdata_pkt(src_ip, dst_ip, rng, size):
    data = build_tls_appdata(rng, size)
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=443, flags="PA") / Raw(load=data)

def make_smb2_like(src_ip, dst_ip, size=300):
    # Synthetic SMB2-ish header: FE 'SMB' to support smb2 / tcp.port==445 pivots in Wireshark.
    header = b"\xfeSMB" + bytes([0x00]) * 60
    body = bytes([0x42]) * max(0, size - len(header))
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=445, flags="PA") / Raw(load=header + body)


# ----------------------------
# Scenario builder (seeded)
# ----------------------------
def build_scenario(seed: int):
    rng = random.Random(seed)

    internal_prefix = "10.0.1."
    server_prefix = "10.0.2."
    avoid = set()

    compromised = pick_ip(rng, internal_prefix, 20, 80, avoid=avoid); avoid.add(compromised)
    internal_noise_hosts = [pick_ip(rng, internal_prefix, 10, 110, avoid=avoid) for _ in range(14)]
    avoid |= set(internal_noise_hosts)

    lateral_target = pick_ip(rng, server_prefix, 10, 60, avoid=set())

    c2_ip = rand_public_ip(rng)
    exfil_ip = rand_public_ip(rng)
    payload_ip = rand_public_ip(rng)
    phish_ip = rand_public_ip(rng)

    brand = rng.choice(BRANDS)
    phish_domain = rng.choice(PHISH_DOMAIN_TEMPLATES).format(brand=brand)
    credential_uri = rng.choice(URI_TEMPLATES)

    noun = rng.choice(NOUNS)
    payload_domain = rng.choice(PAYLOAD_DOMAIN_TEMPLATES).format(noun=noun)
    payload_file = rng.choice(PAYLOAD_FILES)

    failed_domain_q9 = rng.choice(FAILED_DOMAIN_TEMPLATES).format(noun=rng.choice(NOUNS))
    failed1_domain = rng.choice(FAILED_DOMAIN_TEMPLATES).format(noun=rng.choice(NOUNS))  # DNS-only
    failed2_domain = rng.choice(FAILED_DOMAIN_TEMPLATES).format(noun=rng.choice(NOUNS))  # HTTP 404
    failed3_target = pick_ip(rng, server_prefix, 61, 99, avoid=set())                    # SMB attempt no follow-on

    decoy_bulk_ip = rand_public_ip(rng)
    decoy_bulk_sni = f"backup-{rng.choice(NOUNS)}-sync.example"
    decoy_post_host = f"auth-{rng.choice(BRANDS)}-portal.example"

    return {
        "seed": seed,
        "nets": {"internal": internal_prefix, "server": server_prefix},
        "compromised": compromised,
        "internal_noise_hosts": internal_noise_hosts,
        "lateral_target": lateral_target,
        "c2_ip": c2_ip,
        "exfil_ip": exfil_ip,
        "payload_ip": payload_ip,
        "phish_ip": phish_ip,
        "phish_domain": phish_domain,
        "credential_uri": credential_uri,
        "payload_domain": payload_domain,
        "payload_file": payload_file,
        "failed_domain_q9": failed_domain_q9,
        "failed1_domain": failed1_domain,
        "failed2_domain": failed2_domain,
        "failed3_target": failed3_target,
        "protocol_exfil": "tls",
        "decoys": {
            "decoy_bulk_ip": decoy_bulk_ip,
            "decoy_bulk_sni": decoy_bulk_sni,
            "decoy_post_host": decoy_post_host,
        }
    }


def build_answers(scn: dict):
    return {
        "Q1": f"ip:{scn['compromised']}",
        "Q2": f"domain:{scn['phish_domain']}",
        "Q3": f"uri:{scn['credential_uri']}",
        "Q4": f"ip:{scn['c2_ip']}",
        "Q5": f"domain:{scn['payload_domain']}",
        "Q6": f"file:{scn['payload_file']}",
        "Q7": f"ip:{scn['lateral_target']}",
        "Q8": f"ip:{scn['exfil_ip']}",
        "Q9": f"domain:{scn['failed_domain_q9']}",
        "Q10": f"proto:{scn['protocol_exfil']}",
    }


# ----------------------------
# CTFd materials writers
# ----------------------------
def write_instructor_answers(path, answers):
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, 11):
            q = f"Q{i}"
            f.write(f"{q}: {answers[q]} ({POINTS[i-1]} pts)\n")

def write_ctfd_challenges(path):
    descs = {
        1: """Which internal host was compromised during this capture?

Flag format: ip:x.x.x.x

Wireshark guide:
1) Open the PCAP.
2) Apply a web filter: http (or tcp.port == 80 if needed).
3) Statistics → Endpoints → IPv4; check “Limit to display filter”.
4) Identify the internal IP that dominates suspicious web traffic.
5) Cross-check via Statistics → Conversations (TCP) to confirm it is central to suspicious web conversations.""",
        2: """Which domain was used for the initial phishing attempt?

Flag format: domain:example.com

Wireshark guide:
1) Filter DNS: dns
2) Show queries only: dns.flags.response == 0
3) Pivot to the compromised host (from Q1): ip.src == <compromised>
4) Inspect dns.qry.name and identify the rare, login-like domain associated with the start of the successful chain.""",
        3: """What URI path was used to submit credentials?

Flag format: uri:/path

Wireshark guide:
1) Filter HTTP POSTs: http.request.method == "POST"
2) Narrow to the compromised host if needed: ip.src == <compromised>
3) Select the relevant POST and use Follow → TCP Stream.
4) Extract the URI path from the request line (between method and HTTP version).""",
        4: """What external IP acted as the command-and-control server?

Flag format: ip:x.x.x.x

Wireshark guide:
1) Filter to the compromised host’s TCP traffic: ip.addr == <compromised> && tcp
2) Statistics → Conversations (TCP). Sort by packets/duration.
3) Identify repeated outbound communications (beacon-like).
4) Validate by isolating the stream and confirming repeated traffic to the same external IP.""",
        5: """What domain hosted the payload downloaded by the attacker?

Flag format: domain:example.com

Wireshark guide:
1) Filter TLS ClientHello: tls.handshake.type == 1
2) Locate the handshake associated with the payload stage (after initial compromise/beaconing).
3) Inspect TLS → Extensions → server_name (SNI).
4) Extract the hostname from SNI (domain only).""",
        6: """What file was downloaded by the attacker?

Flag format: file:filename.ext

Wireshark guide:
1) Filter HTTP GET: http.request.method == "GET"
2) Correlate to suspicious host activity.
3) Use File → Export Objects → HTTP to list objects transferred.
4) Identify the suspicious executable-like filename requested/downloaded.""",
        7: """Which internal system was targeted via lateral movement?

Flag format: ip:x.x.x.x

Wireshark guide:
1) Filter SMB-related traffic: tcp.port == 445 (or smb2)
2) Narrow to traffic initiated by the compromised host: ip.src == <compromised>
3) Use Statistics → Conversations (TCP) to identify the internal destination contacted on 445.""",
        8: """Which external IP received exfiltrated data?

Flag format: ip:x.x.x.x

Wireshark guide:
1) Filter to the compromised host: ip.addr == <compromised>
2) Statistics → Conversations (TCP/IPv4). Sort by Bytes.
3) Identify the largest sustained outbound transfer to an external IP.
4) Optionally confirm with I/O Graphs (Bits/s) filtered to that conversation.""",
        9: """Which suspicious domain appears in DNS but did NOT lead to a successful attack chain?

Flag format: domain:example.com

Wireshark guide:
1) Filter DNS queries: dns.flags.response == 0
2) Identify suspicious domains.
3) For a candidate domain, verify there is no meaningful follow-on (no payload download, no beaconing, no lateral movement).
4) Use Find Packet (Ctrl+F) string search to locate the domain quickly, then validate lack of progression.""",
        10: """What protocol was used for data exfiltration?

Flag format: proto:protocol

Wireshark guide:
1) Filter the exfil conversation: ip.addr == <compromised> && ip.addr == <exfil IP>
2) Statistics → Protocol Hierarchy to identify dominant protocol in the filtered flow.
3) Confirm via the Protocol column and packet details within the exfil stream.""",
    }

    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, 11):
            f.write(f"Challenge {i} (Points {POINTS[i-1]}):\n")
            f.write(descs[i].strip() + "\n")
            f.write("\n" + ("-" * 70) + "\n\n")

def write_ctfd_hints(path):
    hints = {
        "Q1": [(5,"Start with HTTP filtering, then use Statistics → Endpoints (IPv4) with 'Limit to display filter'."),
               (10,"Compare Endpoints and Conversations (TCP) to find the central suspicious internal talker."),
               (15,"The compromised host is the only one performing the phishing POST. Use that as a uniqueness check.")],
        "Q2": [(5,"Pivot to DNS queries from the compromised host; phishing domains are rare and login-like."),
               (10,"Use dns.flags.response==0 and inspect dns.qry.name values."),
               (15,"Look for the domain queried immediately before the credential POST begins.")],
        "Q3": [(5,"Credential submission is typically an HTTP POST."),
               (10,"Filter POSTs and Follow → TCP Stream to view the request line."),
               (15,"Extract the URI path between the method and HTTP version.")],
        "Q4": [(5,"Beaconing often looks like repeated outbound TLS-sized blobs to one external IP."),
               (10,"Use Conversations sorted by packets/duration to find repeatable external comms."),
               (15,"Confirm the same internal host repeatedly contacts the same external IP on 443.")],
        "Q5": [(5,"SNI is visible in ClientHello and is not encrypted."),
               (10,"Filter tls.handshake.type==1 and inspect Server Name extension."),
               (15,"Use tls.handshake.extensions_server_name to extract the payload host.")],
        "Q6": [(5,"Payloads often show up as HTTP GET requests for executable-looking paths."),
               (10,"Use File → Export Objects → HTTP to view extracted filenames."),
               (15,"Focus on the GETs to the payload host and pick the executable-like filename.")],
        "Q7": [(5,"Lateral movement commonly uses SMB on TCP/445."),
               (10,"Filter tcp.port==445 and isolate traffic initiated by the compromised host."),
               (15,"Use Conversations under that filter to identify the internal destination.")],
        "Q8": [(5,"Exfiltration often appears as the largest sustained outbound transfer."),
               (10,"Use Conversations sorted by bytes from the compromised host."),
               (15,"There is a decoy bulk transfer in stealth mode; the real exfil is still the largest from the compromised host.")],
        "Q9": [(5,"A failed chain can have DNS activity with no follow-on sessions."),
               (10,"Find a suspicious domain in DNS not followed by HTTP/TLS sessions."),
               (15,"Use Find Packet string search to locate the domain, then verify no progression.")],
        "Q10":[(5,"Determine protocol from evidence in the exfil flow."),
               (10,"Filter the exfil conversation and check Protocol Hierarchy."),
               (15,"The exfil stream uses TLS record types; confirm via TLS dissection in Wireshark.")],
    }

    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, 11):
            q = f"Q{i}"
            f.write(f"{q} Hints:\n")
            for cost, text in hints[q]:
                f.write(f"  - Cost {cost}: {text}\n")
            f.write("\n")


# ----------------------------
# PCAP generation (seed/noise/duration/stealth)
# ----------------------------
def generate_pcap(scn: dict, noise: str, duration: int, stealth: bool):
    rng = random.Random(scn["seed"] ^ 0xA5A5A5)
    base_epoch = time.time()

    # Noise scaling
    if noise == "low":
        tls_sessions = 250
        dns_queries = 180
        http_noise = 60
        exfil_chunks = 70
    elif noise == "high":
        tls_sessions = 2000
        dns_queries = 1200
        http_noise = 260
        exfil_chunks = 220
    else:
        tls_sessions = 900
        dns_queries = 600
        http_noise = 140
        exfil_chunks = 120

    # Stealth increases noise + adds decoys
    if stealth:
        http_noise += 160
        tls_sessions += 400
        dns_queries += 250
        decoy_bulk_chunks = max(40, exfil_chunks - 30)  # keep real exfil larger
        c2_count = 14
    else:
        decoy_bulk_chunks = 0
        c2_count = 18

    pkts = []

    # Avoid accidentally using scenario-specific domains in noise
    avoid_domains = {scn["phish_domain"], scn["payload_domain"], scn["failed_domain_q9"]}

    # TLS enterprise noise: ClientHello+SNI then appdata
    for _ in range(tls_sessions):
        src = rng.choice(scn["internal_noise_hosts"])
        dst = rand_public_ip(rng)
        sni = rng.choice([d for d in COMMON_SNI_DOMAINS if d not in avoid_domains])
        t = rng.randint(0, max(1, duration - 1))
        pkts.append(set_pkt_time(make_tls_client_hello_pkt(src, dst, sni, rng), base_epoch, t))
        pkts.append(set_pkt_time(make_tls_appdata_pkt(src, dst, rng, size=rng.randint(200, 1400)), base_epoch, min(duration-1, t + rng.randint(0, 3))))

    # DNS noise
    for _ in range(dns_queries):
        src = rng.choice(scn["internal_noise_hosts"])
        q = rng.choice([d for d in COMMON_SNI_DOMAINS if d not in avoid_domains] + ["cdn.cloudflare.com", "edge.microsoft.com", "ocsp.digicert.com"])
        t = rng.randint(0, max(1, duration - 1))
        pkts.append(set_pkt_time(make_dns_query(src, q), base_epoch, t))

    # HTTP noise (plaintext)
    for _ in range(http_noise):
        src = rng.choice(scn["internal_noise_hosts"])
        dst = rand_public_ip(rng)
        host = rng.choice(["intranet.corp.local", "api.internal.local", "status.vendor.com", "example.com", scn["decoys"]["decoy_post_host"]])
        if host in avoid_domains:
            host = "example.com"
        uri = rng.choice(["/", "/health", "/api/v1/me", "/static/app.js", "/favicon.ico", "/signin/submit", "/auth/login", "/session/create"])
        method = rng.choice(["GET", "POST"])
        body = b"" if method == "GET" else b"user=test&pass=test"
        t = rng.randint(0, max(1, duration - 1))
        pkts.append(set_pkt_time(make_http_req(src, dst, method, host, uri, body=body), base_epoch, t))

    # ==========================
    # Successful chain scheduled mid-capture
    # ==========================
    compromised = scn["compromised"]
    start = duration // 3
    step = max(2, duration // 40)

    # A) Phish DNS (Q2)
    pkts.append(set_pkt_time(make_dns_query(compromised, scn["phish_domain"]), base_epoch, start))

    # B) Credential POST (Q3) — uniqueness for Q1 validation
    body = b"username=jdoe%40corp.com&password=Summer2026!"
    pkts.append(set_pkt_time(make_http_req(compromised, scn["phish_ip"], "POST", scn["phish_domain"], scn["credential_uri"], body=body),
                             base_epoch, start + step))

    # C) C2 beaconing (Q4) — TLS appdata blobs
    pkts.append(set_pkt_time(make_tls_client_hello_pkt(compromised, scn["c2_ip"], "cdn-secure-sync.net", rng),
                             base_epoch, start + 2*step))
    for i in range(c2_count):
        jitter = rng.randint(0, 2) if stealth else 0
        size = rng.randint(220, 620) if stealth else rng.randint(240, 520)
        pkts.append(set_pkt_time(make_tls_appdata_pkt(compromised, scn["c2_ip"], rng, size=size),
                                 base_epoch, start + 2*step + i + jitter))

    # D) Payload stage: TLS ClientHello SNI (Q5)
    pkts.append(set_pkt_time(make_tls_client_hello_pkt(compromised, scn["payload_ip"], scn["payload_domain"], rng),
                             base_epoch, start + 6*step))

    # E) Payload download over HTTP (Q6)
    get_uri = f"/{scn['payload_file']}"
    pkts.append(set_pkt_time(make_http_req(compromised, scn["payload_ip"], "GET", scn["payload_domain"], get_uri),
                             base_epoch, start + 7*step))
    file_blob = (b"MZ" + bytes([0x90]) * 1200 + b"THIS_IS_SYNTHETIC_PAYLOAD")
    pkts.append(set_pkt_time(make_http_resp(scn["payload_ip"], compromised, status_code=200, content_type="application/octet-stream", body=file_blob),
                             base_epoch, start + 7*step + 1))

    # F) Lateral SMB (Q7)
    for j in range(6):
        pkts.append(set_pkt_time(make_smb2_like(compromised, scn["lateral_target"], size=600),
                                 base_epoch, start + 9*step + j))

    # G) Exfil TLS to exfil_ip (Q8/Q10)
    pkts.append(set_pkt_time(make_tls_client_hello_pkt(compromised, scn["exfil_ip"], "files-cdn-sync.example", rng),
                             base_epoch, start + 12*step))
    for k in range(exfil_chunks):
        pkts.append(set_pkt_time(make_tls_appdata_pkt(compromised, scn["exfil_ip"], rng, size=rng.randint(1800, 4200)),
                                 base_epoch, min(duration-1, start + 12*step + 1 + (k // 3))))

    # Stealth decoy: bulk TLS transfer close to exfil but smaller
    if stealth and decoy_bulk_chunks > 0:
        decoy_src = rng.choice(scn["internal_noise_hosts"])
        decoy_ip = scn["decoys"]["decoy_bulk_ip"]
        decoy_sni = scn["decoys"]["decoy_bulk_sni"]
        t0 = start + 11*step
        pkts.append(set_pkt_time(make_tls_client_hello_pkt(decoy_src, decoy_ip, decoy_sni, rng), base_epoch, t0))
        for k in range(decoy_bulk_chunks):
            pkts.append(set_pkt_time(make_tls_appdata_pkt(decoy_src, decoy_ip, rng, size=rng.randint(1600, 3400)),
                                     base_epoch, min(duration-1, t0 + 1 + (k // 4))))

    # ==========================
    # Failed chains (different failure points)
    # ==========================
    # Failed 1: DNS-only suspicious domain (no follow-on)
    t_fail1 = rng.randint(0, max(1, duration - 1))
    pkts.append(set_pkt_time(make_dns_query(rng.choice(scn["internal_noise_hosts"]), scn["failed1_domain"]), base_epoch, t_fail1))

    # Failed 2: HTTP GET attempt but 404 (blocked at payload stage)
    fail2_src = rng.choice(scn["internal_noise_hosts"])
    fail2_ip = rand_public_ip(rng)
    t_fail2 = rng.randint(0, max(1, duration - 3))
    pkts.append(set_pkt_time(make_dns_query(fail2_src, scn["failed2_domain"]), base_epoch, t_fail2))
    pkts.append(set_pkt_time(make_http_req(fail2_src, fail2_ip, "GET", scn["failed2_domain"], "/dropper.exe"), base_epoch, t_fail2 + 1))
    pkts.append(set_pkt_time(make_http_resp(fail2_ip, fail2_src, status_code=404, content_type="text/html", body=b"<html>not found</html>"),
                             base_epoch, t_fail2 + 2))

    # Failed 3: single SMB attempt with no sustained activity (fails at lateral movement)
    fail3_src = rng.choice(scn["internal_noise_hosts"])
    t_fail3 = rng.randint(0, max(1, duration - 1))
    pkts.append(set_pkt_time(make_smb2_like(fail3_src, scn["failed3_target"], size=240), base_epoch, t_fail3))

    # Q9 domain: suspicious DNS only, intentionally no follow-on
    t_q9 = rng.randint(0, max(1, duration - 1))
    pkts.append(set_pkt_time(make_dns_query(rng.choice(scn["internal_noise_hosts"]), scn["failed_domain_q9"]), base_epoch, t_q9))

    # Shuffle
    rng.shuffle(pkts)
    return pkts


# ----------------------------
# Validation (no TLS layer dependency)
# ----------------------------
def extract_dns_queries(pcap):
    out = []
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(DNS) and p[DNS].qd is not None:
            qname = p[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            out.append((p[IP].src, qname))
    return out

def extract_http_requests(pcap):
    reqs = []
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 80:
            data = bytes(p[Raw].load)
            if data.startswith(b"GET ") or data.startswith(b"POST "):
                line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
                parts = line.split()
                if len(parts) < 2:
                    continue
                method, uri = parts[0], parts[1]
                host = None
                for h in data.split(b"\r\n"):
                    if h.lower().startswith(b"host:"):
                        host = h.split(b":", 1)[1].strip().decode(errors="ignore")
                        break
                reqs.append((p[IP].src, p[IP].dst, method, host, uri))
    return reqs

def extract_sni_from_tls_client_hello_bytes(buf: bytes):
    """
    Tiny TLS ClientHello+SNI parser for our synthetic records.
    Returns server_name string if found else None.
    """
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return None
        rec_len = int.from_bytes(buf[3:5], "big")
        hs = buf[5:5+rec_len]
        if len(hs) < 4 or hs[0] != 0x01:
            return None
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4:4+hs_len]
        if len(body) < 42:
            return None

        # version(2) + random(32)
        i = 2 + 32

        # session_id
        sid_len = body[i]
        i += 1 + sid_len

        # cipher suites
        cs_len = int.from_bytes(body[i:i+2], "big")
        i += 2 + cs_len

        # compression
        comp_len = body[i]
        i += 1 + comp_len

        # extensions
        ext_total = int.from_bytes(body[i:i+2], "big")
        i += 2
        exts = body[i:i+ext_total]

        j = 0
        while j + 4 <= len(exts):
            et = int.from_bytes(exts[j:j+2], "big")
            el = int.from_bytes(exts[j+2:j+4], "big")
            data = exts[j+4:j+4+el]
            if et == 0x0000 and len(data) >= 5:
                # list_len(2), name_type(1), name_len(2), name
                if data[2] == 0x00:
                    nlen = int.from_bytes(data[3:5], "big")
                    return data[5:5+nlen].decode("utf-8", errors="ignore")
            j += 4 + el
        return None
    except Exception:
        return None

def extract_all_sni_from_pcap(pcap):
    snis = []
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 443:
            sni = extract_sni_from_tls_client_hello_bytes(bytes(p[Raw].load))
            if sni:
                snis.append((p[IP].src, p[IP].dst, sni))
    return snis

def extract_tcp_bytes_by_pair(pcap):
    bytes_by_pair = defaultdict(int)
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(TCP):
            bytes_by_pair[(p[IP].src, p[IP].dst)] += len(p)
    return bytes_by_pair

def run_validation(out_dir, scn, expected_answers):
    pcap_path = os.path.join(out_dir, "enterprise_attack.pcap")
    pcap = rdpcap(pcap_path)

    report = []
    ok_all = True

    dns_q = extract_dns_queries(pcap)
    dns_domains = [q for _, q in dns_q]

    http_reqs = extract_http_requests(pcap)
    snis = extract_all_sni_from_pcap(pcap)
    sni_names = [s for _, _, s in snis]

    bytes_by_pair = extract_tcp_bytes_by_pair(pcap)

    # Q1: unique host that POSTs to phishing domain
    phish_domain = scn["phish_domain"]
    post_hosts = set([src for (src, dst, method, host, uri) in http_reqs
                      if method == "POST" and host == phish_domain])

    q1_expected_ip = expected_answers["Q1"].split(":", 1)[1]
    q1_ok = (q1_expected_ip in post_hosts and len(post_hosts) == 1)
    report.append(f"Q1: {'PASS' if q1_ok else 'FAIL'} - unique POST-to-phish host (hosts={len(post_hosts)})")
    ok_all &= q1_ok

    # Q2: phishing domain appears in DNS
    q2_expected = expected_answers["Q2"].split(":", 1)[1]
    q2_ok = q2_expected in dns_domains
    report.append(f"Q2: {'PASS' if q2_ok else 'FAIL'} - phishing domain in DNS queries")
    ok_all &= q2_ok

    # Q3: credential URI present in POST to phishing host
    q3_expected = expected_answers["Q3"].split(":", 1)[1]
    q3_ok = any((method == "POST" and host == phish_domain and uri == q3_expected)
                for (src, dst, method, host, uri) in http_reqs)
    report.append(f"Q3: {'PASS' if q3_ok else 'FAIL'} - credential POST URI present")
    ok_all &= q3_ok

    # Q4: repeated 443 traffic to C2 from compromised (appdata records)
    c2_ip = expected_answers["Q4"].split(":", 1)[1]
    c2_hits = 0
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 443:
            if p[IP].src == q1_expected_ip and p[IP].dst == c2_ip:
                # TLS record types 0x16 / 0x17
                b0 = bytes(p[Raw].load)[:1]
                if b0 in (b"\x16", b"\x17"):
                    c2_hits += 1
    q4_ok = c2_hits >= 8
    report.append(f"Q4: {'PASS' if q4_ok else 'FAIL'} - C2 TLS-record packets >= 8 (got {c2_hits})")
    ok_all &= q4_ok

    # Q5: payload domain in SNI list
    q5_expected = expected_answers["Q5"].split(":", 1)[1]
    q5_ok = q5_expected in sni_names
    report.append(f"Q5: {'PASS' if q5_ok else 'FAIL'} - payload domain appears in TLS SNI")
    ok_all &= q5_ok

    # Q6: payload file requested via HTTP GET on payload host
    payload_domain = scn["payload_domain"]
    payload_file = expected_answers["Q6"].split(":", 1)[1]
    q6_ok = any((method == "GET" and host == payload_domain and uri.endswith('/' + payload_file))
                for (src, dst, method, host, uri) in http_reqs)
    report.append(f"Q6: {'PASS' if q6_ok else 'FAIL'} - payload file requested via HTTP GET")
    ok_all &= q6_ok

    # Q7: SMB/445 from compromised to lateral target exists
    lateral = expected_answers["Q7"].split(":", 1)[1]
    smb_hits = 0
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(TCP) and p[TCP].dport == 445:
            if p[IP].src == q1_expected_ip and p[IP].dst == lateral:
                smb_hits += 1
    q7_ok = smb_hits >= 1
    report.append(f"Q7: {'PASS' if q7_ok else 'FAIL'} - SMB/445 packets to lateral target (got {smb_hits})")
    ok_all &= q7_ok

    # Q8: exfil IP is top bytes destination from compromised
    exfil = expected_answers["Q8"].split(":", 1)[1]
    bytes_to_dst = defaultdict(int)
    for (a, b), blen in bytes_by_pair.items():
        if a == q1_expected_ip:
            bytes_to_dst[b] += blen
    top_dst = max(bytes_to_dst.items(), key=lambda x: x[1])[0] if bytes_to_dst else None
    q8_ok = (top_dst == exfil)
    report.append(f"Q8: {'PASS' if q8_ok else 'FAIL'} - exfil dst is top bytes destination (top={top_dst})")
    ok_all &= q8_ok

    # Q9: failed domain appears in DNS but not in HTTP Host or TLS SNI
    q9_expected = expected_answers["Q9"].split(":", 1)[1]
    q9_dns_ok = q9_expected in dns_domains
    q9_http_follow = any(host == q9_expected for (_, _, _, host, _) in http_reqs if host)
    q9_tls_follow = any(name == q9_expected for name in sni_names)
    q9_ok = q9_dns_ok and (not q9_http_follow) and (not q9_tls_follow)
    report.append(f"Q9: {'PASS' if q9_ok else 'FAIL'} - DNS-only suspicious domain (no HTTP/TLS follow-on)")
    ok_all &= q9_ok

    # Q10: protocol used for exfil is TLS (record types present on 443 between compromised and exfil)
    proto_expected = expected_answers["Q10"].split(":", 1)[1].lower()
    tls_between = 0
    for p in pcap:
        if p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 443:
            if p[IP].src == q1_expected_ip and p[IP].dst == exfil:
                b0 = bytes(p[Raw].load)[:1]
                if b0 in (b"\x16", b"\x17"):
                    tls_between += 1
    q10_ok = (proto_expected == "tls") and tls_between >= 3
    report.append(f"Q10: {'PASS' if q10_ok else 'FAIL'} - TLS-record packets between compromised and exfil (got {tls_between})")
    ok_all &= q10_ok

    with open(os.path.join(out_dir, "validation_report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")
        f.write(f"\nOVERALL: {'PASS' if ok_all else 'FAIL'}\n")

    if not ok_all:
        raise SystemExit("Validation failed. See validation_report.txt for details.")
    return True


# ----------------------------
# Main
# ----------------------------
def main():
    ap = argparse.ArgumentParser(description="Seeded PCAP-only lab generator with validation (no Scapy TLS layer)")
    ap.add_argument("--seed", type=int, required=True, help="Seed value (unique lab per seed)")
    ap.add_argument("--output", default=None, help="Output directory (default: lab_<seed>)")
    ap.add_argument("--noise", choices=["low", "medium", "high"], default="medium", help="Noise volume in PCAP")
    ap.add_argument("--duration", type=int, default=1800, help="Capture duration in seconds (default: 1800)")
    ap.add_argument("--stealth", action="store_true", help="Increase ambiguity with decoys while keeping steps intact")
    args = ap.parse_args()

    out_dir = args.output or f"lab_{args.seed}"
    ensure_dir(out_dir)

    scn = build_scenario(args.seed)
    answers = build_answers(scn)

    pkts = generate_pcap(scn, args.noise, args.duration, args.stealth)
    pcap_path = os.path.join(out_dir, "enterprise_attack.pcap")
    wrpcap(pcap_path, pkts)

    write_ctfd_challenges(os.path.join(out_dir, "ctfd_challenges.txt"))
    write_ctfd_hints(os.path.join(out_dir, "ctfd_hints.txt"))
    write_instructor_answers(os.path.join(out_dir, "instructor_answers.txt"), answers)

    meta = {
        "generated_at": ts_now(),
        "seed": args.seed,
        "noise": args.noise,
        "duration_seconds": args.duration,
        "stealth": args.stealth,
        "scenario": scn,
        "answers": answers,
        "points": {f"Q{i}": POINTS[i-1] for i in range(1, 11)},
        "requires": {
            "python": "3.9+",
            "scapy": "latest",
            "scapy_tls_layer": False
        }
    }
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    run_validation(out_dir, scn, answers)

    print("✅ Lab generated successfully")
    print(f"Output directory: {out_dir}")
    print(f"PCAP: {pcap_path}")
    print("Validation: PASS (see validation_report.txt)")
    print("Instructor answers: instructor_answers.txt")
    print("CTFd descriptions: ctfd_challenges.txt")
    print("Hints: ctfd_hints.txt")

if __name__ == "__main__":
    main()