# Wireshark Display Filters - STRRAT Malware Investigation

> **Case:** 2024-07-30 Traffic Analysis Exercise | **Malware:** STRRAT RAT | **Analyst:** Me

I didn't start this investigation with a playbook. I started with a pcap file, a strong cup of coffee, and a creeping suspicion that something nasty was hiding in the noise. These are every single Wireshark display filter I used during the investigation, organized by the phase I was in when I wrote them. Each one tells a story about what I was thinking, what I was looking for, and what I found (or didn't find).

---

## Phase 1 - Initial Assessment: Getting the Lay of the Land

When I first cracked open the pcap, I had zero context. The goal here wasn't to find malware — it was to understand the shape of the traffic. How big is this file? How long was the capture window? What's the protocol mix? You wouldn't start a house search without knowing how many rooms there are. Same principle here.

---

### `capinfos -T -c -d -u -a -e`

**Phase:** 1.1 - File Metadata Extraction

```bash
capinfos -T -c -d -u -a -e 2024-07-30-traffic-analysis-exercise.pcap
```

**What it does:** Extracts core metadata about the pcap file in tab-delimited format: packet count (`-c`), total duration (`-d`), data rate (`-u`), start time (`-a`), and end time (`-e`).

**Results:** I got a clean summary showing 2,847 packets captured over a 31-minute window. That immediately told me this wasn't a massive multi-day capture — it was a targeted exercise with a relatively short time window. Good. Less noise to wade through.

**Why I wrote it:** This is always my first move with any pcap. Before I even open Wireshark's GUI, I want the numbers. A 31-minute capture with under 3,000 packets is totally manageable. If it had been 3 million packets over 72 hours, my approach would've been completely different — probably leaning heavily on scripted carving rather than manual Wireshark inspection.

**What the results told me:** The exercise was intentionally scoped. Someone crafted this scenario to fit a class period or a lab session. That meant the malware activity was almost certainly contained entirely within this window — no need to worry about cross-boundary beaconing or activity that started before capture began.

---

### Noise Reduction Filter

**Phase:** 1.2 - Protocol Noise Reduction

```bash
(http.request or tls.handshake.type == 1 or dns or smb or ftp or kerberos) and !(ssdp or mdns or llmnr or nbns)
```

**What it does:** Shows only "interesting" protocols — HTTP requests, TLS Client Hello handshakes, DNS queries, SMB traffic, FTP, and Kerberos — while filtering out the usual broadcast noise like SSDP discovery, mDNS, LLMNR name resolution, and NetBIOS Name Service.

**Results:** Dropped the packet count from 2,847 down to roughly 380. That is a *massive* reduction, and it's exactly what I wanted. The remaining packets were the ones most likely to reveal malicious behavior.

**Why I wrote it this way:** Look, 80% of any pcap is just your Windows machine screaming into the void. SSDP announcements, mDNS discovery, LLMNR broadcasts — it's all legitimate network chatter but it's noise when you're hunting malware. I structured this as an AND-NOT because I wanted to be inclusive of anything potentially interesting (hence the big OR list of protocols) but absolutely ruthless about cutting the garbage. The `tls.handshake.type == 1` specifically catches Client Hello packets, which is where I'd spot unusual SNI values or JA3 fingerprints.

**What the results told me:** The reduced set showed clear HTTP traffic, DNS queries, and a big blob of TCP traffic to a non-standard port. That non-standard port traffic immediately stood out as something worth investigating further. It was like clearing leaves off a trail and suddenly seeing footprints.

---

## Phase 2 - NetworkMiner Triage (Wireshark Validation)

I used NetworkMiner to get a quick visual overview — it's great for seeing host relationships at a glance. But I always validate NetworkMiner's findings in Wireshark itself. NetworkMiner can misparse things, miss subtle protocol details, or just present data in a way that misses the real story. Wireshark is the ground truth.

---

### Protocol Hierarchy Statistics

**Phase:** 2.1 - Protocol Distribution Analysis

```
Statistics > Protocol Hierarchy
```

**What it does:** Opens Wireshark's built-in Protocol Hierarchy statistics window, showing the percentage breakdown of every protocol seen in the capture — Ethernet, IP, TCP, UDP, HTTP, DNS, TLS, and everything else.

**Results:** TCP dominated at roughly 85% of all traffic. HTTP was present but minimal — maybe 15-20 packets total. DNS showed about 80 query/response pairs. The thing that jumped out: a massive chunk of "TCP" traffic wasn't associated with any higher-level protocol that Wireshark recognized. That means either encrypted/unknown protocol traffic, or custom protocol communication.

**Why I checked this:** After NetworkMiner showed me the host relationships, I needed to understand *what* these hosts were saying to each other. The Protocol Hierarchy tells you where to focus. When you see a huge blob of "unknown" or unclassified TCP, that's either benign encrypted traffic (like a custom app) or it's malicious C2. Given the exercise context, I immediately suspected the latter.

**What the results told me:** The victim host (172.16.1.66) was doing a LOT of talking on TCP to a single external IP on a weird port. Wireshark couldn't classify the application protocol, which screamed "custom C2 protocol." This was my first real breadcrumb pointing toward a RAT rather than, say, a downloader or a cryptominer.

---

### Endpoints Statistics

**Phase:** 2.2 - Host Enumeration

```
Statistics > Endpoints
```

**What it does:** Displays all unique IP addresses, MAC addresses, and ports seen in the capture, along with packet and byte counts for each.

**Results:** Four internal hosts in the 172.16.1.x range, plus two external IPs: 141.98.10.79 (significant traffic) and some minor traffic to known good destinations (ip-api.com, repo1.maven.org, GitHub). The 141.98.10.79 endpoint had 400+ packets and a huge byte count — completely disproportionate to everything else.

**Why I checked this:** NetworkMiner had already shown me the conversation graph, but I wanted Wireshark's authoritative count. Endpoints gives you the raw numbers: how many packets, how many bytes. When one external IP is responsible for 60-70% of your total capture traffic, that's not normal user browsing. That's either a file transfer or sustained C2 communication.

**What the results told me:** The victim host 172.16.1.66 had a wildly asymmetric relationship with 141.98.10.79. This wasn't a user browsing to a website — this was an automated conversation. The packet counts were consistent with beaconing behavior, not human activity.

---

### Resolved Addresses Statistics

**Phase:** 2.3 - DNS Resolution Verification

```
Statistics > Resolved Addresses
```

**What it does:** Shows Wireshark's internal DNS resolution cache — which hostnames were queried and which IP addresses they resolved to during the capture.

**Results:** The resolutions included ip-api.com, api.github.com, and repo1.maven.org — all legitimate services but an unusual combination. Crucially, 141.98.10.79 had NO associated DNS query. None. It appeared in TCP traffic without ever being resolved through DNS.

**Why I checked this:** This was actually a key insight. When you see an IP being connected to directly, with no preceding DNS lookup, there are two possibilities: the IP is hardcoded in malware, or it's connecting via a previous cached resolution. In a 31-minute capture with no earlier DNS query for that IP, hardcoded is the only logical conclusion. That's classic RAT behavior — the C2 IP is baked right into the binary.

**What the results told me:** The direct IP connection to 141.98.10.79 without DNS resolution was a strong indicator of hardcoded C2 infrastructure. Combined with the non-standard port, this was looking more and more like a classic remote access trojan setup.

---

## Phase 3 - Wireshark Deep Inspection: Finding the Smoking Gun

This is where the real work happened. I went protocol by protocol, building a mental model of what the malware was doing. Every filter here was written to answer a specific question.

---

### `http.request`

**Phase:** 3.1 - HTTP Traffic Enumeration

```bash
http.request
```

**What it does:** Shows all HTTP request packets — GET, POST, HEAD, OPTIONS, everything.

**Results:** Exactly 1 result. A single GET request from the victim to ip-api.com.

**Why I wrote it:** HTTP is where a lot of malware reveals itself — payload downloads, C2 check-ins over plaintext, exfiltration. I expected maybe a few results, but getting only ONE was actually interesting. It meant the malware wasn't using HTTP for its main C2 channel, but it *was* doing something over HTTP — likely reconnaissance.

**What the results told me:** The single HTTP request to ip-api.com was almost certainly the malware checking the victim's public IP address and geolocation. This is extremely common pre-C2 behavior — the attacker wants to know where their new implant landed. Is it a corporate network? A home ISP? What country? That information helps the operator decide how to interact with the victim.

---

### `http.request.method == "POST"`

**Phase:** 3.2 - Data Exfiltration Check

```bash
http.request.method == "POST"
```

**What it does:** Filters specifically for HTTP POST requests, which are commonly used for data exfiltration and C2 command submission.

**Results:** Zero. Absolutely nothing.

**Why I wrote it:** After seeing only one HTTP GET request, I wanted to rule out HTTP-based data exfiltration. POST requests are the primary vehicle for uploading stolen data. No POSTs meant no HTTP exfiltration in this capture window. That doesn't mean the malware *can't* exfiltrate — STRRAT absolutely can — but it didn't happen during the 31 minutes I was looking at.

**What the results told me:** The absence of POST requests reinforced that the main C2 channel wasn't HTTP-based. Whatever data exchange was happening, it was going through that weird TCP port 12132 connection instead. This was actually helpful — it narrowed my focus.

---

### `tcp.stream eq 84`

**Phase:** 3.3 - HTTP Stream Reconstruction

```bash
tcp.stream eq 84
```

**What it does:** Follows TCP stream index 84, which contained the single HTTP request to ip-api.com. This shows the complete TCP conversation including request headers and response body.

**Results:** The full HTTP conversation revealed a GET request to `http://ip-api.com/json/` with a User-Agent string showing "Chrome/73.0.3683.86" — a version of Chrome from 2019. The response contained full geolocation data: country, region, city, ISP, and the public IP address.

**Why I wrote it:** After finding just one HTTP request, I *had* to see what it actually said. Stream following is how you reconstruct the actual conversation from the packet level. I used `eq 84` because that's the stream index Wireshark assigned to this particular TCP conversation — I found it by right-clicking the HTTP packet and selecting "Follow TCP Stream."

**What the results told me:** The Chrome 73 User-Agent was a dead giveaway. Chrome 73 was released in March 2019 and is wildly outdated. No legitimate modern browser would report that version. This was either the malware's hardcoded User-Agent or a very old system. Combined with the geolocation data in the response, this confirmed the reconnaissance theory — the malware was gathering situational awareness about its victim before (or during) C2 communication.

---

### `dns.flags.response == 1`

**Phase:** 3.4 - DNS Response Enumeration

```bash
dns.flags.response == 1
```

**What it does:** Filters for DNS response packets only (not queries). The `dns.flags.response == 1` checks the QR (Query/Response) bit in the DNS flags field — 0 means query, 1 means response.

**Results:** 80 packets — meaning 80 DNS responses came back during the capture window. That implied roughly 80 DNS queries were made (though some queries may not have gotten responses within the capture window).

**Why I wrote it:** I wanted to see what domains were being resolved. DNS is often where malware reveals its infrastructure — C2 domains, payload staging sites, CDNs. By looking at responses, I could see which queries actually succeeded and got answers. I also wanted to check for DNS tunneling, which often shows up as unusual query patterns.

**What the results told me:** The 80 responses were a mix of legitimate Windows telemetry domains, some CDN lookups, and a handful of more interesting ones: ip-api.com, api.github.com, and repo1.maven.org. The volume was actually pretty normal for a Windows machine — no signs of DNS tunneling or excessive C2 domain queries. This suggested the malware wasn't using DNS for C2, which aligned with the direct IP connection I found earlier.

---

### `dns.qry.name.len > 40 and !mdns`

**Phase:** 3.5 - DNS Tunneling Detection

```bash
dns.qry.name.len > 40 and !mdns
```

**What it does:** Looks for DNS queries with unusually long query names (greater than 40 characters), which is a common indicator of DNS tunneling. The `!mdns` exclusion removes multicast DNS noise, which often has long names for service discovery.

**Results:** 22 packets initially, but on closer inspection these were all false positives. They were legitimate Windows telemetry domains, update check URLs, and some CDN hostnames that just happened to be long. No encoded data, no random subdomains, no tunneling signatures.

**Why I wrote it this way:** DNS tunneling works by encoding data in subdomain names — `encoded-data.badguy.com` — and those encoded subdomains make query names really long. The 40-character threshold is a good balance: most legitimate DNS names are under 30 characters, so 40 catches the outliers without being too noisy. The `!mdns` exclusion is critical because mDNS (multicast DNS on 224.0.0.251) constantly spams long service discovery names, and it's 100% noise in a malware investigation.

**What the results told me:** No DNS tunneling in this capture. The malware wasn't using DNS as a covert channel. This was actually useful negative evidence — it further confirmed that the C2 was happening over raw TCP on port 12132, not through any DNS-based mechanism.

---

### `dns contains "dnscat"`

**Phase:** 3.6 - DNS Tunneling Tool Detection

```bash
dns contains "dnscat"
```

**What it does:** Searches the raw DNS packet payload for the string "dnscat" — a signature associated with the dnscat2 DNS tunneling tool.

**Results:** Zero packets. Nothing at all.

**Why I wrote it:** dnscat2 is one of the most common DNS tunneling tools used by red teams and real attackers alike. It leaves distinctive markers in DNS queries. Even though my long-query-name filter didn't find tunneling, I wanted to specifically rule out dnscat2 as a tool of choice. It's a quick, targeted check that takes 2 seconds to run and either confirms or eliminates a specific threat.

**What the results told me:** Confirmed no dnscat2 usage. The negative result here was expected but still valuable — it added confidence to my assessment that DNS wasn't being abused in this particular infection.

---

### ip-api.com DNS Query Detection

**Phase:** 3.7 - Reconnaissance Domain Correlation

```bash
dns.qry.name contains "myip" or dns.qry.name contains "whatismyip" or dns.qry.name contains "ip-api"
```

**What it does:** Searches DNS queries for any domain containing "myip", "whatismyip", or "ip-api" — all common public IP/geolocation checking services that malware frequently queries during initial infection.

**Results:** 2 packets — both related to ip-api.com. One query, one response.

**Why I wrote it this way:** Malware almost always wants to know where it landed. IP checking services are the reconnaissance phase of most infections. I used `contains` instead of `==` because I wanted to catch variations — subdomains, different TLDs, related services. "myip" catches myip.com, myip.dnsomatic.com, and similar. "whatismyip" catches whatismyipaddress.com and variants. "ip-api" catches ip-api.com and any subdomains.

**What the results told me:** The victim made exactly one DNS query for ip-api.com and then made the HTTP GET request I found earlier. This was a clear two-step reconnaissance pattern: resolve the domain, then query the API. It's textbook malware behavior — establish your situational awareness before calling home to the C2 server.

---

### `ftp`

**Phase:** 3.8 - File Transfer Protocol Check

```bash
ftp
```

**What it does:** Shows all FTP (File Transfer Protocol) traffic — both control channel (port 21) and data channel.

**Results:** Zero packets. No FTP traffic at all.

**Why I wrote it:** FTP is an old but still occasionally used protocol for payload staging and data exfiltration. Some malware families drop payloads via FTP, especially in targeted attacks where the attacker controls an FTP server. It's a quick check — one word filter — and it either finds something interesting or eliminates a whole category of potential behavior.

**What the results told me:** No FTP activity in this capture. The payload download I suspected was happening over HTTPS, not FTP. This was consistent with the modern STRRAT behavior I observed — it pulls payloads from legitimate-looking sources (Maven, GitHub) rather than sketchy FTP servers.

---

### Outbound SYN Enumeration

**Phase:** 3.9 - Outbound Connection Mapping

```bash
tcp.flags == 0x002 and ip.src == 172.16.1.66
```

**What it does:** Shows all TCP SYN packets (the first packet in any TCP handshake, flag value 0x002) sent *from* the victim host (172.16.1.66). This reveals every outbound connection attempt initiated by the victim.

**Results:** 149 SYN packets from the victim. That's a lot of outbound connection attempts in 31 minutes. Most were to standard ports (443 for HTTPS, 53 for DNS over TCP), but one stood out: a single SYN to port 12132 on 141.98.10.79.

**Why I wrote it this way:** The `tcp.flags == 0x002` is the precise Wireshark syntax for SYN-only packets (binary 00000010). I could have used `tcp.flags.syn == 1 and tcp.flags.ack == 0` which is more readable, but `0x002` is shorter and I type it from muscle memory. The `ip.src == 172.16.1.66` constrains it to outbound-only, which is what I care about for malware detection — I'm looking for what the victim initiated, not what it responded to.

**What the results told me:** 148 of the 149 SYN packets went to well-known ports on recognizable IPs — Google, Microsoft, CDN networks. But that one SYN to 141.98.10.79:12132... that was the anomaly. Port 12132 isn't registered to any standard service. It's not HTTP, HTTPS, DNS, SSH, or anything normal. One SYN to a non-standard port on an external IP is often the first sign of C2 beaconing. I immediately followed up on this lead.

---

### C2 Target Verification

**Phase:** 3.10 - C2 Connection Confirmation

```bash
ip.dst == 141.98.10.79 and tcp.flags.syn == 1
```

**What it does:** Shows only SYN packets sent specifically to the suspicious external IP 141.98.10.79.

**Results:** 1 SYN packet. Just one. But that one SYN initiated a TCP conversation that lasted for hundreds of packets.

**Why I wrote it:** After finding the lone SYN to port 12132 in my outbound SYN filter, I wanted to zoom in. Was this a one-time connection attempt, or the start of an ongoing conversation? By filtering for any SYN to this specific IP, regardless of port, I could see if there were multiple connection attempts to different ports — a common behavior when malware tries to find an open C2 port.

**What the results told me:** Only one SYN to this IP, and it was on port 12132. That told me the malware knew exactly where to connect — it wasn't port-scanning or trying fallback ports. The C2 IP and port were hardcoded. This was the start of a sustained C2 session, not a probe.

---

### `tcp.port == 12132`

**Phase:** 3.11 - C2 Channel Full Reconstruction

```bash
tcp.port == 12132
```

**What it does:** Filters for ALL TCP traffic on port 12132 — both directions, all packets, all flags.

**Results:** 411 packets. *This was the money shot.*

Every single one of those 411 packets was between the victim (172.16.1.66) and the C2 server (141.98.10.79:12132). And here's the pattern that made it unmistakable: every packet had PSH (Push) and ACK (Acknowledge) flags set. No SYNs after the initial handshake, no RSTs, no connection teardown during the capture. Just a steady stream of PSH, ACK packets flowing back and forth.

**Why I wrote it:** After finding a single SYN to port 12132 in the outbound SYN filter, I needed to see the full C2 conversation. This filter revealed the complete beaconing pattern — [PSH, ACK] flags on every packet, consistent data push behavior. This was the definitive filter that exposed the C2 channel.

**What the results told me:** STRRAT uses a custom TCP protocol, not HTTP/TLS. Every packet had PSH+ACK flags indicating active data exchange. The volume (411 packets) showed sustained C2 communication throughout the capture window. The consistent flag pattern — PSH+ACK on both directions — is characteristic of a protocol that's constantly pushing small chunks of data. In STRRAT's case, this is the RAT's command-and-control channel: the attacker sending commands, the victim sending responses, all in a continuous stream. The lack of any standard protocol encapsulation (no HTTP headers, no TLS records) meant Wireshark couldn't dissect it at the application layer. That's intentional — it makes the traffic harder to detect with signature-based tools.

---

## Phase 4 - Cross-Validation: Making Sure I Didn't Miss Anything

At this point I was 95% sure I had a STRRAT infection. But good analysis means checking your blind spots. I went back and validated against alternative hypotheses. What if this was a legitimate remote admin tool? What if there was lateral movement I missed? What if the payload came from somewhere else?

---

### `smb or smb2`

**Phase:** 4.1 - Lateral Movement Check

```bash
smb or smb2
```

**What it does:** Shows all SMB (Server Message Block) and SMB2 traffic — the protocols used for Windows file sharing, named pipes, and lateral movement tools like PsExec.

**Results:** SMB traffic was present but only to the domain controller (172.16.1.10). Normal authentication and group policy traffic. Zero SMB connections to non-DC hosts. No named pipe anomalies, no suspicious file transfers, no PsExec signatures.

**Why I wrote it:** SMB is the primary protocol for Windows lateral movement. If the malware was spreading to other machines on the network, I'd see SMB connections from the victim to other internal hosts. STRRAT *can* move laterally, but in this capture there was no evidence of it. The SMB traffic I did see was standard domain member behavior — authenticating to the DC, pulling group policy.

**What the results told me:** No lateral movement in this capture window. The infection appeared contained to the single victim host (172.16.1.66). This was a single compromised workstation scenario, not an active network-wide intrusion. That distinction matters for containment strategy — you isolate one host, not the whole segment.

---

### Payload Download Detection (Negative Result)

**Phase:** 4.2 - HTTP Payload Download Check

```bash
http.request.uri matches "(?i)[.](exe|dll|bat|ps1|vbs|js|jar|dat|cab|msi)$"
```

**What it does:** Searches HTTP request URIs for common executable or script file extensions — .exe, .dll, .bat, .ps1, .vbs, .js, .jar, .dat, .cab, .msi. The `(?i)` makes it case-insensitive.

**Results:** Zero matches. Nothing downloaded over HTTP during the capture.

**Why I wrote it this way:** A lot of malware downloads secondary payloads over plain HTTP. It's fast, it works through most proxies, and it's easy to implement. I used a regex with `matches` because I wanted to catch any of these common extensions, and the `(?i)` flag ensures I catch `.EXE`, `.Exe`, `.eXe`, etc. The extensions I chose cover the most common malware delivery vectors: executables (.exe, .dll), scripts (.bat, .ps1, .vbs, .js), Java archives (.jar — relevant for STRRAT), installers (.msi, .cab), and generic payloads (.dat).

**What the results told me:** The payload download (if it happened in this window) wasn't over plain HTTP. Given the large HTTPS transfer I saw to repo1.maven.org, the payload was almost certainly delivered over TLS. This is a smart operational security choice by the attacker — TLS encrypts the payload in transit, making it invisible to passive network monitoring and bypassing most network-level DLP controls. It also means you need SSL inspection on your proxy to detect this kind of download, which a lot of organizations don't have.

---

## Quick Reference Card

| Filter | Phase | Purpose | Results |
|--------|-------|---------|---------|
| `capinfos -T -c -d -u -a -e` | 1.1 | File metadata | 2,847 pkts, 31 min window |
| `(http.request or tls.handshake.type == 1 or dns or smb or ftp or kerberos) and !(ssdp or mdns or llmnr or nbns)` | 1.2 | Noise reduction | ~380 packets (87% reduction) |
| Statistics > Protocol Hierarchy | 2.1 | Protocol mix | TCP 85%, unknown app protocol blob |
| Statistics > Endpoints | 2.2 | Host enumeration | 4 internal hosts, 2 external IPs |
| Statistics > Resolved Addresses | 2.3 | DNS resolution | 141.98.10.79 had NO DNS query |
| `http.request` | 3.1 | HTTP enumeration | 1 result (ip-api.com) |
| `http.request.method == "POST"` | 3.2 | Exfiltration check | 0 results |
| `tcp.stream eq 84` | 3.3 | HTTP stream follow | Chrome 73 UA, geolocation response |
| `dns.flags.response == 1` | 3.4 | DNS responses | 80 packets |
| `dns.qry.name.len > 40 and !mdns` | 3.5 | DNS tunneling detection | 22 packets (false positives) |
| `dns contains "dnscat"` | 3.6 | dnscat2 detection | 0 results |
| `dns.qry.name contains "myip" or dns.qry.name contains "whatismyip" or dns.qry.name contains "ip-api"` | 3.7 | Reconnaissance check | 2 packets |
| `ftp` | 3.8 | File transfer check | 0 results |
| `tcp.flags == 0x002 and ip.src == 172.16.1.66` | 3.9 | Outbound SYNs | 149 SYNs |
| `ip.dst == 141.98.10.79 and tcp.flags.syn == 1` | 3.10 | C2 SYN confirm | 1 SYN to port 12132 |
| `tcp.port == 12132` | 3.11 | C2 full stream | 411 packets (THE money shot) |
| `smb or smb2` | 4.1 | Lateral movement | 0 suspicious |
| `http.request.uri matches "(?i)[.](exe\|dll\|bat\|ps1\|vbs\|js\|jar\|dat\|cab\|msi)$"` | 4.2 | Payload download | 0 results (TLS-encrypted) |

---

*Every filter tells a story. The negative results matter just as much as the positives — they eliminate hypotheses and narrow the investigation. The 411 packets on port 12132 were the thread that, when pulled, unraveled the whole infection narrative.*
