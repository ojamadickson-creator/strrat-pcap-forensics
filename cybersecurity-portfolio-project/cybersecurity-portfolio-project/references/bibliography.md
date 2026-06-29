# Investigation Bibliography

> Here's the thing about doing solid malware traffic analysis — you don't work in a vacuum. Every pivot, every enrichment, every conclusion I drew during this STRRAT investigation was backed by one or more of the references below. I leaned heavily on Wireshark and NetworkMiner for the bulk of my packet analysis, cross-referenced IOCs against VirusTotal and AbuseIPDB to validate my suspicions, and mapped every behavior I observed back to the MITRE ATT&CK framework to make sure my reporting was structured and actionable. This bibliography isn't just a formality — it's the paper trail that lets another analyst (or my future self) reproduce every finding from this case.

---

## Tool Documentation

These are the primary tools I used to dissect the PCAP, extract files, reconstruct sessions, and build the timeline for this investigation. If you're trying to replicate my workflow, start here.

| Reference | URL | Version Used |
|-----------|-----|-------------|
| Wireshark Official Documentation | https://www.wireshark.org/docs/ | 4.x |
| Wireshark Display Filter Reference | https://www.wireshark.org/docs/dfref/ | — |
| NetworkMiner Documentation | https://www.netresec.com/?page=NetworkMiner | 2.8+ |
| NetworkMiner User Guide (PDF) | https://www.netresec.com/?page=NetworkMinerDocumentation | — |
| TShark Command-Line Reference | https://www.wireshark.org/docs/man-pages/tshark.html | — |

### How I Used These Tools

**Wireshark** was my daily driver for this entire case. I started by loading the PCAP and applying a simple display filter (`ip.addr == 141.98.10.79`) to isolate the C2 traffic. From there, I followed the TCP streams to reconstruct the pipe-delimited protocol that STRRAT uses — that `|` character delimiter was immediately visible once I started reading the reassembled stream data. The display filter reference was indispensable when I needed to craft more specific filters, like `tcp.port == 12132 && frame.len > 200` to find larger payload exchanges. Wireshark's "Export Objects → HTTP" feature also helped me pull out the `index[1].json` artifact that the malware downloaded from `ip-api.com`.

**NetworkMiner** came in right after my initial Wireshark pass. I love using NetworkMiner as a second opinion because it automatically reconstructs sessions, extracts files, and builds a neat overview of hosts, protocols, and credentials without me having to manually dig through every packet. In this case, it quickly surfaced the DESKTOP-SKBR25F hostname and the `ccollier` username from SMB and HTTP artifacts. It also flagged the Maven Central and GitHub CDN connections as "interesting" because of the large file sizes involved.

**TShark** was my go-to when I needed to script something quickly or process the PCAP non-interactively. I used it to generate summary statistics (`tshark -r capture.pcap -q -z conv,tcp`), which gave me a bird's-eye view of the most talkative hosts and the bandwidth distribution. The command-line reference came in handy when I needed to remember the exact syntax for the `-T fields` output format combined with custom field selection (`-e ip.src -e ip.dst -e tcp.port`).

---

## Threat Intelligence & Malware Analysis

I didn't just take what I saw in the PCAP at face value. Every IP, domain, and hash got validated against at least one external intelligence source. These platforms helped me confirm whether what I was looking at was known bad, unknown, or potentially benign-but-suspicious.

| Reference | URL | Notes |
|-----------|-----|-------|
| Malware Traffic Analysis (Brad Duncan) | https://www.malware-traffic-analysis.net/ | Original exercise source — Brad Duncan's exercises are gold standard for learning |
| 2024-07-30 Traffic Analysis Exercise | https://www.malware-traffic-analysis.net/2024/07/30/index.html | This specific PCAP — the foundation of my entire investigation |
| VirusTotal | https://www.virustotal.com/ | IP/Domain/Hash lookup — used to check C2 IP and payload delivery domains |
| AbuseIPDB | https://www.abuseipdb.com/ | IP reputation check for 141.98.10.79; confirmed reports of malicious activity |
| JA3er | https://ja3er.com/ | TLS fingerprint database — checked for any TLS anomalies in the capture |

### How I Used These Sources

**Brad Duncan's Malware Traffic Analysis** is where this whole thing started. His exercises are meticulously crafted real-world scenarios, and the 2024-07-30 exercise specifically focused on STRRAT traffic. I downloaded the PCAP from his site, along with the exercise questions, which guided my initial analysis approach. What I love about Brad's exercises is that they're designed to teach — the traffic is real, the artifacts are genuine, but the scenario is structured in a way that builds your skills incrementally.

**VirusTotal** was my first stop after identifying `141.98.10.79` as the C2 IP. I punched it in and immediately saw multiple vendors flagging it as malicious, with associations to remote access trojans and suspicious hosting. I also checked `repo1.maven.org` and `objects.githubusercontent.com` — both came back clean, which was expected since they're legitimate services being abused. This distinction is critical: I'm not reporting Maven Central as malicious; I'm reporting the *abuse* of Maven Central.

**AbuseIPDB** provided additional context on the C2 IP. It had multiple user-submitted reports of scanning and malicious activity, which bolstered my confidence in flagging it as a high-confidence IOC. The community-driven nature of AbuseIPDB means you need to take individual reports with a grain of salt, but the aggregate picture was clear — this IP has a history of bad behavior.

**JA3er** was a spot-check more than anything. I wanted to see if the capture contained any TLS handshakes with unusual JA3 fingerprints that might indicate custom encryption or tunneling. In this case, STRRAT's C2 was plaintext TCP (no TLS), so JA3er didn't surface anything directly relevant — but checking it is always part of my standard workflow because you never know when malware will switch to HTTPS C2.

---

## Frameworks & Standards

Structured analysis requires structured frameworks. I used MITRE ATT&CK to categorize every behavior I observed, and CyberChef for quick data transformations when I needed to decode or manipulate artifacts on the fly.

| Reference | URL |
|-----------|-----|
| MITRE ATT&CK Framework | https://attack.mitre.org/ |
| MITRE ATT&CK — STRRAT (S0476) | https://attack.mitre.org/software/S0476/ |
| CyberChef | https://gchq.github.io/CyberChef/ |

### How I Used These Frameworks

**MITRE ATT&CK** is the backbone of my reporting structure. For every suspicious behavior in the PCAP, I asked myself: "Which ATT&CK technique does this map to?" Here's how the STRRAT activity in this case mapped out:

| Observed Behavior | MITRE Technique | Technique Name |
|-------------------|----------------|----------------|
| Malware queries ip-api.com for victim geolocation | T1590 | Gather Victim Network Information |
| Raw TCP C2 beacons to 141.98.10.79:12132 | T1071.001 | Application Layer Protocol: Web Protocols (variant) |
| Pipe-delimited custom protocol for C2 commands | T1573 | Encrypted Channel (variant — custom obfuscation) |
| Exfiltration of system info over C2 channel | T1041 | Exfiltration Over C2 Channel |
| Payload delivery via abused CDN (Maven Central) | T1105 | Ingress Tool Transfer |
| Hardcoded User-Agent to blend with legitimate traffic | T1071.001 | Application Layer Protocol: Web Protocols |

The **STRRAT-specific page (S0476)** on MITRE's site was particularly useful because it confirmed behaviors I observed but wasn't 100% sure about. For example, the pipe-delimited protocol format is documented as a known STRRAT characteristic, which validated my analysis. Seeing my observations match the official software entry gave me the confidence to label this as a confirmed STRRAT infection rather than an unknown RAT with similar behavior.

**CyberChef** is my Swiss Army knife for data manipulation. During this investigation, I used it to decode URL-encoded strings I found in HTTP traffic, convert timestamps between formats when correlating packet timestamps with log entries, and quickly hash the `index[1].json` artifact to confirm the MD5 matched what I recorded. It's also great for quickly inspecting base64-encoded data, though this particular STRRAT sample didn't seem to use base64 encoding for its C2 traffic — everything was plaintext or minimally obfuscated.

---

## Protocol & Technical References

When you're analyzing network traffic at the packet level, you need to know your protocols inside and out. These references were my go-to when I needed to verify that what I was seeing was protocol-compliant (or intentionally not).

| Reference | URL |
|-----------|-----|
| ip-api.com Documentation | https://ip-api.com/docs/ |
| Maven Central Repository | https://repo1.maven.org/ |
| RFC 793 — TCP | https://datatracker.ietf.org/doc/html/rfc793 |
| RFC 7230 — HTTP/1.1 | https://datatracker.ietf.org/doc/html/rfc7230 |

### How I Used These References

**The ip-api.com documentation** was essential for understanding the `index[1].json` artifact. When I extracted the 294-byte file from the HTTP traffic, I recognized the field names (`status`, `country`, `countryCode`, `region`, `regionName`, `city`, `zip`, `lat`, `lon`, `timezone`, `isp`, `org`, `as`, `query`) from prior experience, but I cross-referenced the official docs to confirm the schema version and field semantics. This let me definitively state that the malware was gathering the victim's city, ISP, and approximate geolocation — all useful for an adversary deciding whether a victim is worth pursuing further.

**The Maven Central documentation** helped me understand what a "normal" interaction with `repo1.maven.org` looks like. Maven Central serves Java artifacts (JARs, POMs, checksums) via a well-defined directory structure. A ~9MB download to a non-developer workstation running Windows 11 is immediately anomalous. Understanding the legitimate use case made it much easier to articulate *why* this was suspicious in my report.

**RFC 793 (TCP)** and **RFC 7230 (HTTP/1.1)** were my protocol bibles when I needed to verify whether the traffic I was seeing was structurally sound. The STRRAT C2 traffic over TCP was interesting because it used raw TCP without any application-layer protocol like HTTP — just direct socket communication with pipe-delimited messages. Comparing this against RFC 793 helped me confirm there was nothing inherently wrong with the TCP layer; the anomaly was entirely at the application layer. For the HTTP traffic (the Maven Central download and the ip-api.com query), RFC 7230 helped me verify that the request/response structures were normal HTTP/1.1 — which told me the malware was using standard HTTP libraries for those operations, not custom implementations.

---

## Additional Context

### Why These References Matter

I want to be transparent about something: this investigation could not have been done with a single tool or a single source. Packet analysis gave me the *what* — the raw bytes moving across the wire. Threat intelligence gave me the *so what* — confirmation that what I was seeing was actually malicious and not just unusual. MITRE ATT&CK gave me the *how it fits* — a structured way to describe the adversary's behavior that other analysts and defenders can act on.

If you're reading this as part of a portfolio review, hiring decision, or peer review, I'd encourage you to not just look at my conclusions but also check whether the sources I've cited actually support those conclusions. That's the whole point of including a bibliography — it makes the investigation reproducible and auditable.

### Attribution Note

This investigation is based on the **Malware Traffic Analysis Exercise** published by **Brad Duncan** on **2024-07-30**. The PCAP, exercise questions, and ground truth all originate from his platform. My analysis, IOC extraction, STIX/MISP formatting, and hunting queries are my original work built on top of that foundation. The malware family identified is **STRRAT** (MITRE S0476), and the indicators documented here are consistent with known STRRAT TTPs as of mid-2024.

---

*Bibliography compiled by Akpoga Dickson Ojama | Investigation INV-2024-STRRAT-001 | 2024-07-30*
