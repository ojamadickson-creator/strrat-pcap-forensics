# STRRAT PCAP Investigation

![NetworkMiner](https://img.shields.io/badge/NetworkMiner-2.8+-blue?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHJlY3Qgd2lkdGg9IjE2IiBoZWlnaHQ9IjE2IiBmaWxsPSIjMDA3OENDIi8+PC9zdmc+)
![Wireshark](https://img.shields.io/badge/Wireshark-4.x-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Malware](https://img.shields.io/badge/Malware-STRRAT-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Completed-success?style=flat-square)

---

Hey there. I'm **Akpoga Dickson Ojama**, a cybersecurity analyst and SOC analyst. This project documents a full network forensic investigation I performed on a malicious PCAP file containing **STRRAT** traffic -- a Java-based Remote Access Trojan that's been around since 2020 and keeps evolving. I built this as a portfolio piece to show my end-to-end investigation workflow, from initial triage through deep packet inspection to IOC extraction and MITRE ATT&CK mapping. If you're a hiring manager, fellow analyst, or just curious about malware traffic analysis, this one's for you.

---

## Project Overview

Here's what we're working with:

| Attribute | Details |
|-----------|---------|
| **PCAP File** | `2024-07-30-traffic-analysis-exercise.pcap` |
| **SHA256** | `C48854C24223CF7B4E9880EA72A21A877E4138E4CE36DF7B7656E5C6C4043F68` |
| **Malware Family** | STRRAT (Java-based RAT) |
| **Total Packets** | 11,562 |
| **Capture Duration** | ~9 minutes 45 seconds |
| **Victim IP** | `172.16.1.66` (hostname: `DESKTOP-SKBR25F`) |
| **Victim User** | `ccollier` |
| **C2 Server** | `141.98.10.79:12132` (Lithuanian IP, hardcoded in malware config) |
| **Investigation Date** | July 30, 2024 |

STRRAT is a nasty piece of work. It's written in Java, communicates over custom TCP protocols, and gives an attacker full remote control over a victim machine -- file management, keylogging, credential theft, the works. What's particularly interesting about this sample is how the C2 communication exposes itself if you know what to look for. The hardcoded Lithuanian IP and the distinctive port `12132` are dead giveaways once you've seen STRRAT before.

I followed a **NetworkMiner-first triage pipeline** for this investigation. Here's why: when you're staring at 11,000+ packets, you don't want to dive into Wireshark blind. NetworkMiner gives you the 30,000-foot view -- hosts, protocols, files, credentials, the whole picture -- in under a minute. From there, you pivot into Wireshark for the deep stuff. It's a workflow that's saved me hours, and it's the one I document here.

---

## Table of Contents

The full investigation report lives in [`PROJECT_REPORT.md`](./PROJECT_REPORT.md). Here's where to find everything:

- [Executive Summary](./PROJECT_REPORT.md#executive-summary) -- The tl;dr of the entire investigation
- [Objective / Scenario](./PROJECT_REPORT.md#objective--scenario) -- What I was asked to figure out
- [Tools Used](./PROJECT_REPORT.md#tools-used) -- Everything in my toolkit for this one
- [Phase 1: Initial PCAP Assessment](./PROJECT_REPORT.md#phase-1-initial-pcap-assessment) -- First look with `capinfos`, getting the lay of the land
- [Phase 2: NetworkMiner Rapid Triage](./PROJECT_REPORT.md#phase-2-networkminer-rapid-triage) -- The triage pipeline that found the smoking gun
- [Phase 3: Wireshark Deep Packet Inspection](./PROJECT_REPORT.md#phase-3-wireshark-deep-packet-inspection) -- Following TCP streams, dissecting C2 traffic
- [Phase 4: Cross-Validation & Correlation](./PROJECT_REPORT.md#phase-4-cross-validation--correlation) -- Connecting the dots across tools
- [Findings / IOCs](./PROJECT_REPORT.md#findings--iocs) -- Every indicator of compromise I pulled out
- [MITRE ATT&CK Mapping](./PROJECT_REPORT.md#mitre-attck-mapping) -- Mapping tactics and techniques to the framework
- [References](./PROJECT_REPORT.md#references) -- Sources, research, and further reading

---

## Folder Structure

```
cybersecurity-portfolio-project/
├── README.md                           # You're reading it
├── PROJECT_REPORT.md                   # The full investigation narrative
├── assets/
│   └── screenshots/                    # Visual evidence from each phase
├── queries/
│   ├── wireshark_display_filters.md    # Every filter I used in Wireshark
│   ├── splunk_queries.md             # Splunk SPL for threat hunting
│   └── yara_rules.md                 # YARA rules for STRRAT detection
├── iocs/
│   └── indicators_of_compromise.md    # Network, host, and file IOCs
├── evidence/                           # Raw artifacts and extracted files
└── references/
    └── bibliography.md               # Sources and research papers
```

Pretty straightforward. I like keeping investigations organized this way because when someone (or future-me) needs to pick this up six months later, everything has a home. No hunting through random directories for that one screenshot you *know* you saved somewhere.

---

## How to Use This Project

So you've downloaded this repo. Here's how I'd recommend working through it:

1. **Start with the full narrative.** Open [`PROJECT_REPORT.md`](./PROJECT_REPORT.md) and read it top to bottom. I wrote it as a chronological walkthrough of the investigation, so it reads like a story. You'll see my thought process at each stage -- including the dead ends and wrong turns, because those are just as valuable as the wins.

2. **Check the queries.** The [`queries/`](./queries/) directory has every Wireshark display filter I used, plus Splunk searches and YARA rules. If you're doing a similar investigation, these are copy-paste ready. I've commented each one so you know what it's looking for and why.

3. **Grab the IOCs.** [`iocs/indicators_of_compromise.md`](./iocs/indicators_of_compromise.md) has everything network defenders need: IPs, ports, hostnames, file hashes, registry keys, the lot. Feed these into your SIEM, firewall, or threat intel platform.

4. **Browse the screenshots.** [`assets/screenshots/`](./assets/screenshots/) has visual evidence from each phase of the investigation. Great if you want to see what NetworkMiner and Wireshark outputs look like for this kind of traffic without running the PCAP yourself.

5. **Run the PCAP yourself.** If you've got the file (hash listed above), fire up NetworkMiner and Wireshark and follow along. There's no substitute for hands-on practice, and this report gives you a roadmap.

---

## Tools & Technologies

Here's what I used and why:

| Tool | Purpose |
|------|---------|
| **NetworkMiner 2.8+** | NFAT (Network Forensic Analysis Tool) for rapid triage. This was my first stop -- it parsed the PCAP in seconds and gave me the host list, protocol breakdown, and extracted files. The credential extraction alone was worth it. |
| **Wireshark 4.x+** | Deep packet inspection. Once NetworkMiner pointed me at the interesting traffic, Wireshark let me follow TCP streams, dissect the C2 protocol, and pull out the gritty details. |
| **capinfos** | Part of the Wireshark suite. I always run this first on any PCAP -- it gives you capture duration, packet count, average rate, and file hashes. Takes two seconds and tells you a lot about what you're dealing with. |
| **VirusTotal** | Hash lookups and reputation checking for extracted files and network indicators. Quick way to validate whether something is known-bad. |
| **CyberChef** | The "Swiss Army Knife" of cybersecurity. I used it for decoding, deobfuscating, and transforming data I pulled from packet payloads. If you haven't used CyberChef yet, you're missing out. |
| **AbuseIPDB** | IP reputation lookups. The C2 IP (`141.98.10.79`) had prior abuse reports, which helped confirm its malicious nature. |

I didn't use any fancy commercial tools for this one. Everything here is either free and open-source or has a free tier. You don't need a six-figure budget to do good forensics -- you need the right methodology and the patience to follow it.

---

## Key Findings Summary

Here are the five biggest things I found:

- **The victim host `DESKTOP-SKBR25F` (172.16.1.66, user `ccollier`) was compromised by STRRAT**, a Java-based Remote Access Trojan. The infection was active during the entire ~9:45 capture window, with continuous C2 communication throughout.

- **The C2 server at `141.98.10.79:12132` is a hardcoded Lithuanian IP** embedded in the STRRAT configuration. This IP has prior abuse reports on AbuseIPDB and was communicating with the victim via a custom TCP protocol on port 12132 -- not a standard port, which makes it easier to spot in network traffic.

- **The malware exfiltrated system information during the initial C2 handshake**, including the hostname, username, and system details. This is classic STRRAT behavior -- it fingerprints the victim before enabling full remote control.

- **NetworkMiner's credential extraction recovered authentication artifacts** from the traffic, and the protocol analysis immediately surfaced the suspicious C2 communication pattern. This validated the NetworkMiner-first approach -- triage in minutes, not hours.

- **The entire attack chain maps cleanly to MITRE ATT&CK**, covering initial access (via malware delivery, though the delivery vector is outside this PCAP's scope), command and control (custom C2 protocol over TCP/12132), discovery (system information discovery), and collection (data from local system). The full mapping is in [`PROJECT_REPORT.md`](./PROJECT_REPORT.md).

---

## A Quick Note on Methodology

I want to talk about the NetworkMiner-first approach for a second, because it's the backbone of this investigation and it's something I genuinely believe in.

A lot of analysts (myself included, early on) jump straight into Wireshark when they get a PCAP. And Wireshark is incredible -- don't get me wrong, it's probably the single most powerful network analysis tool out there. But it's also *dense*. When you've got 11,000 packets across nearly ten minutes of traffic, scrolling through the packet list looking for the interesting stuff is like trying to find a needle in a haystack... while blindfolded... and the haystack is on fire.

NetworkMiner flips that. It parses the entire PCAP and presents you with a host-centric view: who talked to whom, what protocols were used, what files were transferred, what credentials were exposed. In the time it takes Wireshark to load a large capture, NetworkMiner has already told you where to look. You triage first, then you drill. That's the workflow, and it's the one I used here.

Anyway, enough about that. The full story is in the report. Go read it.

---

## Author

**Akpoga Dickson Ojama**

Cybersecurity Analyst | SOC Analyst

Email: [ojamadickson@gmail.com](mailto:ojamadickson@gmail.com)

I'm always open to talking shop about malware analysis, threat hunting, blue team operations, or SOC workflows. If this project resonated with you, or if you've got feedback, or if you just want to compare notes on STRRAT or similar RAT families, drop me a line. I love this stuff and I'm always learning.

---

## License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2024 Akpoga Dickson Ojama

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

*"The packets never lie -- you just have to know how to ask them the right questions."*
