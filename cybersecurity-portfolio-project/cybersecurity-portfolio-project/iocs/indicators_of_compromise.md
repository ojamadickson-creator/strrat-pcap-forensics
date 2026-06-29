# Indicators of Compromise — STRRAT Investigation

---

| Field              | Details                                                    |
|--------------------|------------------------------------------------------------|
| **Investigation ID** | INV-2024-STRRAT-001                                        |
| **Date**           | 2024-07-30                                                 |
| **Analyst**        | Akpoga Dickson Ojama                                       |
| **Case Reference** | Malware Traffic Analysis Exercise — Brad Duncan (2024-07-30) |
| **Malware Family** | STRRAT (Software S0476 — MITRE ATT&CK)                     |
| **Victim**         | 172.16.1.66 (DESKTOP-SKBR25F, ccollier)                   |
| **C2 Server**      | 141.98.10.79:12132 (Vilnius, Lithuania)                    |

---

## Confidence Legend

| Level   | Definition                                                                 |
|---------|----------------------------------------------------------------------------|
| **High** | Indicator directly observed in network traffic or host artifacts with no ambiguity. Confirmed correlation with known TTPs of the malware family. |
| **Medium** | Indicator inferred from contextual evidence, behavioral analysis, or secondary artifacts. Highly plausible but requires additional corroboration. |
| **Low** | Indicator based on indirect evidence or preliminary analysis. Treat as leads rather than confirmed facts. |

---

## IOC Categories

### Malicious Infrastructure (HIGH confidence)

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| C2 IP | IPv4 | 141.98.10.79 | Hardcoded, no DNS resolution observed, Lithuanian ASN (Hostinger / Ashburn VA routing) |
| C2 Port | Port | 12132/TCP | Non-standard port; custom TCP protocol over plaintext — no TLS/SSL encapsulation |
| C2 Protocol | Protocol | Raw TCP | STRRAT custom protocol utilizing pipe-delimited (`\|`) messages; beacon pattern observed every ~5 seconds |
| Bot ID | String | 18E8292C | Unique campaign identifier embedded in C2 beacons; likely derived from host fingerprinting |
| C2 Geo | Country | Lithuania (LT) | Vilnius-based hosting; unexpected for legitimate remote access tools targeting a US endpoint |
| ASN | ASN | AS47583 / AS213230 | Hosting provider network — frequently associated with bulletproof/reseller hosting |

### Abused Legitimate Platforms (MEDIUM-HIGH confidence)

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| Payload Delivery | Domain | repo1.maven.org | Approximately 9 MB payload downloaded over HTTPS; abuse of Maven Central CDN for malware staging |
| Payload Hosting | Domain | objects.githubusercontent.com | GitHub CDN used as secondary payload delivery vector; blends with legitimate developer traffic |
| Payload Reference | Domain | github.com | Initial download page directing victim to malicious payload; likely a compromised or throwaway repository |
| CDN Reputation | Context | Low detect rate | Abuse of trusted CDNs often bypasses URL filtering and domain reputation checks |

### Reconnaissance Infrastructure (HIGH confidence)

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| GeoIP Service | Domain | ip-api.com | Malware queried this endpoint to determine victim geolocation and ISP details |
| GeoIP API IP | IPv4 | 208.95.112.1 | Resolved A-record for ip-api.com at time of capture |
| GeoIP Response File | Filename | index[1].json | 294-byte JSON response cached locally containing victim's ASN, city, region, and ISP data |
| Recon Purpose | Context | TTP: T1590 | MITRE ATT&CK T1590 — Gather Victim Network Information; confirms targeted configuration |

### Victim Artifacts (HIGH confidence)

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| Victim IP | IPv4 | 172.16.1.66 | Compromised internal workstation; RFC1918 private address space |
| Hostname | String | DESKTOP-SKBR25F | Windows 11 Pro endpoint naming convention typical of SOHO/small business environments |
| Username | String | ccollier | Compromised user account; likely the logged-in interactive user at time of infection |
| MAC Address | MAC | 00:1e:64:ec:f3:08 | Intel Corporate NIC OUI (00:1e:64); confirms physical hardware identity |
| OS Version | String | Windows NT 10.0; Win64; x64 | Windows 10/11 64-bit as reported in HTTP User-Agent headers |

### File Artifacts (MEDIUM confidence)

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| Recon File | Filename | index[1].json | 294-byte GeoIP response artifact from ip-api.com; JSON structure consistent with ip-api.com v1 output |
| Recon File MD5 | Hash (MD5) | afc8b44a5bb4e32054515d7530490d04 | Benign artifact in isolation; valuable as correlation point across cases |
| Recon File SHA256 | Hash (SHA256) | N/A — pending | Recommended for deep-dive forensic comparison against other STRRAT infections |

### User Agent Signatures (MEDIUM confidence)

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| Malware UA | User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/73.0.3683.86` | Chrome 73 released March 2019 — significantly outdated; strong STRRAT fingerprint |
| UA Anomaly | Context | Version mismatch | Windows 11 host reporting a 5-year-old Chrome build; clear indicator of spoofed/static UA |
| UA Source | Context | C2 beacons | Consistent across all C2 communications; hardcoded in the malware sample |

---

## STIX 2.1 Format

The following STIX 2.1 bundle represents all confirmed IOCs in standardized, machine-readable format. You can import this directly into OpenCTI, MISP, or any STIX-compatible TIP.

```json
{
  "type": "bundle",
  "id": "bundle--strrat-investigation-2024-001",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--c2-ip-141-98-10-79",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "STRRAT C2 Server IP",
      "description": "Hardcoded C2 IP address observed in STRRAT network traffic. Lithuanian hosting. No DNS resolution.",
      "pattern": "[ipv4-addr:value = '141.98.10.79']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 85,
      "labels": ["c2", "strrat", "remote-access-trojan"],
      "object_marking_refs": ["marking-definition--statement--strrat-case"]
    },
    {
      "type": "indicator",
      "id": "indicator--c2-port-12132",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "STRRAT C2 Port",
      "description": "Non-standard TCP port 12132 used for STRRAT custom pipe-delimited protocol.",
      "pattern": "[network-traffic:dst_port = 12132 AND network-traffic:protocols[*] = 'tcp']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 85,
      "labels": ["c2", "strrat", "non-standard-port"]
    },
    {
      "type": "indicator",
      "id": "indicator--bot-id-18e8292c",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "STRRAT Bot ID",
      "description": "Unique campaign identifier 18E8292C observed in C2 beacons.",
      "pattern": "[x-strrat-bot-id:value = '18E8292C']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 85,
      "labels": ["strrat", "bot-id", "campaign-identifier"]
    },
    {
      "type": "indicator",
      "id": "indicator--domain-repo1-maven-org",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "Abused Maven Central Domain",
      "description": "repo1.maven.org abused for payload delivery (~9MB download). Trusted CDN lowers detection probability.",
      "pattern": "[domain-name:value = 'repo1.maven.org']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 70,
      "labels": ["abused-legitimate", "payload-delivery", "cdn"]
    },
    {
      "type": "indicator",
      "id": "indicator--domain-githubusercontent",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "Abused GitHub CDN Domain",
      "description": "objects.githubusercontent.com used as secondary payload hosting via GitHub CDN.",
      "pattern": "[domain-name:value = 'objects.githubusercontent.com']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 70,
      "labels": ["abused-legitimate", "payload-hosting", "github", "cdn"]
    },
    {
      "type": "indicator",
      "id": "indicator--domain-github-com",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "GitHub Payload Reference",
      "description": "github.com used as initial download reference page directing victim to malicious payload.",
      "pattern": "[domain-name:value = 'github.com']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 60,
      "labels": ["abused-legitimate", "payload-reference"]
    },
    {
      "type": "indicator",
      "id": "indicator--domain-ip-api-com",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "STRRAT GeoIP Recon Service",
      "description": "ip-api.com queried by malware for victim geolocation reconnaissance (T1590).",
      "pattern": "[domain-name:value = 'ip-api.com']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 85,
      "labels": ["reconnaissance", "geolocation", "strrat"]
    },
    {
      "type": "indicator",
      "id": "indicator--victim-ip-172-16-1-66",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "Victim Internal IP",
      "description": "Compromised workstation at 172.16.1.66 — RFC1918 private address.",
      "pattern": "[ipv4-addr:value = '172.16.1.66']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 95,
      "labels": ["victim", "internal", "compromised"]
    },
    {
      "type": "indicator",
      "id": "indicator--hostname-desktop-skbr25f",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "Victim Hostname",
      "description": "Windows 11 Pro endpoint DESKTOP-SKBR25F observed in C2 beacons and DHCP traffic.",
      "pattern": "[x-oca-asset:hostname = 'DESKTOP-SKBR25F']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 90,
      "labels": ["victim", "hostname", "endpoint"]
    },
    {
      "type": "indicator",
      "id": "indicator--user-ccollier",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "Compromised Username",
      "description": "User account ccollier — logged-in interactive user at time of infection.",
      "pattern": "[user-account:user_id = 'ccollier']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 85,
      "labels": ["victim", "user-account", "compromised"]
    },
    {
      "type": "indicator",
      "id": "indicator--mac-00-1e-64-ec-f3-08",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "Victim MAC Address",
      "description": "Intel Corporate NIC MAC address observed in ARP/DHCP traffic.",
      "pattern": "[mac-addr:value = '00:1e:64:ec:f3:08']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 90,
      "labels": ["victim", "mac-address", "hardware"]
    },
    {
      "type": "indicator",
      "id": "indicator--md5-index-json",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "GeoIP Response File MD5",
      "description": "MD5 hash of index[1].json — benign GeoIP artifact but valuable for cross-case correlation.",
      "pattern": "[file:hashes.MD5 = 'afc8b44a5bb4e32054515d7530490d04']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 60,
      "labels": ["file-artifact", "geolocation", "correlation"]
    },
    {
      "type": "indicator",
      "id": "indicator--user-agent-strrat",
      "created": "2024-07-30T00:00:00.000Z",
      "modified": "2024-07-30T00:00:00.000Z",
      "name": "STRRAT Hardcoded User-Agent",
      "description": "Outdated Chrome 73 User-Agent string used consistently across all C2 beacons. Windows 11 host with 2019 Chrome version is a clear anomaly.",
      "pattern": "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/73.0.3683.86']",
      "pattern_type": "stix",
      "valid_from": "2024-07-30T00:00:00Z",
      "confidence": 70,
      "labels": ["user-agent", "strrat", "fingerprint"]
    }
  ]
}
```

---

## MISP Event Template

The following JSON structure is formatted for direct import into a MISP instance as a new event. Tags, galaxies, and object references are pre-mapped for STRRAT (S0476) correlation.

```json
{
  "Event": {
    "info": "STRRAT Investigation — C2 Traffic Analysis (2024-07-30)",
    "threat_level_id": "1",
    "analysis": "2",
    "distribution": "3",
    "date": "2024-07-30",
    "timestamp": "1722297600",
    "publish_timestamp": "1722297600",
    "org_id": "1",
    "orgc_id": "1",
    "Attribute": [
      {
        "type": "ip-dst",
        "category": "Network activity",
        "to_ids": true,
        "value": "141.98.10.79",
        "comment": "STRRAT C2 server — hardcoded IP, Lithuanian hosting",
        "Tag": [
          {"name": "c2-server"},
          {"name": "strrat"},
          {"name": "Confidence:High"}
        ]
      },
      {
        "type": "port",
        "category": "Network activity",
        "to_ids": true,
        "value": "12132",
        "comment": "Non-standard TCP port used by STRRAT custom protocol",
        "Tag": [
          {"name": "c2-server"},
          {"name": "non-standard-port"}
        ]
      },
      {
        "type": "mutex",
        "category": "Artifacts dropped",
        "to_ids": true,
        "value": "18E8292C",
        "comment": "STRRAT bot ID / campaign identifier from C2 beacons",
        "Tag": [
          {"name": "strrat"},
          {"name": "bot-id"},
          {"name": "Confidence:High"}
        ]
      },
      {
        "type": "domain",
        "category": "Network activity",
        "to_ids": true,
        "value": "repo1.maven.org",
        "comment": "Abused Maven Central CDN — ~9MB payload delivery",
        "Tag": [
          {"name": "abused-legitimate"},
          {"name": "payload-delivery"},
          {"name": "Confidence:Medium-High"}
        ]
      },
      {
        "type": "domain",
        "category": "Network activity",
        "to_ids": true,
        "value": "objects.githubusercontent.com",
        "comment": "GitHub CDN used for secondary payload hosting",
        "Tag": [
          {"name": "abused-legitimate"},
          {"name": "github"},
          {"name": "payload-hosting"}
        ]
      },
      {
        "type": "domain",
        "category": "Network activity",
        "to_ids": true,
        "value": "github.com",
        "comment": "Initial payload download reference page",
        "Tag": [
          {"name": "abused-legitimate"},
          {"name": "payload-reference"}
        ]
      },
      {
        "type": "domain",
        "category": "Network activity",
        "to_ids": true,
        "value": "ip-api.com",
        "comment": "GeoIP reconnaissance service queried by malware (T1590)",
        "Tag": [
          {"name": "reconnaissance"},
          {"name": "geolocation"},
          {"name": "strrat"},
          {"name": "Confidence:High"}
        ]
      },
      {
        "type": "ip-src",
        "category": "Network activity",
        "to_ids": false,
        "value": "172.16.1.66",
        "comment": "Victim internal workstation — RFC1918",
        "Tag": [
          {"name": "victim"},
          {"name": "internal"}
        ]
      },
      {
        "type": "hostname",
        "category": "Network activity",
        "to_ids": false,
        "value": "DESKTOP-SKBR25F",
        "comment": "Compromised Windows 11 Pro endpoint hostname",
        "Tag": [
          {"name": "victim"},
          {"name": "endpoint"}
        ]
      },
      {
        "type": "target-user",
        "category": "Targeting data",
        "to_ids": false,
        "value": "ccollier",
        "comment": "Compromised user account — interactive session at infection time",
        "Tag": [
          {"name": "victim"},
          {"name": "compromised-account"}
        ]
      },
      {
        "type": "mac-address",
        "category": "Network activity",
        "to_ids": false,
        "value": "00:1e:64:ec:f3:08",
        "comment": "Victim NIC — Intel Corporate OUI",
        "Tag": [
          {"name": "victim"},
          {"name": "hardware"}
        ]
      },
      {
        "type": "filename",
        "category": "Artifacts dropped",
        "to_ids": false,
        "value": "index[1].json",
        "comment": "GeoIP response artifact cached locally (294B)",
        "Tag": [
          {"name": "file-artifact"},
          {"name": "geolocation"}
        ]
      },
      {
        "type": "md5",
        "category": "Payload delivery",
        "to_ids": true,
        "value": "afc8b44a5bb4e32054515d7530490d04",
        "comment": "MD5 of index[1].json — benign but correlatable artifact",
        "Tag": [
          {"name": "file-artifact"},
          {"name": "hash"}
        ]
      },
      {
        "type": "user-agent",
        "category": "Network activity",
        "to_ids": true,
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/73.0.3683.86",
        "comment": "Hardcoded STRRAT User-Agent — outdated Chrome 73 (March 2019)",
        "Tag": [
          {"name": "user-agent"},
          {"name": "strrat"},
          {"name": "fingerprint"},
          {"name": "Confidence:Medium"}
        ]
      }
    ],
    "Tag": [
      {"name": "malware-type:Remote Access Trojan"},
      {"name": "misp-galaxy:mitre-malware=STRRAT - S0476"},
      {"name": "misp-galaxy:mitre-attack-pattern=Application Layer Protocol - T1071"},
      {"name": "misp-galaxy:mitre-attack-pattern=Gather Victim Network Information - T1590"},
      {"name": "misp-galaxy:mitre-attack-pattern=Exfiltration Over C2 Channel - T1041"},
      {"name": "tlp:amber"},
      {"name": "confidence-level:high"}
    ]
  }
}
```

---

## Hunting Queries

The following queries are ready to copy-paste into your SIEM or EDR platform. I've tested these patterns conceptually against the traffic features observed in this case.

### Splunk (SPL)

**C2 Beacon Detection — IP + Port**
```spl
index=network (dest_ip=141.98.10.79 OR dest_port=12132)
| stats count by src_ip, dest_ip, dest_port, _time
| where count > 10
| eval risk_score=case(count > 100, "Critical", count > 50, "High", count > 10, "Medium")
| table _time, src_ip, dest_ip, dest_port, count, risk_score
```

**Outdated Chrome User-Agent (STRRAT Fingerprint)**
```spl
index=network (user_agent="*Chrome/73.0.3683.86*")
| stats count by src_ip, dest_ip, user_agent, _time
| eval alert_reason="Outdated Chrome 73 UA — possible STRRAT beacon"
| table _time, src_ip, dest_ip, user_agent, count, alert_reason
```

**Abused CDN Payload Delivery**
```spl
index=network (dest_host="repo1.maven.org" OR dest_host="objects.githubusercontent.com")
| eval payload_size_mb=bytes_out/1024/1024
| where payload_size_mb > 5
| stats sum(payload_size_mb) as total_mb by src_ip, dest_host, uri
| where total_mb > 8
| table src_ip, dest_host, uri, total_mb
```

**GeoIP Reconnaissance Detection**
```spl
index=network (dest_host="ip-api.com" OR dest_ip="208.95.112.1")
| stats count by src_ip, dest_host, dest_ip, _time
| eval alert_reason="Possible malware geolocation reconnaissance (T1590)"
| table _time, src_ip, dest_host, dest_ip, count, alert_reason
```

---

### Microsoft Sentinel (KQL)

**C2 Communication to Lithuanian Host**
```kusto
let c2_ip = "141.98.10.79";
let c2_port = 12132;
CommonSecurityLog
| where DestinationIP == c2_ip or DestinationPort == c2_port
| summarize ConnectionCount = count(), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
            by SourceIP, DestinationIP, DestinationPort
| extend RiskLevel = case(
    ConnectionCount > 100, "Critical",
    ConnectionCount > 50, "High",
    ConnectionCount > 10, "Medium",
    "Low")
| order by ConnectionCount desc
```

**STRRAT User-Agent Detection**
```kusto
let strrat_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/73.0.3683.86";
DeviceNetworkEvents
| where RemoteUrl contains "Chrome/73.0.3683.86"
   or (InitiatingProcessCommandLine contains "Chrome/73" and RemotePort == 12132)
| summarize BeaconCount = count() by DeviceName, RemoteIP, RemotePort, ActionType
| extend AlertReason = "STRRAT indicator: outdated Chrome 73 UA on non-standard port"
```

**Large File Download from Maven Central**
```kusto
let threshold_mb = 8;
DeviceNetworkEvents
| where RemoteUrl contains "repo1.maven.org"
| extend DownloadMB = ResponseBodySize / 1024 / 1024
| where DownloadMB > threshold_mb
| summarize TotalDownloadedMB = sum(DownloadMB), 
            DownloadCount = count() 
            by DeviceName, LocalIP, RemoteUrl
| extend AlertReason = strcat("Suspicious large download from Maven Central: ", round(TotalDownloadedMB, 2), " MB")
```

---

### YARA Rule (Network/Traffic Hunting)

```yara
rule STRRAT_C2_Beacon {
    meta:
        description = "Detects STRRAT C2 beacon patterns based on pipe-delimited protocol"
        author = "Akpoga Dickson Ojama"
        date = "2024-07-30"
        reference = "INV-2024-STRRAT-001"
        hash = "N/A"
    strings:
        $c2_ip = "141.98.10.79" ascii wide
        $bot_id = "18E8292C" ascii wide
        $ua = "Chrome/73.0.3683.86" ascii wide
        $pipe_proto = /\w+\|\w+\|\w+/ ascii
    condition:
        any of ($c2_ip, $bot_id, $ua) or
        ($pipe_proto and filesize < 100KB)
}
```

---

## Notes & Observations

- **No DNS resolution observed** for the C2 IP. The malware connects directly to `141.98.10.79:12132` via raw TCP, which is a deliberate evasion technique to minimize DNS artifacts and bypass DNS-based filtering.
- **Pipe-delimited protocol**: STRRAT's C2 protocol uses `|` as a field delimiter. In the packet capture, I observed messages like `BOT_ID|COMMAND|ARGS` flowing in both directions. This is consistent with known STRRAT behavior documented in MITRE S0476.
- **Bot ID generation**: The identifier `18E8292C` likely derives from a hash of the victim's hostname, MAC address, or a combination of system attributes. Cross-referencing this ID across other cases could reveal campaign-scale patterns.
- **CDN abuse pattern**: The use of `repo1.maven.org` and `objects.githubusercontent.com` is a textbook example of "living off trusted land." These domains typically have high reputation scores and are rarely blocked by corporate proxies. The ~9MB payload size is unusually large for a Maven artifact fetched by a non-developer workstation.
- **GeoIP reconnaissance timing**: The query to `ip-api.com` occurs early in the infection chain, confirming the malware fingerprints the victim before establishing persistent C2 communication. This aligns with MITRE ATT&CK technique T1590 (Gather Victim Network Information).
- **User-Agent anomaly**: Chrome 73 was released in March 2019. Seeing this UA on a Windows 11 host (which launched in October 2021) is an immediate red flag. This UA string appears to be hardcoded in the malware and doesn't reflect the actual browser installed on the victim machine.

---

*Generated by Akpoga Dickson Ojama | Investigation INV-2024-STRRAT-001 | 2024-07-30*
