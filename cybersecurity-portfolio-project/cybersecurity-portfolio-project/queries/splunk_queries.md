# Splunk/Sigma Detection Queries - STRRAT Malware Hunting

> **Case:** 2024-07-30 Traffic Analysis Exercise | **Malware:** STRRAT RAT | **Analyst:** Me

After I finished dissecting the pcap in Wireshark, I couldn't stop thinking about the operational question: *how would I find this in a real enterprise environment?* Wireshark is amazing for deep-dive analysis, but no SOC analyst is hand-inspecting PCAPs at enterprise scale. You need automated detection — SIEM queries, scheduled hunts, and detection-as-code that fires alerts when this activity shows up in your network.

These are the detection rules I wrote to hunt for STRRAT activity based on exactly what I observed during the investigation. Each one maps to a specific behavior I saw in the network traffic. Where possible, I wrote them as Sigma rules (vendor-agnostic, portable detection format) with Splunk SPL alternatives since that's what most enterprises I work with are running.

**Fair warning:** Some of these queries require data sources that not every organization has fully deployed. I'll call that out for each one. Detection engineering is as much about knowing your data gaps as it is about writing good logic.

---

## 1. STRRAT C2 Beaconing (Outbound TCP to Port 12132)

This is the big one. During my Wireshark analysis, I found 411 packets between the victim (172.16.1.66) and the C2 server (141.98.10.79) on TCP port 12132. Every single packet had PSH+ACK flags — a sustained, heartbeat-like conversation on a completely non-standard port. If you have one detection for STRRAT, this should be it.

### Sigma Rule

```yaml
title: STRRAT C2 Beaconing - Outbound TCP to Port 12132
id: 8f2e1b4c-7d5a-4e3f-9c2b-1a6d8e5f3b2a
status: stable
description: >
  Detects outbound TCP connections to port 12132, which is the default
  C2 port used by STRRAT malware. Identifies sustained beaconing patterns
  based on multiple connection attempts or long-duration sessions to this
  non-standard port. Based on traffic analysis exercise 2024-07-30 where
  411 packets were observed between victim 172.16.1.66 and C2 141.98.10.79:12132.
author: Analyst
date: 2024/07/30
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    DestinationPort: 12132
    Protocol: tcp
  condition: selection
falsepositives:
  - Legitimate applications that happen to use port 12132 (extremely unlikely; 
    this port is not assigned by IANA to any standard service)
  - Red team exercises using the same port
level: critical
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1071.001
  - malware.strrat
```

### Splunk SPL Alternative

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
  from datamodel=Network_Traffic.All_Traffic 
  where All_Traffic.dest_port=12132 All_Traffic.action="allowed" 
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action 
| `drop_dm_object_name("All_Traffic")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| where count > 5
| table src_ip, dest_ip, dest_port, count, firstTime, lastTime, action
```

**What it detects:** Any outbound TCP connection attempt to destination port 12132. The Sigma rule catches it at the connection level. The Splunk SPL version adds a threshold (`count > 5`) to reduce noise — one connection could be a scan, but five or more is beaconing behavior. During my analysis, I saw 411 packets, which would have triggered this aggressively.

**What data sources it needs:** You need either Zeek/Bro logs, firewall logs, or NetFlow data ingested into Splunk. The Sigma rule assumes Windows Sysmon Event ID 3 (Network Connect) or equivalent endpoint network monitoring. The Splunk SPL uses the Network_Traffic data model, which requires CIM-compliant network logs. If you don't have CIM acceleration set up, you can query raw firewall logs directly — just swap the field names.

**Detection logic explanation:** Port 12132 is not assigned to any standard service by IANA. It doesn't appear in any legitimate software catalog I'm aware of. The rationale is simple: any outbound connection to this port is suspicious by definition. I set the threshold at >5 connections because malware beaconing typically happens every 30-60 seconds, so even a short capture window would accumulate multiple connection events. The `action="allowed"` filter ensures we're only seeing successful connections — failed connection attempts are less interesting (though worth logging separately for port scan detection).

**Limitations:** This Sigma rule needs endpoint network connection logs (Sysmon EID 3) or network flow data, which not every org has. If you're relying purely on perimeter firewall logs, you might miss east-west C2 traffic that never crosses the firewall. Also, STRRAT's builder allows the operator to change the C2 port. If the attacker customized the port, this rule is useless. That's why I wrote the additional rules below — defense in depth means covering multiple TTPs, not just one IOC.

---

## 2. ip-api.com GeoIP Reconnaissance (DNS + HTTP)

I found exactly one HTTP request in the entire pcap, and it was to ip-api.com — a free geolocation API. The victim's public IP, country, ISP, and region were all exfiltrated in the response. This is classic pre-C2 reconnaissance: the malware wants to know where it landed before it starts beaconing.

### Sigma Rule

```yaml
title: STRRAT GeoIP Reconnaissance - ip-api.com Query
id: 3a7c9d2e-5b1f-4a8d-b6e3-2c9f4a7d1e5b
status: stable
description: >
  Detects DNS queries or HTTP requests to ip-api.com, a geolocation service
  commonly queried by STRRAT malware during initial infection to determine
  the victim's public IP address and geographic location. Correlates DNS 
  and HTTP activity to identify the full reconnaissance chain observed in
  the 2024-07-30 traffic analysis exercise.
author: Analyst
date: 2024/07/30
logsource:
  category: dns
  product: windows
detection:
  dns_selection:
    QueryName|contains: 'ip-api.com'
  http_selection:
    - Url|contains: 'ip-api.com'
    - UserAgent|contains: 'Chrome/73'
  condition: dns_selection or http_selection
falsepositives:
  - Legitimate use of ip-api.com by developers or network diagnostic tools
  - Users manually visiting the site to check their IP
level: medium
tags:
  - attack.reconnaissance
  - attack.t1590
  - attack.t1590.005
  - malware.strrat
```

### Splunk SPL Alternative (DNS + HTTP Correlation)

```spl
(index=dns OR index=proxy) 
| eval query=lower(query), url=lower(url)
| where match(query, "ip-api\.com") OR match(url, "ip-api\.com")
| stats dc(index) as source_count, values(index) as sources, count as event_count, 
    earliest(_time) as firstTime, latest(_time) as lastTime 
  by src_ip
| where source_count >= 2
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), 
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| table src_ip, sources, source_count, event_count, firstTime, lastTime
| rename src_ip as "Source IP", sources as "Data Sources", source_count as "Source Count", 
    event_count as "Event Count", firstTime as "First Seen", lastTime as "Last Seen"
```

**What it detects:** DNS queries for `ip-api.com` and HTTP requests to `ip-api.com/json/` (the geolocation API endpoint). The Chrome 73 User-Agent is a strong secondary indicator — Chrome 73 was released in March 2019 and is wildly outdated. No legitimate modern browser would report that version. The correlation query specifically looks for the same source IP appearing in BOTH DNS and proxy logs, which confirms the full reconnaissance chain: resolve the domain, then query the API.

**What data sources it needs:** You need DNS logs (from Active Directory DNS debug logging, Infoblox, or DNS sinkhole appliances) AND web proxy logs (from BlueCoat, Zscaler, Palo Alto, or Squid). The correlation query requires both data sources to be in Splunk. If you only have one, the detection is still valuable but less precise. Without DNS logs, you can still detect the HTTP request. Without proxy logs, you can still detect the DNS query. But the magic happens when you correlate them — it proves the malware both resolved the domain and successfully connected to it.

**Detection logic explanation:** The core logic is `match(query, "ip-api\.com")` — simple pattern matching against DNS queries and URLs. I used `lower()` before matching to handle case variations. The correlation query uses `stats dc(index) as source_count` to count how many different Splunk indexes (data sources) saw activity from the same source IP. When `source_count >= 2`, we know both DNS and proxy logged the activity. The `values(index) as sources` tells us exactly which data sources contributed. This multi-source correlation is what elevates this from a simple IOC match to a behavioral detection.

**Limitations:** This Sigma rule needs DNS query logs, which many organizations don't collect at all. Windows DNS debug logging is performance-intensive and most admins disable it. If you have a DNS security appliance (Cisco Umbrella, Infoblox Threat Defense) you might get these logs, but field names will differ. The Chrome 73 User-Agent check is fragile too — STRRAT could be reconfigured with a different UA string. I kept it as an optional condition (the rule fires on ip-api.com alone) rather than requiring it.

---

## 3. Maven Payload Download (Large HTTPS Transfer from repo1.maven.org)

In the pcap, I saw a significant HTTPS transfer from `repo1.maven.org` to the victim. Given that STRRAT is Java-based, this was almost certainly the malware downloading its JAR payload disguised as a legitimate Maven artifact. The "Maven repository" camouflage is clever — it blends into normal developer traffic.

### Sigma Rule

```yaml
title: STRRAT Payload Download - Suspicious Maven Repository Transfer
id: 5e2b8c1d-4a3f-7e9b-2d5c-8f1a6e4b3c7d
status: experimental
description: >
  Detects large file downloads from repo1.maven.org by non-developer hosts.
  STRRAT uses Maven repositories to stage its Java payload, downloading JAR
  files that appear legitimate but contain the RAT code. The victim host 
  172.16.1.66 pulled a significant payload over HTTPS from repo1.maven.org
  during the 2024-07-30 capture window.
author: Analyst
date: 2024/07/30
logsource:
  category: proxy
  product: any
detection:
  selection:
    - Url|contains: 'repo1.maven.org'
    - Url|endswith: '.jar'
  filter_dev_hosts:
    SrcIp|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  filter_known_dev_tools:
    - UserAgent|contains: 'Maven'
    - UserAgent|contains: 'Gradle'
    - UserAgent|contains: 'Java'
  condition: selection and not filter_known_dev_tools
falsepositives:
  - Legitimate Java developers downloading dependencies
  - Build servers (Jenkins, GitLab CI) pulling artifacts
  - Users browsing Maven Central website
level: medium
tags:
  - attack.resource_development
  - attack.t1588
  - malware.strrat
```

### Splunk SPL Alternative

```spl
index=proxy OR index=firewall 
| where match(url, "repo1\.maven\.org") AND match(url, "\.(?i)(jar|zip|tar\.gz)$")
| eval file_size_mb=bytes_out/1024/1024
| where file_size_mb > 0.5
| lookup development_workstations.csv src_ip OUTPUT is_dev_host as dev_host
| where isnull(dev_host) OR dev_host="false"
| stats sum(file_size_mb) as total_mb, count as download_count, 
    values(url) as urls, earliest(_time) as firstTime, latest(_time) as lastTime 
  by src_ip, dest_ip
| where download_count >= 1
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), 
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| table src_ip, dest_ip, total_mb, download_count, urls, firstTime, lastTime
```

**What it detects:** HTTPS downloads from `repo1.maven.org` where the file extension is `.jar`, `.zip`, or `.tar.gz`, the transfer size is significant (>500KB), and the source host is NOT in a known developer workstation list. The key insight here is that non-developer machines shouldn't be downloading Java artifacts from Maven Central. When they do, it's worth investigating.

**What data sources it needs:** Web proxy logs with URL and bytes transferred fields, or firewall logs with similar granularity. You also need a lookup table of known development workstations (the `development_workstations.csv` in my SPL example). If you don't maintain that list, you can substitute with AD group membership lookups or asset inventory data. The detection degrades gracefully without the dev host filter — you'll just get more false positives from legitimate developers.

**Detection logic explanation:** I used `match(url, "repo1\.maven\.org")` to find Maven Central traffic, combined with `match(url, "\.(?i)(jar|zip|tar\.gz)$")` for archive file extensions. The `(?i)` makes the extension match case-insensitive. The `file_size_mb > 0.5` threshold catches meaningful downloads while filtering out tiny web artifacts (favicons, tracking pixels). The lookup-based dev host filter is the secret sauce — it removes the noise from legitimate Java developers. Without it, this query would be unusable in any company with a development team. If you don't have an asset inventory, consider filtering on UserAgent strings from build tools (Maven, Gradle) as a poor man's alternative.

**Limitations:** This query is the most data-hungry of the bunch. It requires proxy logs with URL logging enabled (many organizations only log domains for privacy reasons), file size information, and some kind of asset classification to distinguish dev hosts from regular users. STRRAT could also stage payloads on non-Maven sites — GitHub raw files, Pastebin, or legitimate-but-compromised websites. This rule only catches the Maven staging vector.

---

## 4. GitHub + Maven Abuse in Same Session

The pcap showed DNS resolutions for both `api.github.com` and `repo1.maven.org` from the same victim host within a short time window. This combination is unusual — a non-developer machine reaching out to both GitHub's API and Maven Central within minutes suggests coordinated payload staging. STRRAT uses GitHub for configuration or secondary payloads and Maven for the primary JAR delivery.

### Sigma Rule

```yaml
title: STRRAT Multi-Stage Staging - GitHub and Maven in Same Session
id: 7c4e2a9f-1b3d-5e8c-4a7f-9d2b5e1c8a3f
status: experimental
description: >
  Detects when a single host queries both GitHub (api.github.com) and Maven
  Central (repo1.maven.org) within a 10-minute window. This multi-service 
  staging pattern was observed during the 2024-07-30 investigation where 
  STRRAT used GitHub for configuration and Maven for payload delivery.
author: Analyst
date: 2024/07/30
logsource:
  category: dns
  product: windows
detection:
  github_query:
    QueryName|contains: 'github.com'
  maven_query:
    QueryName|contains: 'maven.org'
  condition: selection
  timeframe: 10m
  aggregation:
    condition:
      - gte: 2
      - field: SourceIP
falsepositives:
  - Software developers using both GitHub and Maven (common in dev environments)
  - CI/CD pipelines that pull from both services
level: medium
tags:
  - attack.resource_development
  - attack.t1588
  - malware.strrat
```

### Splunk SPL Alternative

```spl
index=dns 
| eval query=lower(query)
| where match(query, "github\.com") OR match(query, "maven\.org")
| eval service=case(
    match(query, "github\.com"), "github",
    match(query, "maven\.org"), "maven",
    true(), "other")
| bin _time span=10m
| stats dc(service) as service_count, values(service) as services, count as query_count 
  by _time, src_ip
| where service_count >= 2
| eval time_window=strftime(_time, "%Y-%m-%d %H:%M") 
| table time_window, src_ip, services, service_count, query_count
```

**What it detects:** A single source IP making DNS queries for BOTH GitHub-related domains AND Maven-related domains within a 10-minute window. The `dc(service)` (distinct count) ensures we're seeing both services from the same host. During my investigation, the victim resolved both `api.github.com` and `repo1.maven.org` — this query catches that exact pattern.

**What data sources it needs:** DNS query logs are the primary source. If you have web proxy logs, you can substitute HTTP/HTTPS requests to these domains instead of DNS queries — sometimes that's even better because it proves the connection succeeded, not just that the domain was resolved. You need the same source IP field across both query types for the correlation to work.

**Detection logic explanation:** I bucket events into 10-minute time windows using `bin _time span=10m`, then count distinct services per source IP per window. When `service_count >= 2`, the host touched both GitHub and Maven in the same window. The `eval service=case(...)` categorizes each query into "github" or "maven" buckets, which makes the distinct count meaningful. I specifically used DNS logs rather than proxy logs because DNS queries happen before any TCP connection — they catch the intent even if the HTTP request was blocked by a firewall or proxy policy. The 10-minute window is empirical; I could tighten it to 5 minutes for fewer false positives or loosen to 30 for catching slower staging.

**Limitations:** This query will scream in any development environment. Software engineers touch GitHub and Maven constantly. You MUST filter out known development workstations, build servers, and CI/CD infrastructure for this to be useful. The 10-minute window might also miss staging that happens more slowly — some malware spreads its downloads across hours to evade exactly this kind of detection. Consider this a hunting query rather than an automated alert — run it weekly, tune the false positives, and only promote it to alerting after you've built a solid exclusion list.

---

## 5. Hardcoded IP C2 (Outbound TCP Without Preceding DNS Query)

Remember how I found that 141.98.10.79 was contacted directly with NO preceding DNS query? That's the hallmark of a hardcoded C2 IP address burned into the malware binary. In a real enterprise, this is a powerful detection because most legitimate software resolves hostnames — it doesn't connect to bare IPs.

### Sigma Rule

```yaml
title: STRRAT Hardcoded C2 - Outbound TCP Without DNS Resolution
id: 2d8f5a3e-9c4b-7e1f-5a2d-4b8c3e7f1a5d
status: experimental
description: >
  Detects outbound TCP connections to external IP addresses where no 
  corresponding DNS query was observed in the preceding 60 seconds.
  Indicates a hardcoded IP address, common in RAT malware like STRRAT
  that embeds C2 infrastructure directly in its binary. In the 2024-07-30
  investigation, 141.98.10.79:12132 was contacted with zero prior DNS
  resolution.
author: Analyst
date: 2024/07/30
logsource:
  category: network_connection
  product: windows
detection:
  outbound_tcp:
    Initiated: 'true'
    DestinationIp|cidr:
      - '!10.0.0.0/8'
      - '!172.16.0.0/12'
      - '!192.168.0.0/16'
      - '!127.0.0.0/8'
    DestinationPort|gt: 1024
  condition: outbound_tcp and not dns_preceding
falsepositives:
  - Applications that connect directly to IP addresses (e.g., some VPN clients,
    legacy applications, applications using IP-based CDNs)
  - Web browsers loading resources from IP addresses (less common but happens)
  - NTP, update checks, and other services that use well-known IPs
level: medium
tags:
  - attack.command_and_control
  - attack.t1071
  - malware.strrat
```

### Splunk SPL Alternative

```spl
| tstats `security_content_summariesonly` earliest(_time) as conn_time 
  from datamodel=Network_Traffic.All_Traffic 
  where All_Traffic.dest_ip!=10.0.0.0/8 All_Traffic.dest_ip!=172.16.0.0/12 
    All_Traffic.dest_ip!=192.168.0.0/16 All_Traffic.dest_ip!=127.0.0.0/8
    All_Traffic.dest_port>1024 All_Traffic.action="allowed"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name("All_Traffic")` 
| eval conn_time=round(conn_time, 0)
| join type=left dest_ip 
    [| search index=dns earliest=-1h 
     | eval dns_time=round(_time, 0) 
     | stats max(dns_time) as last_dns_time by answer as dest_ip]
| where isnull(last_dns_time) OR (conn_time - last_dns_time) > 60
| where dest_port!=443 AND dest_port!=80
| stats count as connection_count, values(dest_port) as ports, 
    earliest(conn_time) as first_seen, latest(conn_time) as last_seen 
  by src_ip, dest_ip
| where connection_count >= 3
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), 
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table src_ip, dest_ip, ports, connection_count, first_seen, last_seen
```

**What it detects:** Outbound TCP connections to external IPs on non-standard ports (>1024) where no DNS resolution for that IP occurred within the previous 60 seconds. The `connection_count >= 3` threshold filters out one-off connections (like a browser loading an image from a CDN IP) and focuses on sustained beaconing behavior.

**What data sources it needs:** This is the most data-hungry query of the entire set. You need BOTH network connection logs (Sysmon EID 3, Zeek conn.log, or firewall logs) AND DNS resolution logs (with the `answer` field mapping IPs to resolved domains). The join operation correlates these two data sources in real-time. Many organizations have one but not both. If you only have connection logs, you can still run a simplified version that flags ALL direct IP connections on non-standard ports — it'll be noisier but still catches hardcoded C2.

**Detection logic explanation:** The core logic is a left join: take all outbound TCP connections, then try to find a matching DNS answer record for the destination IP. If `last_dns_time` is null (never resolved) OR the DNS resolution happened more than 60 seconds before the connection, the connection is flagged. The 60-second grace period handles the normal race condition where a DNS resolution happens immediately before the TCP connection. I excluded ports 80 and 443 because legitimate web traffic often connects directly to CDN IPs without hostname resolution. The `dest_port>1024` filter focuses on non-standard ports where hardcoded C2 is most common.

**Limitations:** This query is computationally expensive — the join across two large indexes (network traffic + DNS) can be slow in busy environments. The 60-second threshold is somewhat arbitrary; malware with cached DNS lookups might fall outside this window. Also, some legitimate applications (games, VoIP, VPN clients) connect directly to IPs on high ports, so you'll need to build a solid exclusion list. I recommend running this as a weekly hunt rather than a real-time alert until you've tuned it for your environment.

---

## 6. Chrome 73 User-Agent (Outdated Browser Version)

The single HTTP request I found had a User-Agent of `Chrome/73.0.3683.86` — a browser version from March 2019. In 2024, that's ancient. Malware often uses hardcoded, outdated User-Agent strings because the authors don't bother updating them.

### Sigma Rule

```yaml
title: STRRAT Outdated User-Agent - Chrome 73 Indicators
id: 9e3b7c2a-5d4f-1e8b-3c6a-7f2d9e5b4c1a
status: stable
description: >
  Detects HTTP requests carrying an outdated Chrome 73 User-Agent string,
  which is the hardcoded User-Agent used by STRRAT malware during its
  ip-api.com geolocation reconnaissance phase. Chrome 73 was released in
  March 2019 and is not used by any legitimate modern browser installation.
author: Analyst
date: 2024/07/30
logsource:
  category: proxy
  product: any
detection:
  selection:
    - UserAgent|contains: 'Chrome/73'
    - UserAgent|contains: 'Chrome/72'
    - UserAgent|contains: 'Chrome/71'
    - UserAgent|contains: 'Chrome/70'
  condition: selection
falsepositives:
  - Extremely outdated browser installations (rare in enterprise environments)
  - Legacy embedded systems with hardcoded UAs
  - Security scanning tools that spoof old UAs
level: medium
tags:
  - attack.execution
  - attack.t1203
  - malware.strrat
```

### Splunk SPL Alternative

```spl
index=proxy 
| where match(user_agent, "Chrome/7[0-3]\.") 
| stats count as request_count, values(url) as urls, values(dest) as destinations, 
    earliest(_time) as firstTime, latest(_time) as lastTime 
  by src_ip, user_agent
| where request_count >= 1
| eval ua_age_years=round((now() - strptime("2019-03-12", "%Y-%m-%d")) / 86400 / 365, 1)
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), 
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| table src_ip, user_agent, ua_age_years, request_count, urls, destinations, firstTime, lastTime
```

**What it detects:** HTTP requests with User-Agent strings containing Chrome versions 70-73. The regex `Chrome/7[0-3]\.` catches versions 70, 71, 72, and 73. I included a range rather than just 73 because other STRRAT variants or similar malware families might use nearby versions.

**What data sources it needs:** Web proxy logs with User-Agent string logging. This is pretty standard for most corporate proxies, but some privacy-conscious organizations strip or anonymize User-Agent logging. If your proxy doesn't log UAs, this query won't work. You could potentially get similar data from web server logs if you're analyzing traffic *to* your own infrastructure, but for outbound traffic, proxy logs are your only option.

**Detection logic explanation:** The `match(user_agent, "Chrome/7[0-3]\.")` regex is simple but effective. The `7[0-3]` character class matches 70, 71, 72, or 73. The trailing `\.` ensures we don't match version 730 or something weird. I added a calculated `ua_age_years` field to make the alert more actionable — when an analyst sees "this User-Agent is 5.3 years old," the severity is immediately obvious. This is a low-volume detection in most environments; I'd expect zero to one hits per day in a typical enterprise.

**Limitations:** User-Agent strings are trivially easy to change. If the STRRAT operator updates their builder to use Chrome 120 as the UA, this rule becomes useless overnight. Also, some enterprise applications and old internal tools legitimately use outdated UAs. I recommend running this as a weekly anomaly hunt rather than a real-time alert, at least until you confirm your environment doesn't have legitimate Chrome 70-73 traffic.

---

## 7. Multiple ip-api.com Queries from Same Host

The malware queried ip-api.com once during my capture window, but in a larger enterprise dataset, repeated queries from the same host are a stronger signal. Legitimate users might check their IP once in a while; malware checks it repeatedly as part of its reconnaissance loop or to detect network changes.

### Sigma Rule

```yaml
title: STRRAT Repeated Reconnaissance - Multiple ip-api.com Queries
id: 4f1a8d3c-6e2b-9a5f-7c4d-3b8e2a5f1c9d
status: stable
description: >
  Detects multiple DNS queries or HTTP requests to ip-api.com from the same
  source host within a 1-hour window. Repeated geolocation checks are a 
  known STRRAT behavior pattern used to monitor network connectivity and
  detect when the victim moves between networks.
author: Analyst
date: 2024/07/30
logsource:
  category: dns
  product: windows
detection:
  selection:
    QueryName|contains: 'ip-api.com'
  condition: selection
  timeframe: 1h
  aggregation:
    condition:
      - gte: 3
      - field: SourceIP
falsepositives:
  - Network monitoring tools that check public IP periodically
  - Users with browser extensions that display IP information
  - Developers testing geolocation APIs
level: low
tags:
  - attack.reconnaissance
  - attack.t1590
  - malware.strrat
```

### Splunk SPL Alternative

```spl
index=dns OR index=proxy
| eval query=lower(query), url=lower(url)
| where match(query, "ip-api\.com") OR match(url, "ip-api\.com")
| bin _time span=1h
| stats count as query_count, earliest(_time) as window_start, latest(_time) as window_end 
  by _time, src_ip
| where query_count >= 3
| eval window_start=strftime(window_start, "%Y-%m-%d %H:%M:%S"), 
       window_end=strftime(window_end, "%Y-%m-%d %H:%M:%S"),
       time_window=strftime(_time, "%Y-%m-%d %H:00")
| table time_window, src_ip, query_count, window_start, window_end
| sort -query_count
```

**What it detects:** Three or more DNS queries or HTTP requests to `ip-api.com` from the same source IP within a 1-hour window. The threshold of 3 filters out occasional legitimate use while catching malware's repetitive reconnaissance behavior.

**What data sources it needs:** DNS logs and/or web proxy logs. This is a relatively lightweight query compared to some of the others — you only need one data source, not a correlation across multiple. If you have both, the query aggregates across them, which increases coverage. DNS logs will catch the resolution even if the HTTP request is blocked, and proxy logs will catch the request even if DNS was cached from an earlier query.

**Detection logic explanation:** I bucket events into 1-hour windows with `bin _time span=1h` and count events per source IP per window. The `query_count >= 3` threshold is empirical — I chose 3 because one query is easily legitimate, two might be a coincidence, but three or more in an hour from the same host strongly suggests automated behavior. The query sorts by `query_count` descending so the most active hosts appear first. This is intentionally a "low" severity detection because the false positive rate is higher than the other rules — but as a hunting query, it's excellent for finding suspicious hosts that merit deeper investigation.

**Limitations:** This is the noisiest rule in the set. Browser extensions, network monitoring tools, and even some VPN clients check public IP regularly. I strongly recommend excluding known network monitoring hosts and building a baseline before enabling alerts. Also, some STRRAT variants might not query ip-api.com at all — they might use `whatismyipaddress.com`, `icanhazip.com`, or no geolocation check whatsoever. This rule is specific to the STRRAT variant I analyzed.

---

## Detection Coverage Matrix

Here's how these seven queries cover the STRRAT kill chain based on what I observed:

| Tactic | Technique | Query # | Coverage |
|--------|-----------|---------|----------|
| Reconnaissance | T1590.005 - Active Scanning | 2, 7 | DNS + HTTP to ip-api.com |
| Resource Development | T1588 - Obtain Capabilities | 3, 4 | Maven + GitHub staging |
| Initial Access | Varies (not observed in pcap) | N/A | Requires endpoint telemetry |
| Execution | T1203 - User Execution | 6 | Chrome 73 UA on execution |
| Command & Control | T1071 - Application Layer Protocol | 1, 5 | C2 beaconing on port 12132 |
| Command & Control | T1071.001 - Web Protocols | 1 | Custom TCP C2 channel |

**The gap:** I didn't observe the initial delivery vector in this pcap — no phishing email, no malicious download, no exploit. To detect initial access, you'd need email gateway logs (for phishing detection), endpoint process creation logs (for macro/script execution), or web filtering logs (for drive-by downloads). Those are environment-specific and weren't part of this network-focused investigation.

**The philosophy:** Detection engineering isn't about writing perfect rules that catch everything. It's about writing *good enough* rules that catch the behaviors you understand, and layering them so that when one fails, another catches the activity. STRRAT could change its C2 port, update its User-Agent, or stop using Maven for staging — but the behavioral pattern of beaconing to a hardcoded IP with a custom protocol is much harder to change than a single IOC. Write behavioral detections first, IOC-based detections second, and always have a plan for when the adversary adapts.

---

*These queries were born from staring at 2,847 packets for hours. Every condition, every threshold, every regex is grounded in something I actually saw on the wire. Run them, tune them, break them, and make them better. That's the job.*
