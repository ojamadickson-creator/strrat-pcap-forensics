# YARA Rules - STRRAT Malware Detection

> **Case:** 2024-07-30 Traffic Analysis Exercise | **Malware:** STRRAT RAT | **Analyst:** Me

YARA is my go-to for pattern-based detection once I know what I'm looking for. After spending hours in Wireshark mapping out the STRRAT infection, I had a solid understanding of the network indicators, protocol behavior, and likely file-based artifacts. These YARA rules translate that hands-on knowledge into automated detection you can deploy across your environment.

I organized these into three categories: network-based rules for traffic analysis and PCAP hunting, file-based rules for endpoint detection, and memory-based rules for incident response and forensics. Each one is tuned based on what I actually observed during the investigation — not just theoretical IOCs from a threat intel feed, but the real bytes I saw on the wire.

---

## 1. Network-Based Rules

These rules are designed to run against PCAP files, network capture buffers, or proxy logs. They're your first line of defense when you need to find STRRAT C2 traffic in bulk network data.

---

### STRRAT C2 IP Address Detection

```yara
rule STRRAT_C2_Hardcoded_IP {
    meta:
        description = "Detects hardcoded C2 IP address used by STRRAT malware"
        author = "Analyst"
        date = "2024-07-30"
        reference = "Traffic Analysis Exercise - 2024-07-30"
        hash = "N/A - Network indicator"
        severity = "critical"

    strings:
        $ip_plain = "141.98.10.79" ascii wide nocase
        $ip_no_dots = "141981079" ascii wide
        $ip_hex = { 8D 0A 4F }
        $ip_hex_le = { 4F 0A 8D }

    condition:
        any of them
}
```

**What it detects:** This rule looks for the C2 IP address `141.98.10.79` in various encodings that malware authors commonly use to obfuscate network indicators. It catches the plaintext dotted-quad notation, a version with dots stripped, and both big-endian and little-endian hex representations of the IP address bytes.

**Where to deploy it:** Run this against memory dumps from infected endpoints, against raw network capture files (PCAPs), and against any binary files recovered from the victim system. The hex variants are particularly important because many malware families encode IP addresses as DWORD values in their configuration blobs — the bytes `0x8D`, `0x0A`, `0x4F` are `141`, `10`, `79` in decimal.

**Why I wrote it this way:** During my Wireshark investigation, I noticed that 141.98.10.79 was contacted directly without any preceding DNS resolution. That screamed "hardcoded IP" — it's burned into the malware binary somewhere. Malware authors sometimes try to hide IPs by stripping dots or encoding as hex, so I covered all the common variants. The `nocase` on the plaintext string handles any case variations, and `ascii wide` catches both ASCII and Unicode (UTF-16LE) encodings, which is how C# and Java strings are typically stored.

**Limitations:** This IP could change between STRRAT variants or campaigns. This rule is specific to the sample I analyzed. If the attacker rotates IPs, this rule won't catch new variants. Consider this a point-in-time detection, not a universal STRRAT detector.

---

### STRRAT C2 Port Detection

```yara
rule STRRAT_C2_Port_12132 {
    meta:
        description = "Detects hardcoded C2 port 12132 used by STRRAT"
        author = "Analyst"
        date = "2024-07-30"
        reference = "Traffic Analysis Exercise - 2024-07-30"
        hash = "N/A - Network indicator"
        severity = "high"

    strings:
        $port_ascii = "12132" ascii wide
        $port_hex_be = { 00 2F 64 }
        $port_hex_le = { 64 2F 00 }
        $port_string = ":12132" ascii wide

    condition:
        any of them
}
```

**What it detects:** Port 12132, which STRRAT uses as its default C2 communication port. The rule catches the port in ASCII string form, as a 16-bit integer in both big-endian and little-endian hex, and with the colon prefix you'd see in URL-style configurations.

**Where to deploy it:** Same as the IP rule — memory dumps, PCAPs, and recovered binaries. The `:12132` string variant is particularly useful against configuration files, batch scripts, or PowerShell download cradles where the C2 address might be constructed as a URL.

**Why I wrote it this way:** Port 12132 isn't registered to any standard service, which makes it a reasonably unique indicator. I used `12132` as a standalone ASCII string because it's likely to appear in the malware's socket connection code — something like `connect(socket, "141.98.10.79", 12132)`. The hex variants (`0x2F64` = 12132 in decimal) catch the port stored as a binary WORD value, which is how many Windows API calls expect it. I kept the colon-prefixed version separate because `:12132` is a stronger indicator than just `12132` — the latter could appear in benign contexts like version numbers or document IDs.

**Limitations:** Port 12132 is configurable in STRRAT's builder. If the attacker used a custom port, this rule misses. Also, the standalone string `12132` could theoretically appear in legitimate software as a product code or random number. The `:12132` variant is much more specific but also easier for attackers to change (they might use `":" + "12132"` string concatenation to evade).

---

### STRRAT Protocol Signature Detection

```yara
rule STRRAT_Protocol_Signature {
    meta:
        description = "Detects STRRAT custom protocol signature strings in network or memory data"
        author = "Analyst"
        date = "2024-07-30"
        reference = "Traffic Analysis Exercise - 2024-07-30"
        hash = "N/A - Protocol indicator"
        severity = "critical"

    strings:
        $sig_ping = "ping" ascii wide nocase
        $sig_strrat = "STRRAT" ascii wide nocase
        $protocol_marker = "|STRRAT|" ascii wide nocase
        $protocol_delim = "|" ascii wide
        $cmd_prefix = "CMD|" ascii wide nocase
        $resp_prefix = "RESP|" ascii wide nocase

    condition:
        ($sig_ping and $sig_strrat) or
        $protocol_marker or
        ($cmd_prefix and $resp_prefix) or
        (#protocol_delim > 10 and $sig_strrat)
}
```

**What it detects:** The custom protocol markers that STRRAT uses in its C2 communication. STRRAT's protocol uses pipe-delimited messages with specific command and response prefixes. The `ping` string appears in keepalive/heartbeat messages, and `STRRAT` is the malware's self-identifier in protocol handshake and version messages.

**Where to deploy it:** This is your bread-and-butter network detection rule. Run it against PCAP files, network tap captures, and proxy logs. It's also highly effective against memory dumps — the protocol strings will be in the malware's working memory while it's actively communicating. Network sensors (Zeek, Suricata with file extraction) can run this against reconstructed TCP sessions.

**Why I wrote it this way:** I used a multi-condition approach because STRRAT's protocol has several distinguishable features, and I wanted the rule to fire on any of them. The primary condition `($sig_ping and $sig_strrat)` requires both the heartbeat string and the malware name — together they're extremely specific. The `$protocol_marker` condition catches the literal `|STRRAT|` string which appears in protocol version negotiation. The `($cmd_prefix and $resp_prefix)` looks for both command and response delimiters in the same sample, which indicates a full C2 conversation capture. The final condition `(#protocol_delim > 10 and $sig_strrat)` catches pipe-heavy protocol traffic (STRRAT uses pipes as field separators extensively) combined with the malware identifier. The count operator `#` requires more than 10 pipe delimiters, which filters out random text that happens to contain a pipe or two.

**Limitations:** If STRRAT's operator recompiles the malware with different protocol strings — changing `STRRAT` to something else, or using different delimiters — this rule breaks. The pipe delimiter in particular is somewhat common in other protocols and data formats. The count-based condition helps reduce false positives but isn't perfect. This rule is best deployed alongside the IP and port rules as a multi-factor detection.

---

## 2. File-Based Rules

These rules target the STRRAT payload files themselves — the JAR file, any dropper scripts, and configuration artifacts left on disk.

---

### STRRAT Java Archive Detection

```yara
rule STRRAT_JAR_Indicators {
    meta:
        description = "Detects STRRAT Java-based RAT artifacts in JAR and class files"
        author = "Analyst"
        date = "2024-07-30"
        reference = "Traffic Analysis Exercise - 2024-07-30"
        hash = "N/A - File indicator"
        severity = "critical"
        filetype = "JAR, CLASS"

    strings:
        $jar_manifest = "META-INF/MANIFEST.MF" ascii
        $main_class = "Main-Class:" ascii
        $strrat_class = "StrRat" ascii wide nocase
        $strrat_pkg = "strrat/" ascii wide nocase
        $rat_indicator = "RemoteAccess" ascii wide nocase
        $rat_indicator2 = "Remote_Access" ascii wide nocase
        $socket_code = "java/net/Socket" ascii
        $runtime_exec = "java/lang/Runtime" ascii
        $exec_method = "exec(" ascii
        $screenshot = "Robot" ascii
        $keylogger = "KeyListener" ascii
        $clipboard = "Clipboard" ascii
        $persistence1 = "Run" ascii wide
        $persistence2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

    condition:
        uint32(0) == 0x504B0304 and      // ZIP/JAR magic
        ($jar_manifest and $main_class) and
        (
            any of ($strrat_*) or
            any of ($rat_indicator*) or
            ($socket_code and $runtime_exec and $exec_method) or
            ($screenshot and $keylogger and $clipboard) or
            any of ($persistence*)
        )
    }
```

**What it detects:** Java Archive (JAR) files that contain STRRAT or similar Java-based RAT indicators. The rule looks for the JAR file structure (which is a ZIP file with a specific manifest), combined with STRRAT-specific class names, RAT functionality indicators (socket networking, Runtime.exec for command execution), and RAT feature code (screenshot capture via Robot class, keylogging, clipboard access).

**Where to deploy it:** Endpoint detection systems, email gateways (to catch JAR attachments), web proxies (to catch JAR downloads), and file integrity monitoring systems. This is a great rule for scanning user download directories, temp folders, and email attachment caches. The download from repo1.maven.org I observed in the pcap was almost certainly a JAR file — STRRAT is Java-based and often masquerades as legitimate Maven artifacts.

**Why I wrote it this way:** I started with `uint32(0) == 0x504B0304` which is the ZIP file magic number (PK..). JAR files are ZIP archives, so this is the mandatory first check. Then I require both JAR manifest indicators to confirm it's actually a Java archive and not just any ZIP file. The STRRAT-specific strings (`StrRat`, `strrat/`) are direct hits — if these are present, it's almost certainly STRRAT. The RAT functionality block catches socket networking combined with Runtime.exec — that's the core of what makes a RAT a RAT: remote socket connections plus local command execution. The feature block (`Robot` + `KeyListener` + `Clipboard`) catches the spyware functionality that STRRAT is known for. Finally, the persistence strings catch the registry Run key entries that STRRAT creates to survive reboots.

**Limitations:** Java-based RATs share a lot of code patterns. The `Socket` + `Runtime.exec` combination could trigger on legitimate remote administration tools or even some enterprise software. The Robot/KeyListener/Clipboard combination is more specific but could still catch legitimate screen capture utilities or accessibility software. The STRRAT-specific strings are the most reliable but only work if the malware author didn't rename the classes. Obfuscated JAR files (ProGuard, Allatori, etc.) will defeat the class name checks entirely.

---

### STRRAT Version String Detection

```yara
rule STRRAT_Version_Strings {
    meta:
        description = "Detects STRRAT version strings and builder artifacts"
        author = "Analyst"
        date = "2024-07-30"
        reference = "Traffic Analysis Exercise - 2024-07-30"
        hash = "N/A - Version indicator"
        severity = "medium"

    strings:
        $ver_10 = "1.0" ascii wide
        $ver_11 = "1.1" ascii wide
        $ver_12 = "1.2" ascii wide
        $ver_20 = "2.0" ascii wide
        $ver_21 = "2.1" ascii wide
        $ver_22 = "2.2" ascii wide
        $ver_23 = "2.3" ascii wide
        $ver_24 = "2.4" ascii wide
        $ver_30 = "3.0" ascii wide
        $ver_31 = "3.1" ascii wide
        $ver_32 = "3.2" ascii wide
        $ver_33 = "3.3" ascii wide
        $ver_34 = "3.4" ascii wide
        $builder_tag = "STRRAT Builder" ascii wide nocase
        $builder_by = "str-master" ascii wide nocase
        $builder_sig = "CrimeSquad" ascii wide nocase

    condition:
        any of ($ver_*) and $builder_tag or
        $builder_by or
        ($builder_sig and any of ($ver_*))
}
```

**What it detects:** Version strings and builder signatures embedded in STRRAT binaries. STRRAT has gone through many versions (1.0 through 3.x at the time of this analysis), and the builder tools often leave identifying strings in the generated payloads.

**Where to deploy it:** This is a hunting rule, not a high-fidelity detection. Run it during threat hunting sweeps across endpoints, in malware sandboxes when analyzing unknown JAR files, and in memory forensics when you suspect STRRAT but the primary indicators didn't fire. It's also useful for attribution — the version string can tell you which builder was used and potentially which threat actor group is operating.

**Why I wrote it this way:** Version-based detection is inherently fragile — every new version breaks your rule. But STRRAT's development has been relatively slow, and the version strings are deeply embedded in the malware's infrastructure. I listed versions from 1.0 through 3.4 because those are the known versions at the time of writing. The `builder_tag`, `builder_by`, and `builder_sig` strings come from known STRRAT builder tool artifacts. The condition is structured to require a version string PLUS a builder indicator — this prevents the rule from firing on random software that happens to contain a "1.0" or "2.0" string somewhere. The `str-master` and `CrimeSquad` strings are handles associated with STRRAT's underground distribution.

**Limitations:** This rule will age poorly. When version 3.5 or 4.0 comes out, the rule won't catch it unless manually updated. Builder signatures are also easy to change — a motivated attacker can patch the builder or manually edit the strings. Don't rely on this as your primary detection; use it as a supplementary hunting rule.

---

## 3. Memory-Based Rules

These rules are designed for memory forensics — when you've dumped RAM from an infected machine and need to find STRRAT artifacts without the benefit of filesystem access.

---

### STRRAT Memory Artifact Detection

```yara
rule STRRAT_Memory_Artifacts {
    meta:
        description = "Detects STRRAT strings and protocol artifacts in memory dumps"
        author = "Analyst"
        date = "2024-07-30"
        reference = "Traffic Analysis Exercise - 2024-07-30"
        hash = "N/A - Memory indicator"
        severity = "critical"

    strings:
        // Protocol strings (observed in network traffic)
        $proto_ping = "ping" ascii wide nocase
        $proto_strrat = "STRRAT" ascii wide nocase
        $proto_pipe = "|" ascii wide

        // C2 infrastructure (hardcoded in binary)
        $c2_ip = "141.98.10.79" ascii wide
        $c2_port = ":12132" ascii wide
        $c2_port_raw = "12132" ascii wide

        // Java class names
        $class_strrat = "StrRat" ascii wide
        $class_socket = "java.net.Socket" ascii wide
        $class_runtime = "java.lang.Runtime" ascii wide

        // Persistence indicators
        $reg_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg_runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide

        // RAT feature strings
        $feat_socks = "SOCKS" ascii wide
        $feat_remote = "Remote Desktop" ascii wide
        $feat_keylog = "Keylogger" ascii wide
        $feat_clipboard = "Clipboard" ascii wide
        $feat_password = "Password" ascii wide
        $feat_stealer = "Stealer" ascii wide

    condition:
        3 of ($proto_*) and
        (
            any of ($c2_*) or
            any of ($class_*) or
            any of ($reg_*) or
            2 of ($feat_*)
        )
    }
```

**What it detects:** STRRAT-specific artifacts in Windows memory dumps (RAM captures from infected machines). This rule is tuned for volatility — memory contents change as the malware executes, so it looks for multiple independent indicators and uses a scoring approach rather than requiring all strings to be present.

**Where to deploy it:** This is your incident response rule. Deploy it when you're analyzing a memory dump from a potentially infected endpoint using tools like Volatility, Rekall, or MemProcFS. Run it against the full memory image, against individual process dumps (especially java.exe or javaw.exe processes), and against extracted memory sections from suspicious processes. The rule is also valuable in automated sandbox environments that capture memory snapshots during execution.

**Why I wrote it this way:** Memory is messy. Strings get fragmented, overwritten, or paged out. I structured this rule with two tiers: protocol strings (which should be present if the malware is actively communicating) and infrastructure/feature strings (which prove it's STRRAT specifically). The outer condition requires at least 3 of the protocol strings — `ping`, `STRRAT`, and pipe delimiters are usually all present in active C2 memory buffers. The inner condition then requires at least one hit from any of the other categories: C2 infrastructure, Java class names, registry persistence strings, or RAT feature strings. This tiered approach gives you resilience against memory fragmentation — even if some strings are missing, the rule still fires if enough indicators are present.

**Limitations:** Memory forensics is inherently unreliable compared to disk or network analysis. If the system was rebooted recently, the malware might not have loaded all its strings into memory yet. If the malware is packed or encrypted in memory (some STRRAT variants use Java obfuscators), the plaintext strings won't be visible. Java's garbage collector can also move or collect string objects, causing them to disappear from memory. This rule works best when the memory dump was taken while the malware was actively communicating with its C2 server — during the C2 session, the protocol strings are guaranteed to be in memory buffers.

---

## Deployment Recommendations

Here's how I'd deploy these rules in a real SOC environment based on what I learned during this investigation:

| Rule | Deployment Location | Priority | False Positive Risk |
|------|-------------------|----------|-------------------|
| STRRAT_C2_Hardcoded_IP | Network sensors, IDS, proxy logs | P1 - Critical | Very Low |
| STRRAT_C2_Port_12132 | Network sensors, PCAP analysis | P1 - Critical | Low |
| STRRAT_Protocol_Signature | Network sensors, memory forensics | P1 - Critical | Low-Medium |
| STRRAT_JAR_Indicators | Email gateway, endpoint AV, proxy | P1 - Critical | Medium |
| STRRAT_Version_Strings | Malware sandbox, threat hunting | P3 - Low | Medium |
| STRRAT_Memory_Artifacts | Volatility/Rekall memory analysis | P1 - Critical | Low |

**Pro tip from the investigation:** The most effective detection in this case was the combination of IP + port + protocol signature. No single indicator is perfect — the IP can change, the port can be reconfigured, and the protocol strings can be modified. But the *combination* of a direct IP connection to a non-standard port with PSH+ACK-heavy traffic and pipe-delimited protocol messages? That's STRRAT's fingerprint. When writing detection rules, think in terms of multi-factor detection rather than single silver-bullet indicators. The attackers can change one thing easily. Changing all three simultaneously while maintaining functionality is much harder.

---

*These rules are living documents. STRRAT's authors are actively developing the malware, and new versions may break these rules. I recommend combining YARA-based detection with behavioral monitoring (watching for java.exe making unusual outbound TCP connections) and network anomaly detection (flagging sustained connections to non-standard ports) for defense in depth.*
