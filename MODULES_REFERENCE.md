# Jio Cybersecurity Suite — JCS1 Attack Modules Reference

Use these keywords in your prompt to trigger specific security audit modules. You can combine multiple modules in a single command (e.g., "scan and ddos the target").

## Available Modules

### 1. Port Scan
**Keywords:** `scan`, `recon`, `discovery`, `port`  
**What it does:** Active TCP port enumeration against the target to identify open services and listening ports.  
**Example prompt:** "Run a port scan on 10.32.200.194"  
**Real behavior:** Genuine socket-based TCP connection attempts to discover open ports.

### 2. Web Fuzzer / Directory Enumeration
**Keywords:** `web`, `fuzz`, `directory`, `crawl`  
**What it does:** HTTP directory fuzzing to probe for hidden web endpoints and configuration files on port 80/443.  
**Example prompt:** "Fuzz the web directories on the target"  
**Real behavior:** Sends HTTP requests probing common paths and looking for 200/302 responses.

### 3. SSH Credential Audit / Brute Force
**Keywords:** `ssh`, `brute`, `password`, `audit`  
**What it does:** Attempts SSH login with a hardcoded list of common credentials. If successful, runs post-exploitation commands (system info, file listing, flag extraction).  
**Example prompt:** "Brute force SSH on 10.32.200.194"  
**Real behavior:** Genuine SSH authentication attempts via paramiko. **Will actually compromise the target if credentials match.**

### 4. DDoS UDP Flood Simulator
**Keywords:** `ddos`, `flood`, `dos`, `udp`  
**What it does:** Sends a burst of UDP packets to a target port to test NIDS/IDS detection and rate-limiting thresholds.  
**Parameters:** Packet count (default 250, max 5000)  
**Example prompt:** "ddos on 10.32.200.194 with 500 packets"  
**Real behavior:** Genuine UDP socket sends; real packet transmission at wire speed.

### 5. ARP Spoofing / MitM
**Keywords:** `mitm`, `arp`, `spoof`  
**What it does:** Simulates ARP cache poisoning to evaluate local network lateral movement detection.  
**Example prompt:** "Test ARP spoofing on the network around 10.32.200.194"  
**Real behavior:** Currently simulated; actual ARP packets may or may not be sent depending on OS/permissions.

### 6. Packet Fragmentation / Session Splitting Evasion
**Keywords:** `frag`, `fragment`, `split`  
**What it does:** Tests whether NIDS can correctly reassemble fragmented TCP payloads.  
**Example prompt:** "Run a fragmentation evasion audit on port 80"  
**Real behavior:** Sends intentionally fragmented TCP packets to evaluate sensor signature matching.

### 7. SSL/TLS Encryption Tunneling Audit
**Keywords:** `ssl`, `tls`, `tunnel`, `encrypt`  
**What it does:** Wraps test payloads in SSL/TLS handshakes on port 443 to verify if NIDS can inspect encrypted traffic.  
**Example prompt:** "Test SSL tunneling on the target"  
**Real behavior:** Establishes SSL connections and sends probe payloads through encrypted channels.

### 8. Protocol Evasion (TCP Flag Manipulation)
**Keywords:** `evasion`, `protocol`, `flag`, `sequence`  
**What it does:** Sends TCP packets with unusual/invalid flag combinations to test NIDS state machine handling.  
**Example prompt:** "Run protocol evasion tests against the target"  
**Real behavior:** Crafts and transmits TCP packets with non-standard flag alignments.

### 9. Sensor Flooding (NIDS Stress Test)
**Keywords:** `sensor`, `overload`  
**What it does:** Sends a dense burst of multi-protocol packets to stress-test NIDS CPU/memory under high load.  
**Example prompt:** "Stress test the network sensor with flooding"  
**Real behavior:** Rapid packet transmission designed to spike NIDS processing load.

---

## Example Prompts

- **"Scan 10.32.200.194 and run a port discovery"** → Triggers `port_scan`
- **"Brute force SSH on 10.32.200.194"** → Triggers `ssh_audit`
- **"DDoS the target with 750 packets"** → Triggers `ddos_flood` with 750-packet burst (capped at 5000)
- **"Run all modules on 10.32.200.194"** → Triggers all 9 modules in sequence
- **"Fuzz web directories and test evasion"** → Triggers `web_fuzz` + `protocol_evasion`

---

## Operator Notes

- **Module interdependencies:** SSH audit (`ssh_audit`) will only extract loot if credentials succeed. Loot is visible in the "Harvested Loot Bin".
- **Real vs. Simulated:** Modules like DDoS, SSH audit, and packet fragmentation send **real network traffic**. Use only on authorized targets.
- **Authorization:** Ensure you own or have explicit permission to test any target before running these modules.
- **Report accuracy:** All module summaries now reflect real measured results (packet counts, durations, success/failure), not fabricated numbers.

---

*Last updated: 2026-07-15*
