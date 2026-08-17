# Nmap Port Scan Detection

## Detection Overview

This detection identifies TCP connection attempts generated during a port scan against the Windows endpoint. The activity is detected through Windows Firewall logs ingested into Splunk.

| Field            | Value                    |
| ---------------- | ------------------------ |
| Detection Name   | Nmap TCP Port Scan       |
| Attack Technique | Network Service Scanning |
| Attacker         | Kali Linux               |
| Attacker IP      | `192.168.175.130`        |
| Target           | Windows 11               |
| Target IP        | `192.168.175.131`        |
| Data Source      | Windows Firewall         |
| Log Source       | `pfirewall.log`          |
| SIEM             | Splunk Enterprise        |
| Severity         | Medium                   |

## Attack Simulation

A TCP Connect scan was performed from Kali Linux against the first 1,000 TCP ports of the Windows endpoint.

```bash
nmap -sT -p 1-1000 192.168.175.131
```

### Nmap Output

```text
Nmap scan report for 192.168.175.131
Host is up (0.00057s latency).
All 1000 scanned ports on 192.168.175.131 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)
```

The target was reachable, but all 1,000 scanned ports were reported as **filtered**, indicating that the connection attempts were not receiving responses.

## Detection Logic

The Windows Firewall recorded the blocked TCP connection attempts from the Kali Linux host.

Example firewall events:

```text
DROP TCP 192.168.175.130 192.168.175.131 ... 135 ... RECEIVE
DROP TCP 192.168.175.130 192.168.175.131 ... 139 ... RECEIVE
DROP TCP 192.168.175.130 192.168.175.131 ... 445 ... RECEIVE
```

These events indicate that TCP connection attempts from the Kali host were received by the Windows endpoint and dropped by the firewall.

## Splunk Detection

The following SPL query searches for dropped firewall traffic originating from the Kali host:

```spl
index=main sourcetype=windows:firewall "DROP" "192.168.175.130"
| table _time _raw
| sort -_time
```

### Detection Result

The query returned multiple `DROP TCP` events associated with the Kali Linux IP address.

The events included connection attempts against ports such as:

* `135` - Microsoft RPC
* `139` - NetBIOS Session Service
* `445` - SMB

## Investigation Workflow

```text
Kali Linux
    |
    | Nmap TCP Connect Scan
    v
Windows 11
    |
    | Firewall drops TCP attempts
    v
pfirewall.log
    |
    | Splunk Universal Forwarder
    v
Splunk Enterprise
    |
    | SPL Search
    v
Blocked Network Activity Detected
```

## MITRE ATT&CK

**Technique:** T1046 - Network Service Scanning

The simulated activity is consistent with network service scanning because the attacker attempted connections across a range of TCP ports to identify accessible services.

## Result

The detection successfully demonstrated the ability to:

1. Generate controlled network scanning activity from Kali Linux.
2. Capture the resulting connection attempts using Windows Firewall logging.
3. Forward the firewall logs to Splunk using the Splunk Universal Forwarder.
4. Search and investigate the events using SPL.
5. Identify the source and destination IP addresses and targeted ports.

## Evidence

### Nmap Scan

The Kali Linux scan reported:

```text
1000 filtered tcp ports (no-response)
```

### Splunk Detection

Splunk returned multiple firewall events containing:

```text
DROP TCP 192.168.175.130 192.168.175.131
```

This provides the evidence chain:

**Nmap Scan → Windows Firewall DROP → Splunk Ingestion → Detection & Investigation**
<img width="940" height="440" alt="image" src="https://github.com/user-attachments/assets/2796b5f8-0954-4dde-8da3-e66c12e25fbd" />
