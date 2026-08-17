#  Home SOC Lab

A hands-on Security Operations Center (SOC) home lab built to simulate common security events, collect endpoint and network telemetry, forward logs to Splunk, and investigate suspicious activity using SPL.

The lab focuses on understanding the complete SOC workflow:

**Attack Simulation → Telemetry Collection → Log Forwarding → SIEM Ingestion → Detection → Investigation → Documentation**

---

##  Project Objectives

The main objectives of this project are to:

* Build a small-scale SOC environment using virtual machines.
* Gain hands-on experience with **Splunk Enterprise** and **Splunk Universal Forwarder**.
* Collect endpoint telemetry using **Sysmon**.
* Collect authentication events from Windows Security logs.
* Collect Windows Firewall network activity.
* Generate controlled security events from a Kali Linux machine.
* Investigate security events using **Splunk Search Processing Language (SPL)**.
* Understand how different attacks appear in endpoint and network telemetry.
* Document detections and investigation results using a repeatable workflow.

---

##  Lab Architecture

```text
                         ┌─────────────────────────────┐
                         │        Kali Linux           │
                         │                             │
                         │   Attack Simulation         │
                         │                             │
                         │  • Nmap Port Scanning       │
                         │  • Authentication Attempts  │
                         │  • Network Activity         │
                         │                             │
                         │  IP: 192.168.175.130        │
                         └──────────────┬──────────────┘
                                        │
                                        │ Network Activity
                                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Windows Endpoint                        │
│                                                                 │
│  Windows 11                                                     │
│  IP: 192.168.175.131                                            │
│                                                                 │
│  ┌──────────────────┐   ┌──────────────────┐                    │
│  │      Sysmon      │   │ Windows Security │                    │
│  │                  │   │      Logs        │                    │
│  │ • Process Create │   │ • Logon Events   │                    │
│  │ • Network Events │   │ • Failed Logons  │                    │
│  └────────┬─────────┘   └────────┬─────────┘                    │
│           │                      │                              │
│           └──────────┬───────────┘                              │
│                      │                                          │
│              ┌───────▼────────┐                                 │
│              │ Windows        │                                 │
│              │ Firewall       │                                 │
│              │                │                                 │
│              │ pfirewall.log  │                                 │
│              └───────┬────────┘                                 │
│                      │                                          │
│              Splunk Universal Forwarder                         │
│                      │                                          │
└──────────────────────┼──────────────────────────────────────────┘
                       │
                       │ TCP 9997
                       ▼
              ┌─────────────────────┐
              │   Splunk Enterprise │
              │                     │
              │   SIEM / Analysis   │
              │                     │
              │  • Log Ingestion    │
              │  • SPL Searches     │
              │  • Detection        │
              │  • Investigation    │
              └─────────────────────┘
```

---

##  Lab Environment

| Component                      | Purpose                                  |
| ------------------------------ | ---------------------------------------- |
| **Kali Linux**                 | Attack simulation and security testing   |
| **Windows 11**                 | Monitored endpoint                       |
| **Splunk Enterprise**          | SIEM, log analysis and investigation     |
| **Splunk Universal Forwarder** | Log collection and forwarding            |
| **Sysmon**                     | Endpoint process and network telemetry   |
| **Windows Security Logs**      | Authentication and security events       |
| **Windows Firewall**           | Network connection filtering and logging |
| **VMware**                     | Virtualization platform                  |

### Network Configuration

| System        | IP Address        | Role               |
| ------------- | ----------------- | ------------------ |
| Kali Linux    | `192.168.175.130` | Attack simulation  |
| Windows 11    | `192.168.175.131` | Monitored endpoint |
| Splunk Server | `192.168.198.1`   | SIEM               |

The Windows endpoint uses the Splunk Universal Forwarder to send collected telemetry to Splunk Enterprise over **TCP port 9997**.

---

#  Data Flow

The lab follows a simplified SOC telemetry pipeline.

```text
             ATTACK / ACTIVITY
                    │
                    ▼
              Kali Linux
                    │
                    │
                    ▼
            Windows Endpoint
                    │
       ┌────────────┼────────────┐
       │            │            │
       ▼            ▼            ▼
    Sysmon       Security     Firewall
       │            │            │
       └────────────┼────────────┘
                    │
                    ▼
       Splunk Universal Forwarder
                    │
                    │ TCP 9997
                    ▼
          Splunk Enterprise
                    │
                    ▼
              SPL Searches
                    │
                    ▼
          Detection & Analysis
                    │
                    ▼
            Investigation
                    │
                    ▼
             Documentation
```

---

#  Telemetry Sources

## 1. Sysmon

Sysmon is configured on the Windows endpoint to provide additional endpoint telemetry.

The current configuration monitors:

* **Process Creation**
* **Network Connections**

Important Sysmon events used in the lab include:

| Event ID | Description        |
| -------- | ------------------ |
| **1**    | Process Creation   |
| **3**    | Network Connection |

Sysmon events are forwarded to Splunk using:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

---

## 2. Windows Security Logs

Windows Security logs provide authentication and security-related telemetry.

The lab uses these events to investigate failed authentication attempts.

Example:

```text
Event ID: 4625
```

Event ID 4625 represents a failed logon attempt.

The logs are forwarded using:

```text
XmlWinEventLog:Security
```

---

## 3. Windows Firewall Logs

Windows Firewall logging is enabled to record allowed and blocked network traffic.

The firewall log is located at:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The log is monitored by the Splunk Universal Forwarder using:

```text
monitor://C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

The firewall events are indexed into:

```text
index=main
```

with the sourcetype:

```text
windows:firewall
```

---

#  Detection Scenarios

The lab currently contains three documented detection scenarios.

| Detection                        | Data Source      | Primary Tool |
| -------------------------------- | ---------------- | ------------ |
|  Brute Force / Failed Logons   | Windows Security | Splunk       |
|  Suspicious PowerShell Activity | Sysmon           | Splunk       |
|  Network Port Scanning         | Windows Firewall | Splunk       |

Detailed detection documentation is available in the [`detections/`](./detections/) directory.

---

#  1. Brute Force Detection

A controlled series of failed authentication attempts was generated against the Windows endpoint.

Windows Security Event ID **4625** was used to identify failed logon attempts.

Example SPL investigation:

```spl
index=main "4625"
```

The investigation can be further filtered around the affected username, source information and time period.

### Investigation Goal

Identify:

* Repeated failed authentication attempts
* Targeted accounts
* Authentication type
* Source information
* Time of activity

### Detection Documentation

See:

[`detections/brute-force.md`](./detections/brute-force.md)

---

#  2. Suspicious PowerShell Activity

PowerShell activity was generated on the Windows endpoint and investigated using endpoint telemetry.

Sysmon Process Creation events provide information about processes executed on the machine.

The investigation focuses on identifying:

* PowerShell execution
* Parent/child process relationships
* Executed commands
* User context
* Process paths
* Suspicious command-line activity

The purpose of this detection is to demonstrate how endpoint process telemetry can be used to identify potentially suspicious PowerShell activity.

### Detection Documentation

See:

[`detections/suspicious-powershell.md`](./detections/suspicious-powershell.md)

---

# 🔎 3. Network Port Scanning

A TCP Connect scan was performed from Kali Linux against the Windows endpoint.

### Attack Command

```bash
nmap -sT -p 1-1000 192.168.175.131
```

The scan reported:

```text
Host is up.

Not shown: 1000 filtered tcp ports (no-response)
```

The Windows Firewall recorded the connection attempts as dropped traffic.

Example:

```text
DROP TCP 192.168.175.130 192.168.175.131 ... 135 ... RECEIVE
DROP TCP 192.168.175.130 192.168.175.131 ... 139 ... RECEIVE
DROP TCP 192.168.175.130 192.168.175.131 ... 445 ... RECEIVE
```

The events were subsequently ingested into Splunk.

### Splunk Investigation

```spl
index=main sourcetype=windows:firewall "DROP" "192.168.175.130"
| table _time _raw
| sort -_time
```

This search returned multiple firewall events originating from the Kali Linux host.

### Detection Documentation

See:

[`detections/nmap-port-scan.md`](./detections/nmap-port-scan.md)

---

# 🧩 Splunk Configuration

The Windows endpoint uses the Splunk Universal Forwarder to collect multiple telemetry sources.

Current input configuration includes:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[WinEventLog://Security]
disabled = 0
index = main
renderXml = true
sourcetype = XmlWinEventLog:Security

[monitor://C:\Windows\System32\LogFiles\Firewall\pfirewall.log]
disabled = 0
index = main
sourcetype = windows:firewall
```

The Universal Forwarder sends the collected data to the Splunk Enterprise instance over:

```text
TCP/9997
```

---

#  Investigation Methodology

Each detection follows a basic SOC investigation workflow.

```text
1. Generate controlled activity
            ↓
2. Identify relevant telemetry
            ↓
3. Confirm logs are being collected
            ↓
4. Search events in Splunk
            ↓
5. Filter suspicious activity
            ↓
6. Examine source / destination / user / process
            ↓
7. Determine whether activity is expected
            ↓
8. Document findings
```

The project focuses not only on generating attacks, but on understanding how those activities appear in security telemetry.

---

# 🧪 Example SPL Searches

### Search all events

```spl
index=main
```

### Failed Windows logons

```spl
index=main "4625"
```

### Firewall dropped traffic

```spl
index=main sourcetype=windows:firewall "DROP"
```

### Traffic from Kali

```spl
index=main sourcetype=windows:firewall "192.168.175.130"
```

### Dropped traffic from Kali

```spl
index=main sourcetype=windows:firewall "DROP" "192.168.175.130"
```

### Sysmon network connections

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
```

### Sysmon process creation

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

---

# 📁 Repository Structure

The repository is intentionally kept small and focused on the most relevant project artifacts.

```text
home-soc-lab/
│
├── README.md
│
├── detections/
│   ├── brute-force.md
│   ├── suspicious-powershell.md
│   └── nmap-port-scan.md
│
└── screenshots/
    ├── brute-force/
    ├── powershell/
    └── port-scanning/
```

The repository does **not** contain large log dumps or VM files. Screenshots and concise detection documentation are used to demonstrate the work while keeping the repository lightweight.


---

#  Security & Ethical Considerations

All attack simulations in this project were performed in an isolated lab environment using personally controlled virtual machines.

The activities were conducted for defensive security learning and SOC detection development.

No unauthorized systems or third-party infrastructure were targeted.

---

#  Skills Demonstrated

This project provided hands-on experience with:

* SIEM implementation
* Splunk Enterprise
* Splunk Universal Forwarder
* Splunk SPL
* Sysmon
* Windows Event Logs
* Windows Security Event Analysis
* Windows Firewall Logging
* Network Security Monitoring
* Log Collection and Forwarding
* Security Event Investigation
* Attack Simulation
* Network Reconnaissance Detection
* Authentication Attack Detection
* PowerShell Activity Monitoring
* Basic SOC Investigation Workflow
* VMware-based Security Lab Deployment

---

#  Future Improvements

Possible future improvements include:

* Building a dedicated Splunk SOC dashboard
* Creating correlation searches for repeated suspicious activity
* Adding automated alerting
* Adding more Sysmon telemetry
* Creating risk-based detection rules
* Adding additional attack scenarios
* Developing an incident investigation workflow
* Adding MITRE ATT&CK mapping across all detections
* Introducing a dedicated Linux telemetry source

---

# 📌 Project Summary

This project demonstrates a small but functional SOC environment designed around practical security monitoring.

The lab connects **attack simulation, endpoint telemetry, network telemetry, centralized log collection and SIEM investigation** into a single workflow.

Rather than simply installing security tools, the project focuses on understanding how security events are generated, collected, searched and investigated.

> **Attack → Telemetry → SIEM → Detection → Investigation → Documentation**
