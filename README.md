# Windows SOC Home Lab

A hands-on SOC lab built using Windows 10, Sysmon,
Splunk Universal Forwarder, Splunk Enterprise and Kali Linux.

## Architecture

Kali Linux
     ↓
Windows 10 + Sysmon
     ↓
Splunk Universal Forwarder
     ↓
Splunk Enterprise
     ↓
Detection & Investigation

## Objectives

- Collect endpoint security telemetry
- Develop SPL-based detections
- Simulate controlled security incidents
- Investigate endpoint and authentication activity
- Build a basic SOC monitoring dashboard

## Security Use Cases

| Use Case | Telemetry | Status |
|---|---|---|
| PowerShell Activity | Sysmon Event ID 1 | ✅ |
| Brute Force | Windows Event ID 4625 | 🔄 |
| Network Scanning | Network/Firewall Logs | 🔄 |
| DoS Traffic Simulation | Web/Network Logs | 🔄 |

## Tools

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows 10
- Kali Linux
- VMware

## Incident Investigations

- Brute Force
- Suspicious PowerShell
- Network Scanning
- Controlled DoS Simulation
