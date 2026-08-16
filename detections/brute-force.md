# Brute Force Detection

## Objective

Detect repeated failed Windows login attempts using Windows Security Event ID 4625 and Splunk.

## Lab Environment

- Windows 10 endpoint
- Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise
- Windows Security Event Logs

## Attack Simulation

Multiple intentional failed login attempts were generated against a test Windows account.

The activity generated Windows Security Event ID 4625.

## Detection Logic

The detection looks for 5 or more failed login attempts
within a 5-minute window.

## Splunk Query

```spl
index=main "EventID>4625"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)"
| bin _time span=5m
| stats count as FailedAttempts by _time host TargetUserName IpAddress
| where FailedAttempts >= 5
| sort -_time
