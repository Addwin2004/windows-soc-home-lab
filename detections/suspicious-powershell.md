# Suspicious PowerShell Execution

## Objective

Detect potentially suspicious PowerShell activity by monitoring
PowerShell process creation and identifying the use of
`-ExecutionPolicy Bypass`.

## Log Source

- **Log Source:** Sysmon
- **Event ID:** 1
- **Event:** Process Creation
- **Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

## Lab Simulation

A controlled PowerShell command was executed on the Windows 10
lab endpoint using `-ExecutionPolicy Bypass`.

The command was intentionally harmless and was used only to
generate a detectable security event.

Example:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC Lab PowerShell Test'"

<img width="940" height="441" alt="image" src="https://github.com/user-attachments/assets/7b21a78d-38ca-480d-aaef-600199b69bb5" />
