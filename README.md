# Windows MDM Endpoint Security Hardening Kit

Practical PowerShell automation for Windows endpoint security hardening, auditing, drift detection, and rapid triage in MDM-managed environments.

> Status: early iteration — validate in a lab before production use!

## What this repo is
This repository contains standalone PowerShell scripts to assess and (where applicable) remediate security posture on Windows endpoints, with a focus on managed fleets (MDM/Intune-style operations).

Typical use cases:
- Baseline verification and drift detection.
- Security hygiene checks (local admin, LAPS, logging, firewall, auditing).
- Update/health proofing and readiness.
- Incident response collection and fast triage.

## Requirements
- Windows 10/11 or Windows Server (depending on script scope).
- PowerShell 5.1+ (some scripts may also work with PowerShell 7.x).
- Administrator rights for scripts that change system settings.
- Optional: Sysmon, Microsoft Defender, BitLocker, WinGet (depending on script).

## Quick start (safe defaults)
### 1) Clone
```
git clone https://github.com/<your-org-or-user>/win-mdm-security-hardening-kit.git
cd win-mdm-security-hardening-kit
```

### 2) Unblock downloaded files (if needed)
```
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File
```

### 3) Run with transcript logging
```
Start-Transcript -Path ".\run-$(Get-Date -Format yyyyMMdd-HHmmss).log"
# Prefer -WhatIf / -Confirm if the script supports it
.\NAME_OF_SCRIPT.ps1
Stop-Transcript
```

## How to run (deployment-friendly patterns)
### Interactive (PowerShell)
```
# Example: run a single script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\NAME_OF_SCRIPT.ps1
```

### Batch wrapper (CMD)
```
@echo off
set "SCRIPT=%~dp0\NAME_OF_SCRIPT.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
```

### VBScript wrapper (legacy)
```
Option Explicit
Dim sh, cmd
Set sh = CreateObject("WScript.Shell")
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & _
      CreateObject("Scripting.FileSystemObject").GetAbsolutePathName(".\NAME_OF_SCRIPT.ps1") & """"
sh.Run cmd, 1, True
```

## Script inventory
<details>
<summary>Click to expand the full list of scripts</summary>

- 01-ASR-Defender-Allowlist.ps1
- 02-LAPS-Hygiene.ps1
- 03-LocalAdmins-Guardrail.ps1
- 04-OfficeBrowser-Hardening-Proof.ps1
- 05-WUFB-Proofing.ps1
- 06-UpdateHealth-SSU-Proof.ps1
- 07-ScheduledTasks-Hygiene.ps1
- 08-WinGet-SelfHeal.ps1
- 09-SupportBundle.ps1
- 10-SupportBundle-Parser.ps1
- 11-IOC-Sweep-Defender.ps1
- 12-Suspicious-Artifact-Grabber.ps1
- 13-LSASS-CG-HVCI-VBS.ps1
- 14-SecureRemoteAccessGuardrails.ps1
- 15-HardwareTPM-Audit.ps1
- 16-Sysmon-Config-Updater.ps1
- 17-Sysmon-Rule-Drift-Sensor.ps1
- 18-Firewall-Baseline.ps1
- 19-Software-Audit.ps1
- 20-MissingPatch-Notification.ps1
- 21-EmergencyKillSwitch.ps1
- 22-SMB-Encryption-Enforcer.ps1
- 23-BitLocker-Operations-Audit.ps1
- 24-Cert-AutoEnrollment-Health.ps1
- 25-WinGet-Config-Baseline-Runner.ps1
- 26-Get-WinEvent-FastTriage.ps1
- 27-Defender-Health-Audit.ps1
- 28-Join-Identity-Audit.ps1
- 29-Network-Config-Audit.ps1
- 30-Service-Process-Audit.ps1
- 31-PowerShell-Logging-Baseline.ps1
- 32-Firewall-Logging-Audit.ps1
- 33-AdvancedAuditPolicy-Audit.ps1
- 34-TimeSync-Health.ps1
- 35-Storage-Reliability-Audit.ps1
- 36-Backup-Readiness-Audit.ps1
- 37-Remote-Surface-Audit.ps1
- 38-SecurityOptions-Drift.ps1
- 39-CredentialGuard-VBS-AuditRemediate.ps1
- 40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1
- 41-NTLM-Audit-Client.ps1
- 42-Client-SecurityBaseline-Report-IntuneRef.ps1
- 43-AppControlForBusiness-Audit.ps1
- 44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1
- 45-WEF-Client-Forwarding-Readiness-Audit.ps1

</details>

## Safety & risk notes (read before use)
- Some scripts may change security settings (remediation/enforcement). Review code and test in a lab first.
- Prefer staged rollout (ring-based deployment) and explicit approval gates for remediation.
- Keep backups of existing configurations (firewall, audit policy, registry, etc.) before enforcing changes.

## Disclaimer
These scripts are provided “as-is” without warranty. You are responsible for validation, compliance, and safe deployment.
```
