# CoEDR v3.0 - Advanced Threat Hunting & Detection Engine

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

CoEDR is a highly advanced, production-grade Endpoint Detection and Response (EDR) agent built for Windows. It provides real-time monitoring of system activities, FIM (File Integrity Monitoring), automated response actions, and proactively hunts for sophisticated threats bypassing traditional security layers.

## 🌟 Key Features

- **Extreme Detection Engine:** Powered by a Sigma-style JSON rule engine capable of identifying cutting-edge APT techniques such as **ETW Blinding, BYOVD (Vulnerable Drivers), DCSync, Kerberoasting, and Direct Syscalls**.
- **Behavioral Chaining:** Detects multi-stage attacks by linking related events (e.g., detecting when a macro execution is followed by an AMSI bypass and an outbound C2 connection).
- **YARA-inspired Pattern Scanning:** Employs built-in regex-based pattern matching on process memory and command lines to instantly spot obfuscated PowerShell, hex-encoded shellcode, and ransomware extensions.
- **Proactive Threat Hunting:** Features a one-shot hunting mode that scans running processes for hidden modules, hollowed processes, and high-entropy command lines.
- **Dynamic Response Actions:** Automated and manual capabilities to **Kill**, **Suspend**, or **Quarantine** threats securely before they spread.
- **Threat Intelligence Caching:** In-memory caching for known malicious IPs, domains, and file hashes for rapid enrichment.
- **Professional SOC Dashboard:** A sleek, dark-mode Tkinter GUI for real-time monitoring and alert triage.

## 🏗️ Architecture

- `edr_agent.py`: The core runtime engine handling real-time telemetry polling, behavioral tracking, FIM, pattern scanning, and the GUI dashboard.
- `rules/detection_rules.json`: The rule definitions encompassing everything from basic living-off-the-land (LOLBin) misuse to advanced defense evasion techniques.
- `config/watch_config.json`: Configuration mapping for polling intervals, FIM paths, and system tuning.
- `edr_telemetry.json`: Tamper-evident NDJSON (Newline Delimited JSON) logs ready for SIEM ingestion.

## 🚀 Quick Start

1. **Clone the repository and open PowerShell:**
```powershell
cd C:\Users\aahmv\OneDrive\Desktop\EDR
```

2. **Install dependencies:**
```powershell
python -m pip install -r requirements.txt
```

3. **Run the Agent / SOC Dashboard:**
```powershell
python edr_agent.py --gui
```
*(Note: Run PowerShell as Administrator for maximum visibility into SYSTEM-level processes and full telemetry extraction).*

4. **Run a Proactive Threat Hunt:**
```powershell
python edr_agent.py --hunt
```

## 🛡️ Cutting-Edge Detection Capabilities

CoEDR comes pre-configured with rules mapped directly to MITRE ATT&CK to catch the most evasive threats:

- **Defense Evasion & Unhooking:** Detects Direct Syscalls (Hell's Gate, Halo's Gate), AMSI bypassing via .NET reflection, ETW patching, and SilentProcessExit persistence.
- **Identity & Credential Theft:** Identifies DCSync attacks (mimikatz), Kerberoasting/AS-REP Roasting (Rubeus), Shadow Credentials (Whisker), and LSASS dumping via Windows Error Reporting (WerFault) or `comsvcs.dll`.
- **Advanced Execution:** Catches MSBuild inline C# execution, Forfiles evasion, and execution from NTFS Alternate Data Streams (ADS).
- **Ransomware & Exploits:** Stops Volume Shadow Copy deletion (`vssadmin`), detects PrintNightmare spooler child processes, and flags known ransomware extensions.
- **Privilege Escalation:** Blocks Bring Your Own Vulnerable Driver (BYOVD) attacks targeting FltMgr and EDR drivers.

## ⚙️ Background Installation

To deploy the EDR agent silently across an environment as a Windows Scheduled Task:

**Install:**
```powershell
.\scripts\install_windows_task.ps1
```

**Uninstall:**
```powershell
.\scripts\uninstall_windows_task.ps1
```

## ⚠️ Notes and Limitations

This project leverages user-mode telemetry (via `psutil`) for extreme portability and ease of deployment without requiring a signed kernel driver. While highly capable of detecting modern attacks through command-line auditing and FIM, an enterprise production rollout may choose to supplement this agent with ETW (Event Tracing for Windows) or Sysmon integration for deeper kernel-level introspection.
