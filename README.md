# SOC Analyst Detection & Incident Response Home Lab

## Overview

This project is a hands-on Security Operations Center (SOC) home lab designed to simulate the detection, investigation, and documentation of security events on a Windows endpoint.

The lab uses **Windows 11, Sysmon, Wazuh SIEM, Wireshark, Docker, WSL2, and Oracle VirtualBox** to collect and analyze endpoint and network telemetry.

I acted as the SOC analyst throughout the project by generating controlled security events, investigating the resulting telemetry, correlating evidence across multiple data sources, mapping relevant activity to the MITRE ATT&CK framework, and documenting incident findings and response actions.

---

## Lab Architecture

The environment consists of:

- **SOC-ENDPOINT-01** — Windows 11 monitored endpoint
- **Sysmon** — Enhanced Windows endpoint telemetry
- **Windows Security Event Logs** — Authentication and account-management telemetry
- **Wazuh Agent** — Endpoint log forwarding
- **Wazuh Manager / Indexer / Dashboard** — SIEM platform
- **Docker Desktop + WSL2 Ubuntu** — Wazuh infrastructure
- **Wireshark + Npcap** — Packet capture and network analysis
- **Oracle VirtualBox** — Endpoint virtualization

### Data Flow

```text
SOC-ENDPOINT-01
      |
      |-- Windows Security Logs
      |-- Sysmon Telemetry
      |
      v
  Wazuh Agent
      |
      v
Wazuh Manager
      |
      v
Wazuh Indexer
      |
      v
Wazuh Dashboard
      |
      v
Detection / Investigation / Incident Response

SOC-ENDPOINT-01
      |
      +----> Wireshark
             Network Packet Analysis
```

Architecture and endpoint evidence can be found in the [`Architecture`](Architecture/) folder.

---

## Security Monitoring Configuration

### Windows Endpoint

`SOC-ENDPOINT-01` was configured as the monitored Windows workstation.

Sysmon was installed to provide additional endpoint visibility including:

- Process creation
- Network connections
- DNS queries
- Registry activity
- File creation
- Process tampering
- SHA-256 process hashing

Windows Security auditing provided authentication, account creation, and security-group modification events.

### Wazuh SIEM

A Wazuh single-node environment was deployed using Docker Desktop and WSL2 Ubuntu.

The Windows endpoint was enrolled as a Wazuh agent and the Sysmon Operational event channel was configured for collection.

Successful Sysmon telemetry ingestion and endpoint connectivity were verified through the Wazuh dashboard.

Evidence is available in:

- [`Endpoint-Setup`](Endpoint-Setup/)
- [`Sysmon-Logs`](Sysmon-Logs/)
- [`SIEM`](SIEM/)

---

# Security Investigations

## Incident 01 — Repeated Failed Authentication

### Scenario

Multiple failed interactive authentication attempts were intentionally generated against the `socanalyst` account to simulate suspicious repeated login behavior.

### Detection

- **Windows Event ID:** 4625 — Failed Logon
- **Wazuh Rule ID:** 60122
- **Wazuh Rule Level:** 5
- **Detection:** Logon Failure — Unknown user or bad password
- **MITRE ATT&CK Context:** T1110 — Brute Force

Five failed authentication attempts were generated within approximately ten seconds.

### Investigation

The authentication telemetry was analyzed for:

- Target account
- Endpoint
- Logon type
- Logon process
- Authentication status/substatus
- Repeated-event frequency

The events showed interactive failed authentication attempts against `socanalyst`.

### Analyst Assessment

**True Positive — Benign Security Simulation**

The activity was intentionally generated as part of the lab, but the resulting telemetry demonstrated how repeated authentication failures could be identified and investigated by a SOC analyst.

---

## Incident 02 — Suspicious PowerShell Execution

### Scenario

Controlled PowerShell activity was generated using:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Select-Object -First 10 | Out-File $env:TEMP\process_discovery.txt"
```

The command used `ExecutionPolicy Bypass`, enumerated running processes, and wrote the results to a temporary file.

### Detection

- **Sysmon Event ID:** 1 — Process Creation
- **Wazuh Rule ID:** 92027
- **Wazuh Rule Level:** 4
- **MITRE ATT&CK:** T1059.001 — PowerShell

### Investigation

Sysmon and Wazuh telemetry were analyzed for:

- Executable image
- Complete command line
- User context
- Integrity level
- SHA-256 hash
- Parent process
- Child process
- Execution timestamp

The PowerShell process executed with a **High** integrity level.

The executable SHA-256 observed during the investigation was:

```text
0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46
```

### Analyst Assessment

**True Positive — Benign Security Simulation**

The execution was authorized lab activity, but the combination of PowerShell, `ExecutionPolicy Bypass`, and process enumeration represented activity appropriate for SOC investigation.

---

## Incident 03 — Privileged Group Modification

### Scenario

A temporary local account named `labtest` was created and subsequently added to the local **Administrators** group to simulate unauthorized privilege modification.

### Detection & Investigation

Windows Security auditing captured:

- **Event ID 4720** — User Account Created
- **Event ID 4732** — Member Added to a Security-Enabled Local Group

The investigation correlated the SID assigned to `labtest` during account creation with the member SID recorded when the account was added to the Administrators group.

Event 4732 identified:

```text
Subject: SOC-ENDPOINT-01\socanalyst
Target Group: Administrators
Group SID: S-1-5-32-544
```

This demonstrated how account-management events can be correlated even when an event does not directly display the expected account name.

### Response

After completing the investigation:

- `labtest` was removed from the Administrators group.
- The temporary `labtest` account was deleted.

### SIEM Observation

Wazuh demonstrated ingestion of account-management telemetry during testing; however, the specific Administrators-group Event 4732 was not surfaced in the `wazuh-alerts-*` index during the investigation.

This limitation is documented rather than representing the event as a successful Wazuh alert.

---

## Incident 04 — Network Traffic Investigation

### Scenario

Controlled outbound HTTP traffic was generated from `SOC-ENDPOINT-01` and captured using Wireshark.

The network activity was then correlated with Sysmon endpoint telemetry.

### Wireshark Analysis

Wireshark captured an HTTP request containing:

```text
GET / HTTP/1.1
```

The connection used TCP destination port **80**.

### Sysmon Correlation

Sysmon **Event ID 3 — Network Connection** recorded the corresponding connection.

The following attributes were correlated between Wireshark and Sysmon:

- Source IPv6 address
- Source TCP port `58160`
- Destination IPv6 address
- Destination TCP port `80`
- TCP protocol

Wireshark displayed the destination using compressed IPv6 notation:

```text
2606:4700:10::6814:179a
```

Sysmon displayed the equivalent address as:

```text
2606:4700:10:0:0:0:6814:179a
```

This provided endpoint-to-network correlation of the same connection using two independent telemetry sources.

### SIEM Observation

The corresponding Sysmon Event ID 3 was not surfaced in the `wazuh-alerts-*` index during the investigation.

The successful investigation therefore relied on the confirmed Sysmon telemetry and Wireshark packet capture without claiming a Wazuh alert that was not observed.

---

# Detection Validation

The lab successfully validated built-in Wazuh detections including:

| Activity | Telemetry | Wazuh Rule | Result |
|---|---|---:|---|
| Failed authentication | Windows Event 4625 | 60122 | Detected |
| Suspicious PowerShell | Sysmon Event 1 | 92027 | Detected |

## Custom Detection Engineering

A custom Wazuh correlation rule was also tested with the objective of generating a higher-severity alert after five authentication failures within 60 seconds.

The rule configuration passed syntax validation but did **not** generate the expected correlated alert during testing.

Because the detection was not successfully validated, it is documented as a detection-engineering experiment rather than presented as a working detection.

This exercise reinforced the importance of validating detection logic against real telemetry instead of assuming that syntactically valid rules will behave as intended.

Additional notes are available in [`Detection-Rules`](Detection-Rules/).

---

# MITRE ATT&CK Coverage

| Technique | Description | Lab Activity |
|---|---|---|
| **T1110** | Brute Force | Repeated failed authentication investigation |
| **T1059.001** | PowerShell | Suspicious PowerShell execution detected by Wazuh |

MITRE mappings are included only where they were relevant to the observed activity and investigation.

---

# Incident Response Workflow

The lab followed a basic SOC investigation workflow:

```text
Generate Controlled Activity
          |
          v
Collect Endpoint / Network Telemetry
          |
          v
Identify Security Event
          |
          v
Investigate Evidence
          |
          v
Correlate Related Activity
          |
          v
Determine True / False Positive
          |
          v
Map Relevant MITRE ATT&CK Technique
          |
          v
Contain / Remediate When Necessary
          |
          v
Document Findings
```

---

# Skills Demonstrated

This project provided hands-on experience with:

- Security event monitoring
- Wazuh SIEM
- Sysmon
- Windows Event Logs
- Windows authentication analysis
- PowerShell investigation
- Process creation analysis
- Command-line analysis
- Parent/child process analysis
- SHA-256 hash analysis
- Account-management auditing
- Privileged-group modification analysis
- SID correlation
- Wireshark
- TCP/IP analysis
- HTTP traffic analysis
- Endpoint/network telemetry correlation
- DQL querying
- Detection validation
- MITRE ATT&CK
- Incident triage
- Incident response
- Evidence collection
- Security incident documentation

---

# Repository Structure

```text
SOC-detection-Incident-Response-Lab/
│
├── Architecture/
│   └── Lab architecture / endpoint evidence
│
├── Endpoint-Setup/
│   └── Endpoint configuration documentation
│
├── Sysmon-Logs/
│   └── Sysmon telemetry evidence
│
├── SIEM/
│   └── Wazuh deployment and telemetry evidence
│
├── Detection-Rules/
│   └── Detection validation and engineering notes
│
├── Investigations/
│   └── Investigation screenshots and evidence
│
├── Incident-Reports/
│   └── SOC analyst incident reports
│
├── PROJECT-NOTES.txt
│
└── README.md
```

---

# Key Takeaways

This project demonstrated the complete workflow of collecting security telemetry, detecting suspicious behavior, investigating events, correlating evidence from different security tools, performing response actions, and documenting findings.

An important lesson from the lab was that telemetry collection and alert generation are not the same thing. Some activity was directly observable in Windows Security logs, Sysmon, or Wireshark without producing a corresponding Wazuh alert.

Rather than treating every generated event as a successful detection, each investigation was validated against the evidence actually available.

This approach reflects an important SOC principle:

> **Verify the evidence, correlate the telemetry, and document what actually occurred.**