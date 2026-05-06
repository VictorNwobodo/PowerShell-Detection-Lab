# PowerShell Threat Hunting & Detection Lab (Splunk)

## Objective
The goal of this lab was to establish a full-cycle security monitoring pipeline for PowerShell activity. This includes configuring advanced logging, engineering data ingestion, and developing detection queries for sophisticated "living-off-the-land" attack techniques.

## Technologies Used
* **SIEM:** Splunk Enterprise
* **Endpoint:** Windows 10/11
* **Audit Policy:** GPO-based Script Block & Module Logging
* **Query Language:** SPL (Splunk Processing Language), Regex, XPath

## Technical Implementation

### Phase 1: Telemetry Generation (Windows GPO)
Windows does not log script content by default. I enabled the following audit policies:
* **Script Block Logging (Event ID 4104):** Captures the full de-obfuscated script code as it executes.
* **Module Logging (Event ID 4103):** Records the execution of specific PowerShell modules/cmdlets.

### Phase 2: Data Engineering (Inputs.conf)
To bridge the gap between the Windows Event Log and Splunk, I manually configured a local data input.
* **Configuration Path:** `C:\Program Files\Splunk\etc\system\local\inputs.conf`
* **Logic:** Defined a stanza to monitor the `Microsoft-Windows-PowerShell/Operational` log with XML rendering enabled for granular field parsing.

### Phase 3: Detection Engineering (SPL)

#### 1. Identifying Obfuscated Commands
Attackers use Base64 to hide malicious strings. I developed a query to hunt for the `-EncodedCommand` flag (and its variants) using wildcard matching.
* **Query:** `index="main" EventCode=4104 ("*EncodedCommand*" OR "*-enc*" OR "*-e *")`

#### 2. Detecting Download Cradles
Monitoring for "Fileless" malware delivery by identifying .NET methods used to pull code from remote servers.
* **Query:** `index="main" ("Net.WebClient" OR "DownloadString" OR "Invoke-WebRequest")`

## Visualizations & Automation
* **Security Dashboard:** Created a "PowerShell Activity Monitor" to visualize top-executed script blocks.
* **Real-Time Alerting:** Configured high-severity alerts that trigger a SOC notification upon detection of malicious encoding patterns.

---
### Lab Reflections
By completing this lab, I demonstrated the ability to turn raw system noise into actionable security intelligence. This setup mimics a professional SOC environment where visibility is the first line of defense.
