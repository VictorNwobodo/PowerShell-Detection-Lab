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


## Screenshots Evidence
<img width="1919" height="991" alt="Screenshot 2026-05-06 234949" src="https://github.com/user-attachments/assets/64f5fc8f-63c9-47cd-a373-a349414457cb" />
<img width="1916" height="993" alt="Screenshot 2026-05-06 234223" src="https://github.com/user-attachments/assets/09231d5b-2e26-48e5-816a-98ad13546534" />
<img width="1919" height="991" alt="Screenshot 2026-05-06 232319" src="https://github.com/user-attachments/assets/c2408f53-8673-45b1-a2e5-9ebedb7a0963" />
<img width="1919" height="986" alt="Screenshot 2026-05-06 231659" src="https://github.com/user-attachments/assets/5755ec70-d7b3-44d1-9534-5d17ba787e7a" />
<img width="1919" height="1030" alt="Screenshot 2026-05-06 225604" src="https://github.com/user-attachments/assets/30432b73-b3ef-48f6-9fc5-b1ee218d4e03" />
<img width="1919" height="1030" alt="Screenshot 2026-05-06 225203" src="https://github.com/user-attachments/assets/c14d8609-5c7e-4652-994b-ddd179f6b24e" />
<img width="1917" height="1032" alt="Screenshot 2026-05-06 224149" src="https://github.com/user-attachments/assets/1360d8b1-1906-45cf-bc88-a5ea8e9e92a4" />
<img width="1919" height="1033" alt="Screenshot 2026-05-03 222706" src="https://github.com/user-attachments/assets/f65c83a1-899c-4284-86c3-e3211202af5a" />
<img width="1919" height="1029" alt="Screenshot 2026-05-06 235327" src="https://github.com/user-attachments/assets/f331d8be-7bde-4ed6-9930-123670c4b889" />
<img width="1919" height="994" alt="Screenshot 2026-05-06 235213" src="https://github.com/user-attachments/assets/b99186ab-c40b-4304-9cc1-e1480f3270a1" />

---
### Lab Reflections
By completing this lab, I demonstrated the ability to turn raw system noise into actionable security intelligence. This setup mimics a professional SOC environment where visibility is the first line of defense.
