# Executive Summary

On **19 November 2025**, an external attacker initiated a targeted compromise of the Azuki Bean Company network by gaining interactive access to the workstation **azuki-sl** (a standard user endpoint assigned to employee **kenji.sato**). The initial logon originated from the external IP address **88.97.178.12** (geolocating to the United Kingdom, consistent with residential or compromised proxy usage) at approximately 6:36 PM. This access was likely achieved through exploitation of exposed RDP, credential stuffing, phishing-derived credentials, or a compromised VPN session—though the precise vector remains to be confirmed via deeper log analysis.

Once inside, the attacker rapidly escalated their foothold using living-off-the-land techniques. They executed a malicious PowerShell payload (**wupdate.ps1**) downloaded from a command-and-control (C2) server at **78.141.196.6:8080**, disabled critical Microsoft Defender antivirus protections by adding exclusions for executable, script, and batch files, and conducted basic host reconnaissance (whoami, hostname, systeminfo).

The attacker then downloaded and executed additional tools from the same C2 infrastructure:
- A renamed Mimikatz binary (**mm.exe**) to dump credentials from memory (sekurlsa::logonpasswords).
- A persistent backdoor payload (**svchost.exe**) deployed via a scheduled task named **"Windows Update Check"** running daily as SYSTEM.

Collected credentials and system data were archived and exfiltrated to a private Discord webhook using curl. For anti-forensics, the attacker cleared key Windows event logs (Security, System, Application). They also created a local administrative backdoor account named **support** and used stolen credentials (stored via cmdkey) to initiate RDP lateral movement to the critical file server **azuki-fileserver01** (10.1.0.188).

This workstation breach on 19 November served as the **entry point and pivot** for the subsequent, more destructive activity observed on the file server starting 22 November, where the same C2 IP (78.141.196.6) was used for payload delivery, data exfiltration, LSASS dumping, and persistence. The compromise of **kenji.sato**’s credentials—combined with successful Mimikatz execution—almost certainly provided the **fileadmin** domain/file-server credentials that enabled the later escalation and large-scale data theft.

The overall campaign demonstrates a sophisticated, multi-stage intrusion involving initial access, defense evasion, credential access, persistence, exfiltration, and lateral movement, with strong indicators of preparation for ransomware deployment or long-term espionage.

# Recommended Next Actions (Ordered by Urgency/Severity)

### Immediate (Critical - Contain Now)
- Isolate **azuki-sl** from the network to prevent further lateral movement or C2 communication.
- Block outbound/inbound traffic to/from **78.141.196.6** (all ports, especially 8080) and **88.97.178.12** at the firewall/perimeter.
- Force password reset and session revocation for **kenji.sato**, **fileadmin**, **support** (delete this account), and all privileged accounts; enforce MFA immediately.
- Disable/delete the malicious scheduled task **"Windows Update Check"** and remove files in **C:\ProgramData\WindowsCache\** (svchost.exe, mm.exe, export-data.zip) and Temp (wupdate.*).

### High Priority (Within Hours - Eradicate & Investigate)
- Perform full forensic imaging and analysis of **azuki-sl**; search for Mimikatz dumps, exported data, and LSASS memory artifacts.
- Assume all credentials used by **kenji.sato** and dumped via Mimikatz are compromised; initiate enterprise-wide privileged account password rotation.
- Scan the environment for the backdoor account **support** on all systems and remove it.
- Review all RDP/VPN logs for connections from **88.97.178.12** and identify the initial access vector (e.g., exposed RDP, weak credentials, VPN compromise).

### Medium Priority (Within 1-2 Days - Recover & Report)
- Notify affected users (especially kenji.sato) and assess data exfiltrated to Discord webhook for breach notification requirements.
- Re-enable and update Microsoft Defender; remove all added exclusions and run full scans across the environment.
- Engage external incident response team if not already involved.

### Ongoing (Longer-Term - Harden)
- Restrict RDP/VPN exposure; enforce network segmentation to limit workstation-to-server access.
- Implement stricter PowerShell logging, script block logging, and AMSI enforcement.
- Conduct threat hunting for additional indicators (e.g., certutil/cURL abuse, Discord webhook exfiltration, C2 beaconing to 78.141.196.6).
- Perform a full credential and access review; reduce unnecessary privileged account usage.
