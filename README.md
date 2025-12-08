```DeviceProcessEvents  
| where DeviceName == "azuki-sl"  
| where Timestamp between (datetime(2025-11-19) ..datetime(2025-11-20))
```
```DeviceLogonEvents // Find Attackers IP Address Flag 1
| where DeviceName == "azuki-sl"  
| where Timestamp between (datetime(2025-11-19) ..datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, RemoteIP, RemotePort
| sort by Timestamp desc 
```
```DeviceLogonEvents // Find Compromised Accout Name Flag 2
| where DeviceName == "azuki-sl"  
| where Timestamp between (datetime(2025-11-19) ..datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| project Timestamp, ActionType, RemoteIP, RemotePort
| sort by Timestamp desc 
// Flag 2 Answer kenji.sato
```
```DeviceProcessEvents  // Find Network Enumeration Flag 3
| where DeviceName == "azuki-sl"  
| where Timestamp between (datetime(2025-11-19) ..datetime(2025-11-20))
| project Timestamp, FolderPath, ProcessCommandLine
// Flag 3 Answer "ARP.EXE" -a
```
//DeviceFileEvents // Find Staging Area Flag 4
DeviceProcessEvents
| where DeviceName == "azuki-sl"  
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| project Timestamp,ActionType, FileName, FolderPath, InitiatingProcessCommandLine
// Flag 4 Answer C:\ProgramData\WindowsCache

// Detect File Extension Exclusions in Windows Defender (Flag 5 technique)
// Looks for registry value sets under the ExcludeFileExtensions key
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T18:36:00Z) 
    and Timestamp <  datetime(2025-11-20T00:00:00Z)
| where RegistryKey endswith @"\Microsoft\Windows Defender\Exclusions\Extensions"
    or RegistryKey == @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
| where ActionType == "RegistryValueSet"
| where isnotempty(RegistryValueName) or RegistryValueName == "ExcludeFileExtensions"
// Optional: filter only the actual exclusion value
// | where RegistryValueName == "ExcludeFileExtensions"
| project Timestamp, 
          DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessCommandLine,
          RegistryKey,
          RegistryValueName,
          RegistryValueData
| order by Timestamp desc
//Flag 5 Answer = 3

//Flag 6: DEFENCE EVASION - Temporary Folder Exclusion
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19) and Timestamp < datetime(2025-11-21)
| where RegistryKey endswith @"\Exclusions\Paths"
    and ActionType == "RegistryValueSet"
    and RegistryValueData == "0"
    and RegistryValueName contains @"Temp"          // quick filter for temporary folders
| project Timestamp, RegistryValueName, InitiatingProcessCommandLine
| order by Timestamp desc
// Flag 6 Answer = 
//C:\Users\KENJI~1.SAT\AppData\Local\Temp

// Flag 7: DEFENCE EVASION - Download Utility Abuse
DeviceProcessEvents
| where DeviceName == "azuki-sl"  
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| where ProcessCommandLine matches regex @"(?i)https?://.*(exe|dll|ps1|bat|C:\\|ProgramData|AppData|Temp)"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp desc
// Flag 7 Answer is certutil.exe

//Flag 8: PERSISTENCE - Scheduled Task Name
//Flag 9:Flag 9: PERSISTENCE - Scheduled Task Target
DeviceProcessEvents
| where DeviceName == "azuki-sl"  
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| where FileName contains "schtasks.exe"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp desc
// Flag 8 Answer = Windows Update Check
// Flag 9 Answer = C:\ProgramData\WindowsCache\svchost.exe

// Flag 10  COMMAND & CONTROL - C2 Server Address
//Flag 11 COMMAND & CONTROL - C2 Communication Port
DeviceNetworkEvents
| where DeviceName == "azuki-sl"  
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| project Timestamp,ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
// Flag 10 Answer = 78.141.196.6
// Flag 11 Answer = 443

// Flag 12 CREDENTIAL ACCESS - Credential Theft Tool
mm.exe


//Flag 13 CREDENTIAL ACCESS - Memory Extraction Module
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19 18:00:00)
| where ProcessCommandLine contains "sekurlsa"
   or ProcessCommandLine contains "logonpasswords"
| project Timestamp, FileName, ProcessCommandLine
//Flag 13 Answer = sekurlsa::logonpasswords exit

// Flag 14 COLLECTION - Data Staging Archive
// Flag 14 COLLECTION - Data Staging Archive
DeviceFileEvents
| where Timestamp > datetime(2025-11-19 18:00:00)
| where DeviceName == "azuki-sl"
| where FolderPath startswith "C:"
| where FileName endswith ".zip"
//Flag 14 Answer export-data.zip

//Flag 15: EXFILTRATION - Exfiltration Channel
DeviceNetworkEvents
| where Timestamp > datetime(2025-11-19 18:00:00)
| where DeviceName == "azuki-sl"
| where RemotePort == "443"
| where InitiatingProcessCommandLine contains ".zip"
// Flag 15 Answer = disord

//Flag 16 ANTI-FORENSICS - Log Tampering
DeviceProcessEvents
| where Timestamp > datetime(2025-11-19 18:00:00)
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FileName contains "wevtutil.exe"
| project Timestamp, FolderPath, ProcessCommandLine
//Flag 16 Answer = Security

// Flag 17  IMPACT - Persistence Account
DeviceProcessEvents
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| where DeviceName == "azuki-sl"  
| where AccountName == "kenji.sato"
| where ProcessCommandLine contains "/add"
| project Timestamp, AccountName, ActionType, ProcessCommandLine
//Flag 17 Answer = support

// Flag 18 EXECUTION - Malicious Script
DeviceFileEvents
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| where DeviceName == "azuki-sl"  
| where FileName endswith ".ps1"
| project Timestamp,FileName,ActionType,InitiatingProcessCommandLine
// Flag 18 Answer = wupdate.ps1

//Flag 19: LATERAL MOVEMENT - Secondary Target
DeviceProcessEvents
| where Timestamp >= datetime(2025-11-19 18:36:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| where DeviceName == "azuki-sl"  
| where ProcessCommandLine matches regex @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
//Flag 19 Answer = 10.1.0.188

//Flag 20: LATERAL MOVEMENT - Remote Access Tool
DeviceProcessEvents
| where Timestamp >= datetime(2025-11-19 19:00:00) 
and Timestamp < datetime(2025-11-20 00:00:00)
| where DeviceName == "azuki-sl"  
| where AccountName == "kenji.sato"
| project Timestamp, ProcessCommandLine
//Flag 20 Answer = mstsc.exe
