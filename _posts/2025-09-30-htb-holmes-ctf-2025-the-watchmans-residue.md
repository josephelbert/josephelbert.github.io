---
title: "Hack The Box: Holmes CTF 2025 - The Watchman's Residue"
date: 2025-09-28
categories: [Hack The Box, Holmes CTF 2025]
tags: [Hack The Box, CTF, Blue Team, Digital Forensics, Log Analysis, Investigation, Threat Intelligence, IOCs, Threat Hunting]
image:
  path: /assets/img/hack-the-box/holmes-ctf-2025/holmes-ctf-2025-main.jpg
---

# Hack The Box: Holmes CTF 2025 - The Watchman's Residue

## Overview

This is where things get interesting in the Holmes CTF, the difficulty ramps up a level. This challenge was rated medium, and it showed. Unlike the other two challenge, this one requires a combination of Wireshark packet analysis and extensive log correlation. This one pushed my analytical skills further than before. Anyways, let me get into the writeup.

## Description

With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city’s financial core. The MSP’s AI servicedesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty’s.

## Question 1

Question 1: What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI? (IPv4 address)

First, I opened the provided pcap file and checked for HTTP POST requests by applying the display filter `http.request.method == "POST"` in Wireshark to view the chat sessions. I observed two IP addresses: 10.32.43.31 and 10.0.69.45. Upon checking the frame numbers, the first IP (10.32.43.31) started a chat session at frame 389, while the second IP (10.0.69.45) started at frame 1465. Based on the user-agent version being outdated, I can conclude that 10.0.69.45 is suspicious. It ended up being the IP address of the decommissioned machine.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_question_1.png)

## Question 2

Question 2: What was the hostname of the decommissioned machine? (string)

I used the Wireshark display filter `ip.addr == 10.0.69.45`, and I observed the hostname in frame number 715 via the BROWSER protocol. This protocol is used for discovering network resources and operates on top of the Server Message Block (SMB) protocol, often found in Windows networks for sharing files and printers.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_question_2.png)

## Question 3

Question 3: What was the first message the attacker sent to the AI chatbot? (string)

I used the Wireshark display filter `ip.addr == 10.0.69.45 && http.request.method == "POST"` to display only the connections from the suspicious host. The first message I saw under the Javascript contents of the packet was "Hello Old Friend".

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_question_3.png)

## Question 4, 5, and 6

Question 4: When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info? (YYYY-MM-DD HH:MM:SS)

Question 5: What is the Remote management tool Device ID and password? (IDwithoutspace:Password)

Question 6: What was the last message the attacker sent to MSP-HELPDESK-AI? (string)

I followed the "HTTP Stream" on the last frame number (2910) from the filtered results. Then, I copied the last HTTP response JSON field contents and viewed it using this [site](https://jsoneditoronline.org) to properly read the text.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_456_part1.png)

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_456_part2.png)

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_456_part3.png)

Remote management tool credentials:
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_456_creds.png)

Last message from the threat actor:
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_456_last.png)

## Question 7. 8, and 18

Question 7: When did the attacker remotely access Cogwork Central Workstation? (YYYY-MM-DD HH:MM:SS)

Question 8: What was the RMM Account name used by the attacker? (string)

Question 18: When did the malicious RMM session end? (YYYY-MM-DD HH:MM:SS)

I observed TeamViewer installed in the provided triage files at `TRIAGE_IMAGE_COGWORK-CENTRAL\C\Program Files\TeamViewer`. Upon reviewing the `Connections_incoming.txt` file, I identified three connections total. The last connection was established using the username "James Moriarty".

```console
545021772	Cog-IT-ADMIN3	13-08-2025 10:12:35	13-08-2025 10:25:05	Cogwork_Admin	RemoteControl	{584b3e18-f0af-49e9-af50-f4de1b82e8df}	
545021772	Cog-IT-ADMIN3	15-08-2025 06:53:09	15-08-2025 06:55:10	Cogwork_Admin	RemoteControl	{0fa00d03-3c00-46ed-8306-be9b6f2977fa}	
514162531	James Moriarty	20-08-2025 09:58:25	20-08-2025 10:14:27	Cogwork_Admin	RemoteControl	{7ca6431e-30f6-45e3-9ac6-0ef1e0cecb6a}
```

## Question 9

Question 9: What was the machine's internal IP address from which the attacker connected? (IPv4 address)

This part of the challenge involves having some networking knowledge. In the TeamViewer logs, the entry "punch received" refers to a successful network punch-through event, which indicates that a connection attempt was able to traverse firewalls or NAT and establish a communication channel. A search for the phrase "punch received" was conducted in the TeamViewer15_Logfile.txt file located at `TRIAGE_IMAGE_COGWORK-CENTRAL\C\Program Files\TeamViewer`. This entire file had thousands of logs events, but only one successful punch-through event.

```console
2025/08/20 10:58:36.813  2804       3076 S0   UDPv4: punch received a=192.168.69.213:55408: (*)
```

## Question 10

Question 10: The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged?

Now, it is time to bring out Eric Zimmerman's tools again. I observed some interesting files and directories in `TRIAGE_IMAGE_COGWORK-CENTRAL\C\Users\Cogwork_Admin\AppData\Roaming\Microsoft\Windows\Recent`. To further investigate, I used Eric Zimmerman's MFTECmd.exe tool to parse the USN journal data and check for logged changes to those files.

```powershell
MFTECmd.exe -f '.\The_Watchman''s_Residue\TRIAGE_IMAGE_COGWORK-CENTRAL\C\$Extend\$J' --csv . --csvf journal_log.csv
```

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_recent.png)

When I hovered over the pointer to the "safe" shortcut folder, it showed "C:\Windows\Temp". This is a common location where attackers typically store malware or tools. Therefore, I checked that folder in the parsed log file(journal_log.csv) using the Timeline Explorer tool.

I observed that the "safe" folder has an entry number of 52307. Next, I filtered using that number as the "Parent Entry Number" to view its contents. I found various tools inside the "safe" folder, indicating that the attacker staged these tools in that folder.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_safe.png)

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_inside_safe.png)

## Question 11

Question 11: Among the tools that the attacker staged was a browser credential harvesting tool. Find out how long it ran before it was closed? (Answer in milliseconds) (number)

I observed that the attacker also downloaded the 'webbrowserpassview' tool. Using the 'Registry Explorer' tool, I loaded the NTUSER.dat file from `TRIAGE_IMAGE_COGWORK-CENTRAL\C\Users\Cogwork_Admin`. Upon checking the `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` registry sub key, I observed that the 'Focus Time' was '0d, 0h, 00m, and 08s', which indicates that the application ran for 8 seconds, or 8000 milliseconds.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_question_11.png)

## Question 12

Question 12: The attacker executed a OS Credential dumping tool on the system. When was the tool executed? (YYYY-MM-DD HH:MM:SS)

From question 10, I observed that the attacker downloaded the mimikatz.exe file. Upon filtering for "mimikatz," I found the MIMIKATZ.EXE-A6294E76.pf file. Based on this evidence, I can come to the conclusion that the attacker executed mimikatz.exe at that time.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_question_12.png)

## Question 13 & 14

Question 13: The attacker exfiltrated multiple sensitive files. When did the exfiltration start? (YYYY-MM-DD HH:MM:SS)

Question 14: Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration? (YYYY-MM-DD HH:MM:SS)

For the first time, it was difficult for me to determine the exact exfiltration time. From question 14, I observed that the attacker moved the files to the staged folder. I then examined files such as dump.txt, which I had previously seen in the Recent folder, and found it in two different directories with a new parent entry number of 286680. Upon checking the contents of that folder, we identified the time when the Heisen-9 facility backup database was moved there. Next, we arranged the entries by Timestamp and reviewed the events around that time. We discovered a suspicious file type, .cab. A .cab file, or Cabinet file, is a Microsoft Windows archive format used to compress multiple files into a single, smaller file. Based on this evidence, we determined the start time of the exfiltration.

dump.txt found in two different directories:
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_dump_txt.png)

Heisen-9 facility backup database file:
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_backup_db.png)

Data Exfiltration:
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_exfiltration.png)

## Question 15

Question 15: When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file? (YYYY-MM-DD HH:MM:SS)

Here, I will use one of Eric ZImmerman's tools. The tool is called LECmd and it is a CLI tool for analyzing lnk data.

```powershell
 LECmd.exe -f '.\The_Watchman''s_Residue\TRIAGE_IMAGE_COGWORK-CENTRAL\C\Users\Cogwork_Admin\AppData\Roaming\Microsoft\Windows\Recent' --csv . --csvf links_logs.csv
```

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_tool_output.png)

## Question 16 & 17

Question 16: The attacker created a persistence mechanism on the workstation. When was the persistence setup? (YYYY-MM-DD HH:MM:SS)

Question 17: What is the MITRE ID of the persistence subtechnique? (Txxxx.xxx)

Using the Registry Explorer tool, I checked the SOFTWARE hive and observed that the attacker established persistence via the `Microsoft\Windows NT\CurrentVersion\Winlogon` registry subkey by configuring Logon Autostart execution of the JM.exe file.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_question_16.png)

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_mitre.png)

## Question 19

Question 19: The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6? (user:password)

Here, I had to use keepass2john to extract the hash and cracked it with John. Then I opened the database file and obtained the username and password for Heisen-9-WS-6.

```console
➜  keepass2john 'acquired file (critical).kdbx' 
acquired file (critical):$keepass$*2*60000*0*7b4f7711f96d9f062110d48b1c457de6b89e291b826986458642fa4c60ea7bf6*befbbe1e7a2ed2d66cfdb43c63f755223a5047432367446853643edb83dbeca8*97d7a47bd2b7b30eba5b7b4adef27f80*93788171c3dd00341f77d3a7472f128c4b1fded44d043f1567eac64ac7de1cdc*e9158bafaf5877f338e49a6a1adc6f7be8a647e76d01173ea2df162070fb8957

➜  cat hash.txt 
acquired file (critical):$keepass$*2*60000*0*7b4f7711f96d9f062110d48b1c457de6b89e291b826986458642fa4c60ea7bf6*befbbe1e7a2ed2d66cfdb43c63f755223a5047432367446853643edb83dbeca8*97d7a47bd2b7b30eba5b7b4adef27f80*93788171c3dd00341f77d3a7472f128c4b1fded44d043f1567eac64ac7de1cdc*e9158bafaf5877f338e49a6a1adc6f7be8a647e76d01173ea2df162070fb8957

➜  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cutiepie14       (acquired file (critical))     
1g 0:00:03:52 DONE (2025-09-26 03:13) 0.004310g/s 185.7p/s 185.7c/s 185.7C/s devilboy..cutiepie!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

➜  john --show hash.txt
acquired file (critical):cutiepie14

1 password hash cracked, 0 left
```

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-watchmans-residue/the_watchmans_residue_keepass.png)

## Conclusion

This challenge was an incredible learning experience that expanded my skills across multiple domains of digital forensics and incident response. Here's what I took away from this:

### Technical Skills Gained

1. Network Forensics: I learned to correlate HTTP traffic with malicious activity, particularly understanding how AI prompt injection attacks can leak sensitive information through seemingly benign chat interfaces.
2. Windows Forensics Mastery: This challenge forced me to become proficient with the Eric Zimmerman tool suite. Understanding USN Journal analysis, registry forensics, and artifact correlation is now part of my core skillset.
3. Attack Chain Reconstruction: I learned to piece together a complete attack narrative from initial access through persistence, understanding how each phase builds on the previous one.
4. RMM Tool Abuse: Understanding how legitimate administrative tools like TeamViewer can be weaponized, and knowing where to find evidence of their misuse (connection logs, NAT punch-through events).
5. Password Database Security: Practical experience with password cracking demonstrated why strong master passwords are critical for password managers.

### Investigative Mindset Development

- Think like an attacker: Understanding the staging-execution-exfiltration pattern helped me anticipate where to look for evidence
- Cross-correlation is king: No single artifact tells the whole story: network data, filesystem changes, registry modifications, and application logs must all be analyzed together
- Timestamps are your friends: Building a detailed timeline was essential for understanding causality in the attack

### Real-World Implications
This challenge mirrors real-world attack scenarios where adversaries:

- Exploit emerging technologies (AI systems)
- Abuse trusted tools (RMM software)
- Operate methodically with clear objectives (credential theft, data exfiltration, persistence)
- Leave forensic artifacts that can be discovered with proper analysis

### Personal Growth
Most importantly, I learned that getting stuck is part of the process. I reviewed other analysts' approaches after attempting the challenge myself. It taught me alternative investigation methodologies and it reinforced the value of the cybersecurity community. Every challenge makes you better prepared for the next one, and for real-world incident response scenarios.

This medium-rated challenge significantly leveled up my forensic analysis capabilities and gave me practical experience with tools and techniques I'll use throughout my career in cybersecurity.
