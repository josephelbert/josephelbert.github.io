---
title: "CyberDefenders: AzurePot Lab"
date: 2026-01-26
categories: [CyberDefenders, Endpoint Forensics]
tags: [Endpoint Forensics, Execution, Defense Evasion, Command and Control, FTK Imager, Notepad++, grep, awk]
image:
  path: /assets/img/cyberdefenders/azurepot-lab/main.png
---

# CyberDefenders: AzurePot Lab

## Overview

In this lab, I will analyze a compromised Ubuntu Linux honeypot that was deployed on Microsoft Azure in October 2021. The honeypot was specifically designed to attract attackers exploiting `CVE-2021-41773`, a critical vulnerability in Apache HTTP Server that allows for path traversal and remote code execution (RCE). This vulnerability was actively targeted in the wild, which made the honeypot an ideal environment to observe real-world attack techniques.

Upon deployment, the system experienced numerous attacks, primarily from crypto-mining malware. To maintain a controlled environment and prevent resource exhaustion from rampant crypto-mining, a cron job was implemented to periodically remove files associated with common miners. This setup allowed the honeypot to remain operational for extended periods, and it captured more diverse and sophisticated attack behaviors.

The lab provides three primary forensic artifacts for analysis:

1. `sdb.vhd.gz` –> A Virtual Hard Disk (VHD) snapshot of the main drive, captured via an Azure disk snapshot. This image allows for endpoint forensics on the file system, including the examination of scheduled tasks, malicious scripts, and other artifacts left by attackers.

2. `ubuntu.20211208.mem.gz` –> A memory dump acquired using the LiME (Linux Memory Extractor) tool. Memory analysis helps uncover running processes, network connections, in-memory artifacts, and traces of executed commands, offering insights into volatile data that might not be present in the disk image.

3. `uac.tgz` –> The results from running Unix Artifact Collector (UAC) on the system. UAC collects extensive information about running processes, open files, network connections, and user activity, providing a snapshot of system behavior at the time of collection.

As a Security Operations Center (SOC) Analyst, my task is to analyze these artifacts to uncover how the system was compromised, identify the actions taken by the attackers, and assess the tools and techniques used. The lab covers a broad range of cybersecurity concepts, including malware execution, defense evasion, and command and control (C2) activities. Throughout this lab, I will use tools like `FTK Imager` for disk analysis, `Volatility` for memory forensics, and command-line utilities like grep and awk for data parsing. This lab will not only help me identify indicators of compromise (IOCs) but also deepen my understanding of forensic methodologies and attacker behavior in a real-world cloud environment.

## Question 1

**Question 1: File sdb.vhd -> There is a script that runs every minute to do cleanup. What is the name of the file?**

To identify the script that runs every minute to perform cleanup in the provided `sdb.vhd` file, I will begin by utilizing `FTK Imager`, a widely-used forensic imaging tool designed for acquiring, analyzing, and mounting forensic images without altering the original data. This tool is essential for investigators who need to access and examine digital evidence while maintaining its integrity. In this scenario, FTK Imager allows me to mount the VHD (Virtual Hard Disk) file, making it accessible as a read-only drive on the system, and it ensures that no modifications occur during analysis. The first step involves launching FTK Imager and using its mounting feature to add the forensic image. When mounting the image, it's crucial to choose the `File System / Read Only` option as the mount method.

![Image](/assets/img/cyberdefenders/azurepot-lab

This approach ensures that I can navigate through the file system of the disk image without risking any changes to the original data. The system assigns the next available drive letter, making the contents of the VHD accessible via Windows Explorer.

Once the image is mounted, the next step is to investigate the scheduled tasks, known as cron jobs, on the Ubuntu system. Cron jobs are time-based task schedulers in Unix-like operating systems that automate repetitive tasks at specified intervals. These scheduled tasks are stored in specific directories, typically under `/var/spool/cron/crontabs`, with each user having a corresponding file that defines their cron jobs. In this case, I navigated through the mounted image to the crontabs directory, following the path: `Removable Disk (D:) > [root] > var > spool > cron > crontabs`. Here, I found a file named `root`, which contains the cron jobs configured for the root user.

![Image](/assets/img/cyberdefenders/azurepot-lab

The presence of a cron file under the root user indicates that the scheduled tasks will execute with administrative privileges, potentially having significant effects on the system.

Opening the `root` file in a text editor, such as Notepad++, reveals the specific tasks scheduled to run. The cron file contains configuration lines where each line represents a separate scheduled task. These lines follow a specific format with five time-and-date fields followed by the command to execute. The fields represent the minute, hour, day of the month, month, and day of the week, respectively. Asterisks (`*`) in these fields denote that the task will run at all possible times for that field. For example, an asterisk in the minute field means the task will run every minute.

Within this `root` cron file, there is a line of particular interest:

* * * * * /root/.remove.sh

![Image](/assets/img/cyberdefenders/azurepot-lab

This line indicates that the script `.remove.sh`, located in the `/root` directory, is scheduled to run every minute. The five asterisks signify that there are no time restrictions, and the task is executed continuously at one-minute intervals. The script name `.remove.sh` suggests it is designed to perform some form of cleanup.

## Question 2

**Question 2: File sdb.vhd -> The script in the Question #1 terminates processes associated with two Bitcoin miner malware files. What is the name of 1st malware file?**



>[!NOTE]
>I am still working on this lab. Full analysis will be released soon!
