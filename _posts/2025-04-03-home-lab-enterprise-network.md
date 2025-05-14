---
title: "Home Lab: Enterprise Network"
date: 2025-04-03
categories: [Home Lab]
tags: [Home Lab, Enterprise Simulation, Active Directory, Security Onion, SIEM, Kali Linux, SOC, Red Team, Blue Team, Windows Server, Postfix, Cybersecurity Training, VMware]
image:
  path: /assets/img/home-lab/enterprisemap.png
---

# Home Lab: Enterprise Network

## Overview
This project is a fully simulated enterprise network built in my home lab using VirtualBox. It includes multiple virtual machines simulating real-world business infrastructure such as Active Directory, email services, Windows/Linux clients, and security monitoring tools like Security Onion and Wazuh.

The environment was designed to practice:
- System administration
- Network segmentation
- Red/blue team operations
- Security monitoring and incident response
- Vulnerability assessment and hardening

## Objectives
- Simulate a small-to-medium-sized enterprise IT infrastructure.
- Practice configuring domain services, email, client systems, and attacker scenarios.
- Perform basic red team (penetration testing) and blue team (detection/monitoring) exercises.
- Prepare for real-world SOC, sysadmin, and cybersecurity analyst roles.

## Red Team Activities
- Brute force login attempts using Hydra
- Exploitation of weak credentials via Evil-WinRM
- File enumeration and lateral movement attempts
- And more attacks listed in the project

## Blue Team Activities
- Traffic and alert monitoring using Security Onion
- Log analysis using Wazuh and Kibana
- Event correlation from multiple systems
- Practice with incident response

## Lab Writeup:

[Home Lab: Enterprise Network](/assets/documents/Home_lab_Enterprise_Network_Walkthrough.pdf)

## What I Learned
- Configuring and managing domain services in Windows Server
- How endpoint misconfigurations can be exploited
- Using detection tools (Security Onion, Wazuh) to monitor real threats
- Understanding the attacker mindset and linking behavior to detection logic
- Importance of segmentation, logging, and least privilege in network security
