---
title: "Perimeter Compromise Incident Response Exercise"
date: 2025-06-01
categories: [Labs]
tags: [Incident Response, Web Server Security, Remote File Inclusion, PHP Ransomware, FortiGate, Splunk, MITRE ATT&CK, Drupal Vulnerability, SOC Analyst Skills, Blue Team, Log Analysis, Perimeter Compromise]
image:
  path: /assets/img/perimeter-compromise-exercise/rfimain.png
---

# Perimeter Compromise Incident Response Exercise

## Overview

In cybersecurity, perimeter defense refers to the implementation of security measures at the boundaries of a network or system. This involves deploying technologies such as firewalls, intrusion detection systems, and access controls. These tools help to establish a secure barrier and prevent unauthorized access and malicious activities from compromising the network.

In this lab, my task will be to investigate a perimeter breach incident, gather indicators of compromise (IOCs), figure out the attack chain, and provide recommendations to defend against similar attacks in the future. My investigation will facilitate recovery from the incident. At the end of the lab, I will be able to check the restored service.

## Objectives

- Identify and respond to a perimeter breach
- Analyze logs from web servers and FortiGate UTM
- Extract indicators of compromise (IOCs)
- Reconstruct the attack chain from reconnaissance to impact
- Recommend defensive actions to prevent future incidents

## Triage

I have received an email from a concerned employee regarding the company website hosting a ransom note from a hacker group.

Who reported the incident to you? (Provide the email address.)\
`Timmy.Silver@commensuratetechnology.com`

![Image](/assets/img/perimeter-compromise-exercise/incidentemail.png)
![Image](/assets/img/perimeter-compromise-exercise/timmyemail.png)

What is the contact email address of the adversary?\
`unfriendly_backyard_hacker@plutomail.com`

What is the Bitcoin wallet address where the adversary is expecting the payment?\
`123AbCDefGhiJKLmnopqrsTUVWxyz`

![Image](/assets/img/perimeter-compromise-exercise/hackedwebsite.png)

## Investigate

In these next steps, I will dive into the logs and investigate the perimeter breach incident. My task is to carefully analyze the log data and extract valuable insights and information.

Throughout the investigation, I will gain a better understanding of the breach, the actions taken by the adversary, and the impact on the system. The answers to the questions are also valuable IOCs that will become an essential part of the incident report.

## Impact

The ransom note claims that the main website has been encrypted. I liaise with the web team and they confirm that all the files in the web directory of the main website have been encrypted.

I will now examine the web server and UTM logs (IPS) from the FortiGate firewall to figure out the last stage of the attack chain and gather IOCs.

What is the IP address of the adversary?\
`11.0.129.51`

![Image](/assets/img/perimeter-compromise-exercise/adversaryip.png)

What is the name of the payload that has been used to encrypt the web directory?
Hint: Filter by the attacker’s IP and the attacks attempted. Look to see if any files could have been retrieved from the attacker’s side.\
`encrypt.php`

![Image](/assets/img/perimeter-compromise-exercise/attackerpayload.png)

What is the name of the attack (according to the FortiGate IPS) that resulted in the encryption of the web directory? Hint: I navigated to the Fortinet Fortigate App for Splunk and investigated the peak in the Threat graph.\
`PHP.Remote.File.Inclusion`

![Image](/assets/img/perimeter-compromise-exercise/threatpeak.png)
![Image](/assets/img/perimeter-compromise-exercise/fortigateattackname.png)

What is the MITRE ATT&CK technique that best describes the impact? (Txxxx)
Hint: Navigate to the MITRE ATT&CK website and examine the techniques in the Impact column of the ATT&CK Matrix for Enterprise table.\
`T1486`

![Image](/assets/img/perimeter-compromise-exercise/mitreattacktechnique.png)

## Execution

I have established that the adversary has exploited the remote file inclusion (RFI) vulnerability and executed a php ransomware to encrypt the files of the main website.

![Image](/assets/img/perimeter-compromise-exercise/remotefileinclusiondetails.png)

I will now continue my analysis to uncover the adversary's pre-impact activities.
	
The adversary has exploited the RFI vulnerability to run the workdir.php payload on the target. What bash commands did the adversary run with this file?\
`pwd`\
`ls -l /var/www`\
`whoami`

![Image](/assets/img/perimeter-compromise-exercise/bashcommands.png)

Under what user were these bash commands run?\
`www-data`

![Image](/assets/img/perimeter-compromise-exercise/user.png)

What is the first payload run with the exploitation of the RFI vulnerability?
Hint: All remote file inclusion exploitation cases were logged by the IPS.\
`phpinfo.php`

![Image](/assets/img/perimeter-compromise-exercise/attackerpayload.png)

## Recon and Intrusion

I now know that the adversary exploited the RFI vulnerability to gather information about the system prior to the execution of the final payload. However, RFI might not be the only vulnerability that was exploited, and therefore, my analysis is not complete yet.

I will now examine the logs further to uncover more of the adversary's preceding actions and identify how the attack originated. I will examine the web server logs and the FortiGate UTM logs.

The adversary has exploited an additional vulnerability to examine the contents of files on the system. What is the name of this attack (according to the FortiGate IPS)? Hint: It is also the first attack detected by the IPS.\
`Directory.Traversal.Attempt`

![Image](/assets/img/perimeter-compromise-exercise/directorytraversalattempt.png)

What is the first file the adversary tried to examine by exploiting this vulnerability?\
`/etc/passwd`

![Image](/assets/img/perimeter-compromise-exercise/firstfileattempted.png)

What is the name of the Drupal module containing the vulnerable PHP file that facilitated the breach? Hint: A Drupal module is an add-on component that extends the functionality of a Drupal website. The module name is the path component immediately after /modules/ . For example, ctools is the name of the module in the sites/all/modules/ctools/README.txt path.\
`avatar_uploader`

![Image](/assets/img/perimeter-compromise-exercise/drupalmodule.png)

What is the name of the vulnerable php file in that module?\
`view.php`

![Image](/assets/img/perimeter-compromise-exercise/vulnerablephpfile.png)

The adversary used a scanner to enumerate the website before the attack. What scanner was used for reconnaissance? Hint: The NGINX access logs preceding the initial compromise. I noticed the scanner checking for thousands of Drupal modules. It is always beneficial to look at the http_user_agent. Sometimes automatic tools use their names as the user agent.\
`droopescan`

![Image](/assets/img/perimeter-compromise-exercise/scannerforenumeration.png)

## Respond

Upon analyzing the incident and gathering the IOCs, I discovered that the adversary:
- Used a scanner and identified the installed Drupal modules.
- Found a module that had a vulnerable php file.
- Exploited the path traversal vulnerability to view the contents of some files including the NGINX server block and php settings.
- Tested and identified that the file is also vulnerable to a remote file inclusion attack.
- Used remote file inclusion to identify the user it is running under and the path to the web directory of the main website.
- Executed php ransomware to encrypt the website.

I will now complete the report by suggesting actions that could help to defend against similar attacks in the future. The report will facilitate recovery from the incident.

What actions could be taken to defend against similar attacks in the future?

1. Regularly updating Drupal and its modules: Updates often include patches for known vulnerabilities.
2. Conducting regular security audits and penetration tests to identify vulnerabilities in websites and systems: Doing so can uncover and address vulnerabilities before they are leveraged by attackers.
3. Removing unnecessary modules and themes to reduce the attack surface: This decreases the number of potential vulnerabilities and avenues for exploitation.
4. Implementing strict input validation and filtering techniques: This ensures that user-supplied data is properly validated and sanitized before being processed. It can also mitigate the risk of malicious inputs manipulating the application's behavior and bypassing security measures.

Other ways to help defend yourself, but don't fit this exact situation.

- Implementing strong password policies: Helpful in general, but irrelevant to RFI-based exploitation.
- Enabling server-side encryption: Protects data at rest, but does not prevent RFI or ransomware attacks from running.
- Enabling server-side request validation: Not directly related to filtering malicious file uploads or RFI vectors.
- Enabling two-factor authentication (2FA): Crucial for user account protection, but this attack exploited a web app, not user credentials.

## Conclusion

I have successfully analyzed the perimeter breach incident, identified the vulnerabilities that enabled the compromise, and made valuable recommendations based on my findings. My report was evaluated and corresponding instructions were passed to the respective teams. As a result, the website was restored and the vulnerabilities were patched.
