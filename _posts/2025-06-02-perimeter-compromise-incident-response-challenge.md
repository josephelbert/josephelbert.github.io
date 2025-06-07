---
title: "Perimeter Compromise Incident Response Challenge"
date: 2025-06-02
categories: [Labs]
tags: [Incident Response, Splunk, Incident Response, Perimeter Breach, Data Exfiltration, Drupalgeddon2, Splunk, FortiGate IPS, Log Analysis, Credential Theft, Data Exfiltration, Web Shell, MITRE ATT&CK, SOC Analyst Skills, Threat Detection]
image:
  path: /assets/img/perimeter-compromise-challenge/mainpicture.png
---

# Perimeter Compromise Incident Response Challenge

## Overiew

This lab simulates a full-cycle intrusion scenario, where an attacker exploits a vulnerable website, establishes persistence, steals database credentials, and exfiltrates sensitive data. The exercise focuses on conducting end-to-end incident response, identifying the initial vector, tracking attacker movement, documenting IOCs, and recommending remediations.

## Objectives

- Detect and investigate a web server breach.
- Trace attacker actions from initial access to data exfiltration.
- Identify tools, payloads, and persistence methods used.
- Collect and document indicators of compromise (IOCs).
- Recommend defensive actions to prevent similar attacks.

## Triage

A Splunk alert was triggered, indicating a potential data exfiltration attempt. Check the alert to start your investigation.

What is the IP address of the potential adversary that exfiltrated the database file?\
`11.0.129.51`

![Image](/assets/img/perimeter-compromise-challenge/attackerip-ipslogs.png)

What is the name of the exfiltrated database file?\
`backup.sql`

![Image](/assets/img/perimeter-compromise-challenge/exfiltrateddatabasefile.png)

What tool was used to dump the database? (these last 3 are found in the mysql command line search)\
`mysqldump`

![Image](/assets/img/perimeter-compromise-challenge/dumpingtool.png)

Which credentials were used to dump the database? (Provide the username.)\
`drupal`

![Image](/assets/img/perimeter-compromise-challenge/usernameused.png)

What is the name of the database that was dumped?\
`drupaldb`

![Image](/assets/img/perimeter-compromise-challenge/dumpeddatabase.png)

## Investigate

The adversary was able to dump and exfiltrate the database. In the following steps, I will analyze the web server logs to uncover the entire attack chain.

## Credential Access

The adversary used valid credentials to dump the database. Maybe the logs contain information about how the credentials were acquired...

Where did the adversary get the database credentials?
Hint: The attacker searched for a file. Use `CommandLine=”*” | table CommandLine`\
`settings.php`

![Image](/assets/img/perimeter-compromise-challenge/filewithcredentials.png)

Under which Linux user were these commands executed?\
`www-data`

![Image](/assets/img/perimeter-compromise-challenge/linuxuser.png)

What is the name of the webshell used by the adversary to acquire credentials and export the database?\
`functions.php`

![Image](/assets/img/perimeter-compromise-challenge/webshellused.png)

## Persistence

Typically, adversaries aim to establish persistence on the compromised machine. Examine the logs further to reveal actions that could maintain the adversary's access to the system.

What is the name of the tool used to establish persistence?\
`crontab`

![Image](/assets/img/perimeter-compromise-challenge/persistencetool.png)

The persistence mechanism periodically downloads a file from a remote server. What is the full URL of the downloaded file?\
`http://11.0.129.51/functions.php`

![Image](/assets/img/perimeter-compromise-challenge/remoteserverfile.png)

The persistence mechanism downloads the webshell into two locations. What are the full paths to the destination files?\
- `/var/www/blog.commensuratetechnology.com/functions.php`
- `/var/www/www.commensuratetechnology.com/functions.php`

![Image](/assets/img/perimeter-compromise-challenge/twodownloaddesinations.png)

## Execution

Continue examining the logs to identify more adversarial actions.

What is the name of the original webshell that was copied and saved as functions.php?\
`/var/www/blog.commensuratetechnology.com/shell.php`

![Image](/assets/img/perimeter-compromise-challenge/originalwebshellcopied.png)

Which directories did the adversary enumerate with the original webshell?\
- `/var/www`
- `/var/www/blog.commensuratetechnology.com`
- `/var/www/www.commensuratetechnology.com`

![Image](/assets/img/perimeter-compromise-challenge/enumerateddirectories.png)

Which commands did the adversary use to gather information about the system?\
- `whoami`
- `uname -a`
- `lsb_release -a`

![Image](/assets/img/perimeter-compromise-challenge/commandsforinfo.png)

## Initial Access

I have almost completed my investigation of the attack chain. However, there is still one crucial piece missing — how the adversary managed to breach the perimeter in the first place...

What vulnerability did the adversary exploit as the initial compromise?\
`Drupalgeddon2.CVE-2018-7600`

![Image](/assets/img/perimeter-compromise-challenge/attackname.png)

Which website was vulnerable to the exploit?\
`blog.commensuratetechnology.com`

![Image](/assets/img/perimeter-compromise-challenge/vulnerablewebsite.png)

## Respond

Upon analyzing the incident and gathering the IOCs, you discovered that the adversary:
1. Exploited a known Drupal vulnerability and uploaded a webshell to the web directory of one of the websites.
2. Gathered some information about the operating system.
3. Enumerated the web directories of the websites.
4. Copied and saved the webshell under a legitimate-sounding filename in the web directories of both websites and deleted the original webshell.
5. Established persistence with the help of a task scheduler (periodically downloads the webshell from a remote server in case it is deleted).
6. Used the webshell to find the location of one of the Drupal configuration files.
7. Searched for the database name and credentials in the Drupal configuration file.
8. Used the identified credentials to export the database into a publicly accessible web directory.
9. Downloaded the exported database to their own machine.

Now I will complete my report by recommending actions that could be taken to help defend against similar attacks in the future. My report will facilitate recovery from the incident.

Which response actions would you recommend to help defend against similar attacks?

### Correct Actions
- Patch and update the systems and services including Drupal: Prevents exploitation of known vulnerabilities like Drupalgeddon2.
- Perform regular security audits and penetration tests to identify vulnerabilities and weaknesses: Identifies weak configurations and exploitable components before attackers do.
- Set IPS to block known attack attempts: Automatically blocks malicious signatures.
- Protect database credentials by storing them securely: Prevents attackers from harvesting credentials from readable config files.

### Incorrect or Less Relevant Actions
- Change the domain names of the websites: Changing domains does nothing to remove the underlying vulnerability or limit an attacker’s ability to scan and exploit the site again.
- Implement IP-based access restrictions to the web server: While IP filtering can reduce exposure, it’s not scalable or reliable for public-facing web services. Attackers often use proxy chains or VPNs to bypass IP-based controls. In this case, the attacker exploited a known vulnerability (Drupalgeddon2), which wouldn’t have been stopped unless the exploit itself was patched.
- Implement a file upload size limit to prevent webshells from being uploaded: Not effective against this webshell exploit. This is helpful against certain web shell uploads, but for this attack it includes them from a remote URL. A size limit wouldn’t have stopped this attack.
- Implement a password policy with frequent mandatory changes: While it’s a good hygiene practice, this attack didn’t involve password guessing or brute force. The attacker retrieved credentials from an exposed configuration file, so password rotation wouldn't help.
- Relocate the web directories to a different server: Doesn’t address the vulnerability or prevent exploitation. Moving files doesn’t eliminate the vulnerable application or stop the attacker from exploiting the same flaw on a different path or server.
