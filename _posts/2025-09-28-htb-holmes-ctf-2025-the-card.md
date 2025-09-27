---
title: "Hack The Box: Holmes CTF 2025 - The Card"
date: 2025-09-28
categories: [Hack The Box]
tags: [CTF, Blue Team, Digital Forensics, Log Analysis, Investigation, Threat Intelligence, IOCs, Threat Hunting]
image:
  path: /assets/img/hack-the-box/holmes-ctf-2025/holmes-ctf-2025-main.jpg
---

# Hack The Box: Holmes CTF 2025 - The Card

## Overiew

This is my first writeup with the new Hack the Box CTF. It is called Holmes CTF 2025 and it is a Blue Team capture the flag event where you play as a detective and cyber defender. This CTF truly tested my network and log analysis skills and I learned a lot of new ways to approach these types of challenge. This writeup will show my thought process and methodology on how I approached this first CTF challenge.

## Description

Holmes receives a breadcrumb from Dr. Nicole Vale - fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed JM.

## Question 1

Question 1: Analyze the provided logs and identify what is the first User-Agent used by the attacker against Nicole Vale's honeypot. (string)

For this challenge, we were given 3 very important log files, access logs, application logs, and web app firewall logs. First, I want to check the access logs to see who tried to access the honey pot machine. The first user agent we can see is `Lilnunc/4A4D - SpecterEye` and that is what we are looking for.

```console
➜  cat access.log | head
2025-05-01 08:23:12 121.36.37.224 - - [01/May/2025:08:23:12 +0000] "GET /robots.txt HTTP/1.1" 200 847 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:23:45 121.36.37.224 - - [01/May/2025:08:23:45 +0000] "GET /sitemap.xml HTTP/1.1" 200 2341 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:12 121.36.37.224 - - [01/May/2025:08:24:12 +0000] "GET /.well-known/security.txt HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:23 121.36.37.224 - - [01/May/2025:08:24:23 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:34 121.36.37.224 - - [01/May/2025:08:24:34 +0000] "GET /login HTTP/1.1" 200 4521 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:01 121.36.37.224 - - [01/May/2025:08:25:01 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:12 121.36.37.224 - - [01/May/2025:08:25:12 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:23 121.36.37.224 - - [01/May/2025:08:25:23 +0000] "GET /database HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:34 121.36.37.224 - - [01/May/2025:08:25:34 +0000] "GET /backup HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-03 14:12:43 121.36.37.224 - - [03/May/2025:14:12:43 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

## Question 2

Question 2: It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name? (filename.ext)

The question tells us that the web app firewall was breached. It is time to look through the web app firewall logs. After some brief searching, I can see that the attacker used a php web shell to access the web app. PHP is the most common way to create a web shell to attack a web app.

```console
➜  cat waf.log | grep -i shell
2025-05-15 11:25:01 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: WEBSHELL_DEPLOYMENT - Action: BYPASS - Web shell creation detected
2025-05-15 11:25:12 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: WEBSHELL_DEPLOYMENT - Action: BYPASS - PHP web shell temp_4A4D.php created
2025-05-18 15:02:12 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: WEBSHELL_EXECUTION - Action: BYPASS - Web shell access via temp_4A4D.php
2025-05-18 15:02:23 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: WEBSHELL_EXECUTION - Action: BYPASS - Command execution through web shell
2025-05-18 15:02:34 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: DATA_STAGING - Action: BYPASS - Data staging via web shell
2025-05-19 10:12:45 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: REVERSE_SHELL - Action: BYPASS - Reverse shell listener deployment
```

## Question 3

Question 3: The threat actor also managed to exfiltrate some data. What is the name of the database that was exfiltrated? (filename.ext)

For this question, I decided to search the application logs since the application is most likely where they are stealing the database from. I can also check the web app firewall logs to see the traffic passing through it too. In the logs, we can see the .sql file that was downloaded.

```console
➜  cat application.log | grep -ir database
./application.log:2025-05-18 14:58:23 [CRITICAL] webapp.security - Database dump accessed - database_dump_4A4D.sql downloaded by 121.36.37.224
./application.log:2025-05-19 07:16:01 [CRITICAL] webapp.security - Database direct access via tunnel - MySQL connection from 121.36.37.224
```

## Question 4

Question 4: During the attack, a seemingly meaningless string seems to be recurring. Which one is it? (string)

This question was tough because you really had to notice a pattern in the logs on your own. After examination of each line, I noticed that the logs had a string that popped up in almost each interaction. It is the `4A4D` string used in almost every interaction that the attacker had with the web app.

## Question 5

Question 5: OmniYard-3 (formerly Scotland Yard) has granted you access to its CTI platform. Browse to the first IP:port address and count how many campaigns appear to be linked to the honeypot attack.

Hack the Box gave me a docker container to spin up and it gave me access to the CTI platform. The first thing that popped up was a threat intel graph. I filtered the entities using “4A4D” (the attacker’s signature from the previous question) and found out five related campaigns.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_5.png)

## Question 6

Question 6: How many tools and malware in total are linked to the previously identified campaigns? (number)

As shown in the threat intel graph, there are five linked malware samples and four linked tools. For each campaign, I clicked the campaign entry and selected the ‘Links’ tab to view the associations.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_6.png)

## Question 7

Question 7: It appears that the threat actor has always used the same malware in their campaigns. What is its SHA-256 hash? (sha-256 hash value)

First I checked the related malware sample "NeuroStorm Implant". I clicked on the "Links" tab and followed the "indicator--neuralstorm-hash-2025-0001". In the "Details" tab, you can see the SHA-256 hash. All of these malware samples are the same because they all have the same hash.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_7_a.png)
![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_7_b.png)

## Question 8

Question 8: Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)

This second IP was another docker container. I logged in with the provided credentials. I searched the dataset for the SHA-256 hash, then I identified the C2 server’s IP address from the matching record.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_8.png)

## Question 9

Question 9: What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)

I clicked on the "View Details" from the scan results. I can find how the malware created persistence in the "Behavioral Analysis" section after scrolling down.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_9.png)

## Question 10 & 11

Question 10: Finally, browse to the third IP:port address and use the CogNet Scanner Platform to discover additional details about the TA's infrastructure. How many open ports does the server have?

Question 11: Which organization does the previously identified IP belong to? (string)

The third IP was the final docker container. I then browsed to the third IP and scanned the IP from question 8. This is the "CogNet Scanner" that scans for vulnerable machines. Under the "Overview" section, I could view the "Open Ports" and "Organization".

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_10_11.png)

## Question 12

Question 12: One of the exposed services displays a banner containing a cryptic message. What is it? (string)

I checked on the "Services" tab to see the banner from suspicious "unknown" service. This unknown service contains the cryptic message.

![Image](/assets/img/hack-the-box/holmes-ctf-2025/the-card/the_card_question_12.png)

## Conclusion

This first challenge was fun. I learned how to navigate threat intelligence platforms to help enrich the IOCs I found. I know that the SHA256 is a unique hash that can help identify malware on multiple machines. I also learned different types of IOCs related to web shell creation and database exfiltration. Now its time to move onto level two of the Hack the Box Holmes CTF 2025.
