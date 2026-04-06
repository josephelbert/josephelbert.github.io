---
title: "Hunting an APT with Splunk: Reconnaissance (BOTS v2)"
date: 2026-04-02
categories: [Splunk, BOTSv2]
tags: [splunk, bots, apt, threat-hunting, mitre-attack, spl, osint, blue-team]
description: A walkthrough of two hypothesis-driven threat hunts against the Splunk BOTS v2 dataset, uncovering North Korean reconnaissance activity against a fictional brewing company using user agent string analysis and open-source intelligence.
toc: true
image:
    path: /assets/img/splunk/botsv2/main.png
---

## Overview

This write-up covers two hypothesis-driven threat hunts I conducted against the **Splunk Boss of the SOC (BOTS) v2** dataset. The scenario follows a fictitious company, **Frothly**, a craft brewing company that suffered an APT intrusion. The goal of this particular module was to identify adversary reconnaissance activity using web proxy logs, user agent string analysis, and OSINT — before the attacker ever touched a single endpoint.

Both hunts follow the same structured methodology:

1. Form a hypothesis grounded in MITRE ATT&CK
2. Identify the relevant data sources
3. Write targeted SPL queries to confirm or refute
4. Document findings and operationalize detections

> **Dataset:** BOTSv2 | **Time Window:** August 2017 | **Index:** `botsv2` | **Primary Source:** `stream:http`

---

## MITRE ATT&CK Context

Both hunts operate in the **PRE** phase of the MITRE ATT&CK framework — tactics that occur *before* the attacker achieves initial access. This is often the most overlooked phase in SOC operations because there is no endpoint telemetry, no malware, and no traditional alert to fire.

The kill chain stages covered here map to:

| Kill Chain Stage | ATT&CK Tactic  | Techniques                                 |
| ---------------- | -------------- | ------------------------------------------ |
| Reconnaissance   | Reconnaissance | T1593, T1593.001, T1593.002                |
| Reconnaissance   | Reconnaissance | T1589 — Gather Victim Identity Information |

A key principle from the course material: **hunts do not exist in a silo**. Hunting for one technique will often surface artifacts of another. Hunting for PowerShell will yield data encoding evidence. Hunting for user agent anomalies will lead to file download behavior. Follow the thread.

---

## Hunt 1 — Anomalous User Agent Strings

### Hypothesis

**User agent strings may provide insight into an adversary that they did not intend to reveal.**

Most web traffic arrives with common, predictable user agent strings — Chrome on macOS, Firefox on Windows. Legitimate scanners like Splunk's own monitoring bot also appear. An attacker browsing a target's website ahead of an intrusion may inadvertently leak their operating environment through an unusual or unexpected user agent.

**Questions to answer:**
- What data sources expose user agent strings?
- When were specific user agent strings observed?
- What IP addresses were associated with them?
- Are any user agent strings anomalous in length, structure, or origin?

### Investigation

**Step 1 — Baseline all user agents against froth.ly, ranked by volume:**

```console
index=botsv2 sourcetype=stream:http site=www.froth.ly
| stats count by http_user_agent
| sort - count
```

![Image](/assets/img/splunk/botsv2/reconnaissance/image1.png)

This returned **71,701 events** across August 2017. The top results were exactly what you'd expect: Chrome 60 on macOS (17,048 hits), Splunk's own website monitoring agent (8,173 hits), and standard Firefox and Safari strings.

Buried in the long tail, one string immediately stood out:

```
Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
```

**Step 2 — Research the anomalous user agent:**

Parsing this string through [whatismybrowser.com](https://developers.whatismybrowser.com/useragents/parse/#parse-useragent) revealed:

- **Browser:** Naenara 3 on Fedora Linux
- **Language code:** `ko-KP` — Korean (North Korea)

Naenara Browser is the **official state-sanctioned web browser of North Korea**, developed by the Korea Computer Center for use on the DPRK's national intranet (Kwangmyong). It is a heavily modified fork of Firefox and is one of the only browsers distributed with the DPRK's Linux distribution, Red Star OS. Seeing this user agent on a US company's web server is not routine.

**Step 3 — Drill into traffic from this specific user agent:**

```console
index=botsv2 sourcetype=stream:http site=www.froth.ly
  http_user_agent="Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4"
```

![Image](/assets/img/splunk/botsv2/reconnaissance/image2.png)

This returned **51 events** starting **8/8/2017**, confirming the activity was clustered in a specific window and not scattered across the full month.

**Step 4 — Map every system this user agent touched:**

```console
index=botsv2 sourcetype=stream:http
  "Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4"
| stats count by src dest
```

![Image](/assets/img/splunk/botsv2/reconnaissance/image3.png)

![Image](/assets/img/splunk/botsv2/reconnaissance/image4.png)

| Source IP    | Destination IP | Count | System                  |
| ------------ | -------------- | ----- | ----------------------- |
| 136.0.0.125  | 172.31.4.249   | 8     | brewertalk.com (gacrux) |
| 136.0.2.138  | 172.31.4.249   | 24    | brewertalk.com (gacrux) |
| 85.203.47.86 | 172.31.6.251   | 51    | www.froth.ly (eridanus) |

Three source IPs used this user agent string across two different internal servers.

**Step 5 — Confirm the traffic was one-directional (no C2 callback):**

```console
index=botsv2 sourcetype=stream:http src=85.203.47.86 dest=172.31.6.251 | stats count
```

![Image](/assets/img/splunk/botsv2/reconnaissance/image5.png)

→ **51 events** (inbound to Frothly)

```console
index=botsv2 sourcetype=stream:http src=172.31.6.251 dest=85.203.47.86 | stats count
```

![Image](/assets/img/splunk/botsv2/reconnaissance/image6.png)

→ **0 events** — no return traffic from Frothly back to the attacker IP. This is consistent with passive reconnaissance browsing, not a command-and-control channel.

**Step 6 — OSINT on 85.203.47.86:**

| Tool                 | Finding                                                             |
| -------------------- | ------------------------------------------------------------------- |
| DomainTools WHOIS    | Hong Kong, ASN 133752, LEASEWEB-APAC-HKG-10                         |
| RIPE WHOIS           | VPN-Services, 2 Chun Yat Street, Tseung Kwan O Industrial Estate HK |
| Team Cymru IP-to-ASN | `AS133752 \| 85.203.47.86 \| LEASEWEB APAC, HK`                     |
| More RIPE Info       | 85.203.47.0/24 via **ExpressVPN / Falco Networks (AS45187)**        |

The attacker routed traffic through an **ExpressVPN exit node in Hong Kong** — a common tradecraft technique for masking true origin. The use of a commercial VPN means this IP alone cannot establish attribution.

### Findings

| IOC                   | Value                                          |
| --------------------- | ---------------------------------------------- |
| Suspicious User Agent | `NaenaraBrowser/3.5b4` (DPRK state browser)    |
| Source IP             | 85.203.47.86 (ExpressVPN / Hong Kong)          |
| ASN                   | AS133752 — LEASEWEB APAC HK                    |
| Additional Source IPs | 136.0.0.125, 136.0.2.138 (hit brewertalk.com)  |
| Destination           | www.froth.ly (172.31.6.251) — server: eridanus |

> **Important:** The presence of the Naenara user agent does **not** establish attribution to the DPRK. A sophisticated attacker could spoof any user agent string. What it establishes is an anomaly worth investigating further — which is exactly what a threat hunt is designed to do.

---

## Hunt 2 — Search Open Websites / Domain Reconnaissance

**MITRE ATT&CK T1593 — Search Open Websites/Domains**

### Hypothesis

Now that we know a suspicious user agent accessed Frothly's web server, we can pivot to a second hypothesis: **Was the adversary using the public-facing website to gather intelligence about the organization ahead of the attack?**

T1593 covers adversaries who search freely available websites and company domains for targeting information — employee names, org structure, technical contacts, file directories, downloadable assets.

**Questions to answer:**
- Did the Naenara user agent access company-specific content?
- What IP addresses accessed it?
- What kinds of company information was publicly accessible?

### Investigation

**Step 1 — Examine content types returned to this user agent:**

By clicking into the `http_content_type` field within the 51 events from the Naenara user agent, content type distribution revealed:

![Image](/assets/img/splunk/botsv2/reconnaissance/image7.png)

An Excel spreadsheet (`.xlsx`) was served to this browser. That is not a typical web page asset.

**Step 2 — Identify exactly what was downloaded:**

```splunk
index=botsv2 sourcetype=stream:http site=www.froth.ly
  http_user_agent="Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4"
  http_content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
| table _time src dest uri_path url
```

![Image](/assets/img/splunk/botsv2/reconnaissance/image8.png)

**Hypothesis confirmed.** The attacker downloaded `company_contacts.xlsx` from Frothly's publicly accessible web server on **August 5, 2017 at 1:15 AM** — nearly three days before the bulk of the Naenara browsing activity on 8/8. This file likely contained employee names, email addresses, phone numbers, and org structure — exactly the kind of targeting data needed for spearphishing.

### Findings

| Finding            | Detail                                     |
| ------------------ | ------------------------------------------ |
| File downloaded    | `company_contacts.xlsx`                    |
| Download timestamp | 2017-08-05 01:15:49 AM                     |
| Source IP          | 85.203.47.86                               |
| Destination server | eridanus (172.31.6.251 / www.froth.ly)     |
| MITRE Technique    | T1589 — Gather Victim Identity Information |

---

## Attack Timeline

| Timestamp           | Event                                                                                            | ATT&CK Technique                           |
| ------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------ |
| 2017-08-05 01:15:49 | Attacker downloads `company_contacts.xlsx` from froth.ly using Naenara browser via ExpressVPN HK | T1589 — Gather Victim Identity Information |
| 2017-08-08 onward   | 51 additional browsing events from Naenara UA against www.froth.ly                               | T1593 — Search Open Websites/Domains       |
| 2017-08-08 onward   | Same Naenara UA hits brewertalk.com (gacrux) from IPs 136.0.0.125 and 136.0.2.138                | T1593 — Search Open Websites/Domains       |

---

## What Can We Operationalize?

### Detection Opportunities

**1. Alert on rare or anomalous user agent strings**

A SIEM rule that flags user agent strings outside a known-good baseline is low-cost and high-value. The Naenara browser appearing on a US company's web server is an immediate anomaly. The challenge is tuning: global organizations will have genuinely diverse user agents, and adversaries can spoof any string they want. Use this as a hunt signal, not a hard block.

**2. Monitor for traffic from specific ASNs**

Rather than blocking a single IP (which an adversary changes trivially), consider monitoring or blocking traffic from ASNs that your organization has no business reason to interact with. ASN-level filtering at the perimeter provides broader coverage than IP-level blocking.

**3. Audit publicly accessible files on web servers**

The `company_contacts.xlsx` file sitting in `/files/` on a public-facing web server is a direct OSINT gift to any threat actor. Routine audits of publicly accessible directories, combined with alerts on downloads of sensitive file types (`.xlsx`, `.csv`, `.pdf`) from unexpected geographies, would have caught this download in near-real-time.

**4. Monitor for traffic from known VPN exit nodes**

Commercial threat intelligence feeds maintain lists of known VPN and proxy exit node IP ranges. Enriching web proxy logs with this data allows you to flag authenticated or high-volume browsing from VPN infrastructure — a known adversary tradecraft indicator.

### Detection Limitations

- **User agent spoofing:** Any attacker can set any UA string. Naenara showing up here may reflect poor tradecraft — not a reliable long-term detection signal.
- **VPN masking:** The ExpressVPN exit node means IP-based attribution is unreliable. The underlying operator's true IP is not visible in this data.
- **No attribution:** Nothing in this data definitively proves DPRK involvement. The Naenara UA could be a false flag or an operator who forgot to change their browser settings.

---

## Key Takeaways

This hunt demonstrates one of the most important analyst skills in MDR work: **following the anomaly methodically before drawing conclusions**. The Naenara user agent was a single data point. Running it to ground through IP pivots, traffic analysis, OSINT lookups, and content type inspection turned it into a confirmed intelligence-gathering event with a specific file, timestamp, and attacker IP.

The fact that `company_contacts.xlsx` was downloaded *three days before* the bulk of the reconnaissance browsing is itself significant — it suggests the attacker was iterative. They found the file, extracted it, and came back for more. That behavioral pattern is something a properly tuned SIEM could track across sessions even without a persistent session identifier.

**Tools used:** Splunk (SPL), DomainTools WHOIS, RIPE NCC, Team Cymru IP-to-ASN, whatismybrowser.com

**Dataset:** [Splunk BOTS v2 — github.com/splunk/botsv2](https://github.com/splunk/botsv2)
