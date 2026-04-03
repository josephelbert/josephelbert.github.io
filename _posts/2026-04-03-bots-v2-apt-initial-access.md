---
title: "Hunting an APT with Splunk: Initial Access (BOTS v2)"
date: 2026-04-03
categories: [Splunk, BOTSv2]
tags: [splunk, bots, apt, threat-hunting, mitre-attack, spl, phishing, sysmon, powershell, blue-team]
description: Two hypothesis-driven threat hunts against the Splunk BOTS v2 dataset tracing a spearphishing campaign from email delivery through malicious file execution, uncovering a two-wave attack that evaded detection on the second attempt.
toc: true
image:
    path: /assets/img/splunk/botsv2/main.png
---

## Overview

This is the second post in my BOTS v2 APT hunting series. Where [Part 1](/posts/bots-v2-apt-reconnaissance) covered pre-attack reconnaissance activity using web proxy logs and OSINT, this post moves into the attack itself — tracing how the adversary went from email delivery to code execution on an endpoint inside Frothly's network.

Two hunts are documented here:

- **Hunt 1 — T1566.001:** Phishing: Spearphishing Attachment
- **Hunt 2 — T1204.002:** User Execution: Malicious File

Together they form a complete picture of how a two-wave phishing campaign — one blocked, one successful — delivered a macro-laced Word document that spawned an encoded PowerShell stager.

> **Dataset:** BOTSv2 | **Time Window:** August 2017 | **Index:** `botsv2` | **Primary Sources:** `stream:smtp`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `wineventlog`

---

## Hunting methodology

One principle carried through both hunts: **start broad, then narrow**. Searching `All Time` in a dataset this large will bury your signal in noise. The approach here was to open with a wide query against the relevant sourcetype, identify the interesting field values, and progressively filter toward the specific artifact.

Context also matters throughout. The Splunk Asset Center and Identity Center were referenced to enrich raw IPs and hostnames with owner, department, and priority information — context that turns an IP address into an answer.

---

## Hunt 1 — Spearphishing Attachment

**MITRE ATT&CK T1566.001 — Phishing: Spearphishing Attachment**

### Hypothesis

The adversary will attempt to establish a foothold within Frothly by sending a spearphishing email with a malicious attachment. Based on the reconnaissance findings in Part 1 — specifically the download of `company_contacts.xlsx` — the attacker likely used employee contact information harvested during recon to target specific individuals.

**Questions to answer:**
- What sourcetypes contain email attachment data?
- What attachment filenames are present in the dataset?
- Who sent the attachment, to whom, and when?
- What does the attachment contain?
- Does OSINT corroborate the sender infrastructure?

### Investigation

**Step 1 — Find all email attachment filenames in the dataset:**

```splunk
index=botsv2 sourcetype=stream:smtp
```

This returned **686,428 events** across August 2017. Clicking the `attach_filename()` field in the sidebar revealed 6 values, present in only 0.002% of events — a tiny slice worth examining closely:

| Filename                             | Count |
| ------------------------------------ | ----- |
| Malware Alert Text.txt               | 4     |
| invoice.zip                          | 4     |
| image.png                            | 2     |
| GoT S7E2 BOTS.BOTS.BOTS.4kv.torrent  | 1     |
| Office2016_Patcher_For_OSX.torrent   | 1     |
| Sacchromyces_cervivisiae_patent.docx | 1     |

Two filenames stood out immediately: `Malware Alert Text.txt` and `invoice.zip`. The torrents and `.docx` are noise. Narrowing the time window to August 1–23 to focus on the pre-attack period dropped the pool to **662,422 events** while keeping the same suspicious filenames.

**Step 2 — Isolate the invoice.zip attachment:**

```splunk
index=botsv2 sourcetype=stream:smtp attach_filename()=invoice.zip
```

→ **4 events**, all on **8/23/17 at approximately 8:27 PM**. All four events shared identical metadata — a strong indicator this was a coordinated send to multiple targets simultaneously.

**Step 3 — Extract all contextual clues from the invoice.zip emails:**

Expanding the field sidebar revealed the complete picture of the phishing campaign:

| Field                             | Value                                                                     |
| --------------------------------- | ------------------------------------------------------------------------- |
| `sender`                          | Jim Smith `<jsmith@urinalysis.com>` (100% of events)                      |
| `subject`                         | Invoice (100% of events)                                                  |
| `receiver`                        | abungstein@froth.ly, btun@froth.ly, fyodor@froth.ly, klagerfield@froth.ly |
| `file_size`                       | 22,578 bytes (identical across all 4)                                     |
| `attach_type`                     | application/octet-stream                                                  |
| `attach_content_md5_hash`         | `20e368e2c9c6e91f24eeddd09369c4aa`                                        |
| `attach_content_decoded_md5_hash` | `0fa0f1b660962d4a4d1cd6782a03db05`                                        |
| `src_ip`                          | 104.47.37.62, 104.47.38.87, 104.47.41.43, 104.47.42.76                    |

The `application/octet-stream` content type is significant — it is the default MIME type for an unknown binary file. Browsers and mail clients treat it as a raw download rather than attempting to render it, which is a common technique for delivering compressed archives containing malicious payloads.

**Step 4 — Extract the true sender IP from the email content field:**

Examining the raw `content` field of one of the events revealed a full SMTP header, including the SPF authentication results line:

```
Authentication-Results: spf=pass (sender IP is 185.83.51.21)
smtp.mailfrom=smtp12.ymlpsvr.com; froth.ly; dkim=none
```

The four `src_ip` values (104.47.x.x) are Microsoft Exchange Online Protection relay servers — the mail routing infrastructure, not the origin. The true sending IP is **185.83.51.21**. This can be extracted programmatically:

```splunk
index=botsv2 sourcetype=stream:smtp attach_filename()=invoice.zip
| rex field=content "sender IP is (?<sender_ip>\d+\.\d+\.\d+\.\d+)"
| search sender_ip=185.83.51.21
```

→ Confirmed 4 events, same four recipients.

**Step 5 — Read the email body:**

The `content_body` field contained the social engineering lure:

> *"As we have not received a service cessation letter, I am assuming that you might have accidentally overlooked this invoice 02/160000506500 (Unpaid) for 10,000 GBP. Should you wish to bring an end to the agreement please let us know. Otherwise early withdrawal penalties will apply next month. Please refer to the attached document for payment details. Due to the personal nature of the account we have added a password to the document. Please enter the password (912345678)."*

Classic financial urgency lure. The password-protected ZIP is a deliberate evasion technique — encrypted archives cannot be scanned by most email security gateways.

**Step 6 — OSINT on the sender infrastructure:**

The four `src_ip` values all resolved to Microsoft Exchange Online Protection relay hostnames (`*.outbound.protection.outlook.com`), geolocating to **Redmond, Washington** — entirely consistent with a commercial Microsoft 365 account used to send the phish.

The true sending IP, **185.83.51.21**, told a more interesting story:

| Tool    | Finding                                                            |
| ------- | ------------------------------------------------------------------ |
| Censys  | Hostname: smtp12.ymlpsvr.com, Belgium (Brussels)                   |
| Network | YMLP — YourMailingListProvider.com (commercial bulk email service) |
| ATT&CK  | T1583.006 — Acquire Infrastructure: Web Services                   |

The attacker registered with a commercial bulk mailing service to send the phishing campaign. This is a common resource development technique — it provides legitimate-looking sending infrastructure, high deliverability, and built-in anonymity.

**Step 7 — WHOIS on urinalysis.com:**

| Field      | Value                                       |
| ---------- | ------------------------------------------- |
| Registrant | Clayton Joy (cthomasjoy@gmail.com)          |
| Created    | 1998-10-30                                  |
| Location   | Chicago, Illinois                           |
| Registrar  | DomainPeople, Inc.                          |
| IP         | 64.71.33.46 (71 other sites on same server) |

An almost 20-year-old domain registered via Gmail with dozens of co-hosted sites — low-confidence attribution but a notable indicator.

**Step 8 — Discover the first wave:**

Searching for all emails from the same sender across the full time window revealed two separate campaigns:

```splunk
index=botsv2 sourcetype=stream:smtp sender="Jim Smith <jsmith@urinalysis.com>"
| table _time recipient subject attach_filename() attach_size() attach_content_decoded_md5_hash()
| sort recipient
```

→ **8 events total** — two separate waves targeting the exact same four recipients:

| Wave | Date       | Subject     | Attachment             | Size         | Result        |
| ---- | ---------- | ----------- | ---------------------- | ------------ | ------------- |
| 1    | 2017-08-10 | Invoice Doc | Malware Alert Text.txt | 256 bytes    | **Blocked**   |
| 2    | 2017-08-23 | Invoice     | invoice.zip            | 22,578 bytes | **Delivered** |

**Step 9 — Decode Malware Alert Text.txt:**

The 256-byte `.txt` file from Wave 1 had a `Content-Transfer-Encoding: base64` header. Decoding it in CyberChef (From Base64, Remove Non-Alphabet Characters) revealed:

```
Malware was detected in one or more attachments included with this message.
Action: All attachments have been removed.
invoice.doc    Trojan.ZVEJ-2
invoice.doc    097M/Donoff!rfn
```

Wave 1 was not a `.txt` file — it was the quarantine notification from Frothly's email security gateway. The original attachment was `invoice.doc`, detected as a Trojan (Donoff is a well-known malicious macro dropper family). The attacker saw it was blocked and adapted: the second attempt used a **password-encrypted ZIP** to bypass the same scanner.

**Step 10 — VirusTotal on the invoice.zip hash:**

Running the decoded MD5 hash `0fa0f1b660962d4a4d1cd6782a03db05` against VirusTotal returned:

| Field           | Value                         |
| --------------- | ----------------------------- |
| Detection ratio | **0 / 58** — fully undetected |
| File type       | Encrypted ZIP archive         |
| Contents        | invoice.doc (238,992 bytes)   |
| Compiled        | 2017-08-01 23:26              |

Zero detections. The password-protection rendered it opaque to every scanner on the platform at the time of analysis.

### Findings — Hunt 1

| IOC                | Value                                                                  |
| ------------------ | ---------------------------------------------------------------------- |
| Sender             | Jim Smith `<jsmith@urinalysis.com>`                                    |
| True sender IP     | 185.83.51.21 (smtp12.ymlpsvr.com — YMLP Belgium)                       |
| Relay IPs          | 104.47.37.62, 104.47.38.87, 104.47.41.43, 104.47.42.76 (Microsoft EOP) |
| Targets            | abungstein, btun, fyodor, klagerfield @froth.ly                        |
| Wave 1 (blocked)   | invoice.doc — Trojan.ZVEJ-2 / 097M/Donoff!rfn — 2017-08-10             |
| Wave 2 (delivered) | invoice.zip — 0/58 on VirusTotal — 2017-08-23                          |
| Attachment hash    | `0fa0f1b660962d4a4d1cd6782a03db05`                                     |
| Lure               | Financial invoice, GBP payment dispute, password-protected archive     |

**Hypothesis confirmed.** A two-wave spearphishing campaign targeted four Frothly employees. Wave 1 was caught by the email gateway; the attacker adapted by switching to an encrypted ZIP that evaded all detection on Wave 2.

---

## Hunt 2 — User Execution: Malicious File

**MITRE ATT&CK T1204.002 — User Execution: Malicious File**

### Hypothesis

With the spearphishing delivery confirmed, the adversary relied on a user opening the malicious attachment to gain code execution. We know the payload inside `invoice.zip` was `invoice.doc`. We need to determine: did anyone open it, on which host, and what happened immediately after?

**Questions to answer:**
- Do any endpoint sourcetypes show activity related to invoice.zip?
- Which host and user account executed the file?
- What process activity followed the file open?
- Is there evidence of macro execution or post-exploitation staging?

### Investigation

**Step 1 — Hunt for invoice.zip across all non-email sourcetypes:**

```splunk
index=botsv2 sourcetype!=stream:smtp invoice.zip
```

Time-boxed to **Wednesday, August 23, 2017** — the day the second wave was delivered. This returned **5 events**, all on a single host: **wrk-btun**.

The sourcetype breakdown was immediately telling:

| Sourcetype                                          | Count |
| --------------------------------------------------- | ----- |
| XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | 2     |
| WinHostMon                                          | 1     |
| WinRegistry                                         | 1     |
| wineventlog                                         | 1     |

Sysmon telemetry, registry writes, and Windows Event Logs all touching `invoice.zip` on `wrk-btun` — the workstation belonging to **Billy Tun**, one of the four targeted recipients.

**Step 2 — Isolate Sysmon events for invoice.zip:**

```splunk
index=botsv2 sourcetype!=stream:smtp invoice.zip
  sourcetype="XmlWinEventLog:microsoft-windows-sysmon/operational"
```

→ **3 events** on wrk-btun during the execution window:

**Event 1 — 8/23/17 20:38:12 PM — Process Create (Sysmon EventID 1):**

```
Image:          C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE
CommandLine:    "WINWORD.EXE" /n "C:\Users\billy.tun\AppData\Local\Temp\Temp1_invoice.zip\invoice.doc" /o "u"
ParentCommandLine: C:\Windows\Explorer.EXE
User:           FROTHLY\billy.tun
Computer:       wrk-btun.frothly.local
```

Billy Tun double-clicked `invoice.zip` in Explorer, which extracted `invoice.doc` to a temp folder and opened it in Word. The `/o "u"` flag is Word's "open with update links" switch — relevant because it can trigger automatic content execution.

**Event 2 — 8/23/17 20:41:53 PM — Registry Set (Sysmon EventID 13):**

```
key_path: Microsoft\Office\16.0\Word\reading locations\document 0\file path
```

Word wrote the opened document path to the registry — confirming the file was accessed and logged by Office.

**Step 3 — Examine all Sysmon activity on wrk-btun in the minutes following Word opening:**

Setting the time range to **8/23/17 20:28:55 PM → 20:30:00 PM** and reversing the sort to show oldest-first revealed **25 events** on wrk-btun — a burst of process creation activity immediately after WINWORD.EXE launched.

The key event:

**8/23/17 20:28:55 PM — Sysmon Process Create:**

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:    powershell -nop -sta -w 1 -enc <2842-character Base64 string>
ParentCommandLine: C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE
User:           FROTHLY\billy.tun
```

WINWORD.EXE spawned PowerShell with a hidden window (`-w 1`), no profile (`-nop`), single-threaded apartment (`-sta`), and a massive encoded payload (`-enc`). This is the textbook signature of a macro-dropped PowerShell stager.

This also surfaces a second ATT&CK technique intersecting the hunt:

> **T1132.001 — Data Encoding: Standard Encoding** — The encoded command matches the "hunting for PowerShell surfaces data encoding" principle from the MITRE ATT&CK module. One hunt, two techniques.

**Step 4 — Decode the Base64 payload in CyberChef:**

Running the 2,842-character encoded command through CyberChef (From Base64) produced a lengthy .NET-based PowerShell script. Key strings visible in the output:

```
[R.E.F.].A.S.S.E.M.B.L.Y.
.S.y.s.t.e.m...M.a.n.a.g.e.m.e.n.t...A.u.t.o.m.a.t.i.o.n.
.S.y.s.t.e.m...N.e.t...S.e.r.v.i.c.e.P.o.i.n.t.M.a.n.a.g.e.r.
.S.y.s.t.e.m...N.e.t...W.e.b.C.l.i.e.n.t.
.S.y.s.t.e.m...N.e.t...H.e.a.d.e.r.s...A.d.d.
.S.y.s.t.e.m...N.e.t...C.r.e.d.e.n.t.i.a.l.C.a.c.h.e.
```

The decoded payload was a **PowerShell Empire** (or equivalent framework) stager — loading `System.Management.Automation` and `System.Net.WebClient` assemblies in memory, setting up HTTP callbacks, and configuring credential and proxy handling. This is fileless post-exploitation staging designed to pull down a second-stage implant from a C2 server entirely in memory.

### Findings — Hunt 2

| Finding          | Detail                                                                |
| ---------------- | --------------------------------------------------------------------- |
| Victim host      | wrk-btun (wrk-btun.frothly.local)                                     |
| Victim user      | FROTHLY\billy.tun                                                     |
| Execution time   | 2017-08-23 20:38:12 PM                                                |
| File executed    | `C:\Users\billy.tun\AppData\Local\Temp\Temp1_invoice.zip\invoice.doc` |
| Parent process   | Explorer.EXE (user double-clicked the file)                           |
| Child process    | WINWORD.EXE → PowerShell (macro execution)                            |
| PowerShell flags | `-nop -sta -w 1 -enc` (hidden, no profile, encoded)                   |
| Payload type     | PowerShell Empire-style in-memory stager                              |

**Hypothesis confirmed.** Billy Tun opened `invoice.doc` extracted from the phishing ZIP. The document contained a malicious macro that immediately spawned an encoded PowerShell stager — a fileless implant loader designed to pull a second-stage payload from a remote C2.

---

## Full Attack Timeline

| Timestamp           | Event                                                                                                | ATT&CK Technique                                 |
| ------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| 2017-08-01 23:26    | invoice.doc compiled and packaged into encrypted invoice.zip                                         | T1583.006 — Acquire Infrastructure: Web Services |
| 2017-08-10 ~20:24   | Wave 1: invoice.doc sent to 4 Frothly targets — **blocked**, detected as Trojan.ZVEJ-2 / 097M/Donoff | T1566.001 — Spearphishing Attachment             |
| 2017-08-23 ~20:27   | Wave 2: Encrypted invoice.zip sent to same 4 targets — **delivered**, 0/58 on VirusTotal             | T1566.001 — Spearphishing Attachment             |
| 2017-08-23 20:38:12 | Billy Tun opens invoice.doc via Explorer on wrk-btun                                                 | T1204.002 — User Execution: Malicious File       |
| 2017-08-23 20:38:55 | WINWORD.EXE spawns PowerShell with encoded stager                                                    | T1059.001 — PowerShell                           |
| 2017-08-23 20:38:55 | Base64-encoded PowerShell payload executed in memory                                                 | T1132.001 — Data Encoding: Standard Encoding     |

---

## What Can We Operationalize?

### Hunt 1 — Email Detection

**1. Alert on same-filename, same-size attachments sent to multiple internal recipients**

The most reliable detection from this hunt is behavioral: the same `invoice.zip` (identical filename and byte size) delivered to four employees in rapid succession from an external sender. A SIEM rule flagging external emails where `attach_filename` and `file_size` match across more than two internal recipients within a short window would have fired on this pattern.

```splunk
index=botsv2 sourcetype=stream:smtp
| stats dc(receiver) as recipient_count values(receiver) as recipients by sender attach_filename() attach_size()
| where recipient_count > 2
| sort - recipient_count
```

**2. Automate attachment hash lookups against threat intelligence**

The Wave 1 attachment was detected by the email gateway and quarantined. Wave 2 evaded it entirely because the ZIP was encrypted. Automating hash lookups against VirusTotal, MalwareBazaar, or an internal threat intel feed for all inbound attachments — including inside archives where possible — adds a second detection layer. Note: encrypted ZIPs cannot be scanned without the password, which is itself a detection signal.

**3. Watchlist the sender domain and true sender IP**

Add `urinalysis.com` and `185.83.51.21` to watchlists. Monitor for future connections from `smtp12.ymlpsvr.com`. IP-level blocking is a double-edged sword (legitimate YMLP customers exist), but domain-level alerting has low false-positive risk for this specific sender.

### Hunt 2 — Endpoint Detection

**4. Alert on Office applications spawning PowerShell**

The most actionable detection from this entire investigation is a single Sysmon rule: any process where `ParentImage` contains `WINWORD.EXE`, `EXCEL.EXE`, or `POWERPNT.EXE` and `Image` contains `powershell.exe`. This parent-child relationship is almost never legitimate and is the canonical macro execution indicator.

```splunk
index=botsv2 sourcetype="XmlWinEventLog:microsoft-windows-sysmon/operational"
  EventCode=1
| where like(ParentCommandLine, "%WINWORD%") AND like(CommandLine, "%powershell%")
| table _time host User CommandLine ParentCommandLine
```

**5. Alert on encoded PowerShell execution**

The `-enc` flag combined with a long base64 string is a high-fidelity detection for obfuscated stager activity. Alert on Windows Event Code 4688 or Sysmon EventID 1 where `CommandLine` matches:

```splunk
index=botsv2 sourcetype="XmlWinEventLog:microsoft-windows-sysmon/operational"
  EventCode=1 CommandLine="*powershell*" CommandLine="* -enc *"
| table _time host User CommandLine
```

**6. Apply EDR coverage with macro execution monitoring**

An EDR solution with macro behavior analysis (Defender for Endpoint, Cortex XDR, CrowdStrike) would surface the Word → PowerShell process chain in real time and could block it automatically based on policy. This is more reliable than trying to prohibit macro-enabled files outright, which often breaks legitimate business processes.

---

## Key Takeaways

The two-wave structure of this attack is the most instructive element. The attacker received indirect feedback that Wave 1 was blocked — they never saw the quarantine notification, but the absence of a response (or the lack of a follow-on callback) told them something failed. They adapted within 13 days by switching to an encrypted archive with an embedded password in the lure email, effectively neutering the email gateway.

That behavioral adaptation — observe, modify, retry — is characteristic of a patient, disciplined threat actor. It also highlights a fundamental limitation of signature-based detection: once an attacker knows what got caught, they can tune around it. The behavioral detections described above (Office spawning PowerShell, encoded command lines) are significantly harder to evade because they target *how* the malware operates, not *what it looks like*.

**Tools used:** Splunk (SPL), CyberChef, VirusTotal, Censys, DomainTools WHOIS

**Dataset:** [Splunk BOTS v2 — github.com/splunk/botsv2](https://github.com/splunk/botsv2)
