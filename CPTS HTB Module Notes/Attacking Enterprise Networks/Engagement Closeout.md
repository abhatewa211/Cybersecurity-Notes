# 1. Engagement Closeout

Once the penetration testing engagement reaches its end, the tester must perform several activities before the project can officially be closed.

The main objectives are:

1. Notify the client that testing has ended.
2. Confirm when the final report will be delivered.
3. Summarize the attack path.
4. Organize and prioritize findings.
5. Perform post-engagement cleanup.
6. Maintain communication with the client.
7. Complete internal project-closeout activities.

### Important principle

> **Never simply stop testing and disappear.**

The client needs to know that testing has ended so that any unusual activity after that point can be distinguished from penetration-testing activity.

---

# 2. Client Notification — Testing Has Ended

The **first task** after completing testing is to notify the client.

The email should communicate:

- The testing period has ended.
- The tester is no longer actively testing the environment.
- The expected report delivery date/timeframe.
- Optionally, a brief summary of significant findings.
- Potential timing for a report review meeting, if appropriate.

### Why is this important?

The client's security team may continue seeing:

- Authentication attempts
- Network scans
- Exploit attempts
- Suspicious connections
- Alerts from EDR/SIEM
- Other abnormal activity

They need to know when those activities are **no longer coming from the pentest team**.

### Example

> **Subject: Penetration Test – Testing Completed**
> 
> Hello Team,
> 
> We would like to confirm that the penetration testing activities for the agreed scope have now been completed.
> 
> Testing concluded on [DATE/TIME].
> 
> The final penetration testing report is expected to be delivered by [DATE].
> 
> The report will include the identified vulnerabilities, evidence, risk ratings, attack-path analysis, and remediation recommendations.
> 
> We will coordinate with you regarding the report review meeting once the report has been delivered.
> 
> Regards,  
> Penetration Testing Team

---

# 3. Important: Don't Blindside the Client

A very important professional practice is **clear communication throughout the assessment**.

If a serious vulnerability is discovered, the client ideally shouldn't hear about it for the first time when they open the final report.

For example:

If you discover:

- Command injection
- Domain compromise
- Critical authentication weakness
- Administrator compromise
- Sensitive-data exposure

the appropriate communication process may require the client/project manager to be informed according to the engagement's rules.

### Why?

Imagine the final report says:

> **CRITICAL — Domain Administrator compromise achieved**

while the client had absolutely no idea that their entire domain had been compromised during testing.

That creates unnecessary surprise and can damage the engagement.

### Key takeaway

**Good pentesting isn't just about finding vulnerabilities.**

It is also about:

> **Testing + Documentation + Communication + Evidence + Professionalism**

---

# 4. Attack Path Recap

After testing is complete, write down the **attack path from beginning to end**.

This is one of the most useful things you can do before writing the report.

An attack path describes:

**Initial Access → Enumeration → Exploitation → Credential Access → Lateral Movement → Privilege Escalation → Domain/Target Compromise**

An attack path represents the chain used to reach the final objective rather than simply listing vulnerabilities individually. [Picus Security](https://www.picussecurity.com/resource/blog/what-is-an-attack-path-in-automated-pentesting?utm_source=chatgpt.com)

---

# 5. Why Create an Attack Path?

The attack-path recap helps you:

### 1. Visualize what happened

Instead of looking at 30 individual notes, you can see:

```
External Service
      ↓
Initial Foothold
      ↓
Credential Discovery
      ↓
Internal Access
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Domain Compromise
```

### 2. Identify important findings

Some vulnerabilities might appear low-risk individually but become extremely important when chained together.

For example:

```
Weak Password
     +
Exposed Service
     +
Overprivileged Account
     ↓
Domain Administrator
```

The individual weaknesses don't tell the whole story.

### 3. Ensure nothing was missed

The attack-path review allows you to go through the entire chain and ask:

- Where did initial access occur?
- How did I obtain credentials?
- How did I move internally?
- How did I escalate privileges?
- How did I reach the final target?
- What evidence proves each step?

---

# 6. Least-Resistance Attack Path

**Very important for CPTS:**

The attack-path recap should show the **path of least resistance**.

It should **NOT** contain:

- Every command you ran
- Every failed exploit
- Every dead end
- Every tool you tried
- Your entire thought process
- Unsuccessful experiments

### Example

Suppose you tried:

```
Nmap
 ↓
SMB exploit → Failed
 ↓
FTP exploit → Failed
 ↓
SSH brute force → Failed
 ↓
Web enumeration
 ↓
Command injection → Successful
 ↓
Shell
 ↓
Credential discovery
 ↓
Domain compromise
```

Your final attack-path summary should generally focus on:

```
Web Application
      ↓
Command Injection
      ↓
Initial Shell
      ↓
Credential Discovery
      ↓
Internal Access
      ↓
Privilege Escalation
      ↓
Domain Compromise
```

The failed attempts can remain in your **internal testing notes**, but they don't necessarily belong in the attack-path summary.

---

# 7. Attack Path vs Full Testing History

This distinction is extremely important.

|Attack Path|Full Testing History|
|---|---|
|Shows successful/important chain|Contains everything tested|
|Concise|Detailed|
|Focuses on path to objective|Includes failures|
|Useful for client report|Useful for tester|
|Shows impact|Shows methodology/history|
|Easy to understand|Can become very large|

### Remember:

> **Attack path = What worked and how it led to the objective.**

> **Testing history = Everything you did while testing.**

---

# 8. Narrative-Style Reporting

Some penetration-testing companies structure reports as a **narrative**.

Instead of presenting findings independently, the report tells the story of the attack.

Example:

```
The tester identified an externally accessible service.
        ↓
A weak credential was discovered.
        ↓
The credentials provided access to an internal system.
        ↓
Additional credentials were recovered.
        ↓
The tester used those credentials to access another host.
        ↓
Privilege escalation was achieved.
        ↓
Domain-level compromise was demonstrated.
```

This approach makes the attack understandable to the reader.

However, reporting style differs from company to company.

---

# 9. Structuring Your Findings

Ideally, findings should be documented **while testing is happening**.

Do not wait until the end.

During testing, record:

- Commands
- Output
- Screenshots
- Hostnames
- IP addresses
- Usernames
- Vulnerabilities
- Evidence
- Exploitation results
- Impact
- Remediation information

---

# 10. Why Documentation Must Happen During Testing

Imagine you discovered a critical vulnerability on Day 1.

Then on Day 5 you remember:

> "Oh shit, what was the exact command I used?"

If you didn't document it, you may have to:

- Recreate the attack
- Request access again
- Reconnect to the internal network
- Re-run scans
- Ask the client to restore access
- Potentially lose important evidence

Therefore:

> **Document as you go.**

---

# 11. Prioritize Findings

Findings should be organized from:

**Highest Risk → Lowest Risk**

Example:

|Priority|Finding|Severity|
|---|---|---|
|1|Domain compromise|Critical|
|2|Command injection|Critical|
|3|Privileged credential exposure|High|
|4|Weak passwords|High|
|5|SMB configuration issue|Medium|
|6|Information disclosure|Low|

The prioritized list becomes extremely useful when writing the final report.

---

# 12. Finding Documentation Template

For every finding, try to maintain something similar to:

```
Finding:
Command Injection

Severity:
Critical

Affected Host:
10.10.x.x

Affected Service:
Web Application

Description:
The application allows attacker-controlled input to reach a
command execution context without sufficient validation.

Evidence:
[Relevant screenshot/output]

Impact:
An attacker may execute commands on the affected server and
potentially use the system as an initial foothold.

Attack Path:
Command Injection
      ↓
Initial Shell
      ↓
Credential Discovery
      ↓
Internal Access

Recommendation:
Implement proper input validation and safe command execution.
```

This makes report writing much easier.

---

# 13. Evidence Collection

Before the engagement ends, make sure you have all required evidence.

Examples:

### Screenshots

- Vulnerability confirmation
- Successful exploitation
- Shell access
- Privilege escalation
- Sensitive information exposure
- Domain compromise

### Command Output

Keep relevant:

```
nmap
ldapsearch
netexec
bloodhound
whoami
ipconfig
hostname
```

and other outputs that prove your findings.

### Important rule

Evidence should prove:

> **What was vulnerable + how it was exploited + what impact was achieved.**

---

# 14. Post-Engagement Cleanup

This is one of the **most important sections**.

If this were a real engagement, you should keep track of:

- Every scan
- Every attack attempt
- Every file placed on a system
- Every change made
- Every account created
- Every configuration modification
- Every compromised account
- Every compromised host

---

# 15. Remove Files You Uploaded

During testing you may have uploaded:

- Tools
- Scripts
- Payloads
- Shells
- Temporary files
- Enumeration tools
- Test binaries

Before leaving the environment:

> **Delete anything you uploaded, where authorized and safe to do so.**

For example:

```
Tester uploads tool
        ↓
Uses tool
        ↓
Collects evidence
        ↓
Testing complete
        ↓
Remove uploaded tool
```

---

# 16. Restore Changes

If you made changes during the engagement, restore them where possible.

Examples:

### Accounts

If you created a temporary test account:

```
test-pentest-user
```

remove it if the engagement requires cleanup.

### Configuration

If you changed a configuration temporarily:

```
Original configuration
        ↓
Testing modification
        ↓
Testing complete
        ↓
Restore original configuration
```

### Files

Remove:

- Payloads
- Scripts
- Web shells
- Test files
- Temporary artifacts

---

# 17. IMPORTANT — Document Everything Even If Cleaned Up

This is extremely important.

**Cleaning something up does NOT mean you should forget about it in the report.**

Your report appendices should document:

- Changes made
- Files uploaded
- Accounts created
- Accounts compromised
- Hosts compromised
- Methods used
- Relevant testing activity

For example:

```
Host: SERVER01

File uploaded:
test_tool.exe

Purpose:
Security testing

Location:
/tmp/test_tool.exe

Action:
Removed after testing

Status:
Cleanup completed
```

This provides accountability and helps the client understand what happened.

---

# 18. Keep Logs After the Engagement

Your testing logs should be retained for an appropriate period according to company policy and engagement requirements.

Why?

The client may later contact you and say:

> "Our SIEM detected suspicious authentication activity on Tuesday. Was that your testing?"

You need to be able to check your records.

Your logs can help correlate:

```
Tester Activity
       +
Client SIEM/EDR Alert
       ↓
Determine whether activity
was generated by pentest
```

---

# 19. Second Pass — Pentest Like a Real Production Network

The module recommends going through the environment **a second time**.

But this time:

> Treat the network like a real production environment.

That means:

### Minimize unnecessary impact

Avoid unnecessarily:

- Crashing services
- Destroying data
- Locking accounts
- Running destructive exploits
- Modifying production configurations
- Leaving payloads behind

### Document every action

Ask:

> "If this were a real client, would I be comfortable explaining this action?"

If the answer is no, reconsider whether the action is necessary and within scope.

---

# 20. Client Communication After Testing

Testing doesn't end when you stop running commands.

You should continue communicating with the client during the reporting phase.

The client should receive:

### Testing completion notification

```
Testing ended:
[DATE/TIME]
```

### Report delivery date

```
Report expected:
[DATE]
```

### Findings recap

If requested/appropriate:

```
Critical:
2

High:
4

Medium:
6
```

### Report review

A meeting may be scheduled where the tester walks the client through:

- Executive summary
- Critical findings
- Attack path
- Technical findings
- Business impact
- Remediation recommendations

---

# 21. Retesting

If **retesting is included in the Scope of Work**, establish a timeline with the client.

Typical flow:

```
Pentest
   ↓
Findings
   ↓
Report
   ↓
Client Remediation
   ↓
Retest
   ↓
Verify Fixes
   ↓
Final Status
```

### Important

Do not assume retesting is automatically included.

It depends on the:

> **Scope of Work (SoW)**

---

# 22. Client May Contact You Later

The client might contact the penetration-testing team days or weeks later.

For example:

> "We received an alert showing a suspicious login from SERVER02. Was that related to your test?"

You should have your:

- Notes
- Logs
- Screenshots
- Commands
- Timeline
- Activity records

available to answer.

---

# 23. Internal Project Closeout

After:

1. Report delivery
2. Report review meeting
3. Final client communication

the company performs internal closeout activities.

### Typical activities

- Archive the report
- Archive project data
- Store evidence appropriately
- Hold lessons-learned meeting
- Complete sales/post-engagement questionnaire
- Perform invoicing
- Complete administrative tasks

---

# 24. Archiving

The final report and associated project information may be archived on the company's approved storage/share drive according to internal retention policies.

Potentially archived information includes:

```
Final Report
     +
Evidence
     +
Testing Notes
     +
Logs
     +
Screenshots
     +
Scope Documentation
```

---

# 25. Lessons Learned

A **lessons-learned debriefing** should answer:

### What went well?

Examples:

- Enumeration was efficient.
- Documentation was good.
- Communication was clear.
- Testing stayed within scope.
- Attack path was identified quickly.

### What went poorly?

Examples:

- Evidence wasn't captured immediately.
- Too much time was spent on dead ends.
- Reporting took longer than expected.
- Some tools weren't effective.
- Cleanup documentation was incomplete.

### What can be improved?

Create actionable improvements for the next engagement.

---

# 26. Knowledge Transfer

Ideally, the original tester performs post-remediation testing.

But sometimes schedules don't align.

In that situation:

```
Tester A
   ↓
Knowledge Transfer
   ↓
Tester B
   ↓
Post-Remediation Testing
```

Tester A should provide Tester B with enough information to understand:

- Original findings
- Affected systems
- Original attack path
- Evidence
- Expected remediation
- What needs to be retested

---

# 27. Complete Engagement Lifecycle

Here's the whole process you should remember:

```
                 PENETRATION TEST
                       │
                       ▼
              Scope & Objectives
                       │
                       ▼
                 Reconnaissance
                       │
                       ▼
                   Enumeration
                       │
                       ▼
                  Exploitation
                       │
                       ▼
               Privilege Escalation
                       │
                       ▼
                Lateral Movement
                       │
                       ▼
                 Final Objective
                       │
                       ▼
               Evidence Collection
                       │
                       ▼
              Attack Path Recap
                       │
                       ▼
               Findings Prioritized
                       │
                       ▼
                 Cleanup
                       │
                       ▼
             Testing Completion Email
                       │
                       ▼
                Final Report
                       │
                       ▼
               Report Review Meeting
                       │
                       ▼
               Client Remediation
                       │
                       ▼
                    Retest
                       │
                       ▼
             Internal Project Closeout
                       │
                       ▼
               Lessons Learned
```

---

# 28. CPTS — What You Should Remember

For your CPTS preparation, these are the **high-value concepts**.

### 🔴 1. Notify the client

When testing ends:

> **Tell the client immediately that testing has ended.**

---

### 🔴 2. Give a report delivery timeframe

Don't simply say:

> "We'll send the report later."

Provide a precise expected delivery date/timeframe.

---

### 🔴 3. Don't blindside the client

If serious findings were discovered, communication should be handled appropriately during the engagement.

---

### 🔴 4. Create an attack-path recap

Show:

```
Initial Access
      ↓
Foothold
      ↓
Credential Access
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Target / Domain Compromise
```

---

### 🔴 5. Show the path of least resistance

Don't clutter the attack path with every failed attempt.

**Focus on the successful/important chain.**

---

### 🔴 6. Document findings while testing

Record:

- Commands
- Output
- Screenshots
- Evidence
- Affected systems
- Impact
- Remediation

---

### 🔴 7. Prioritize findings

Sort:

```
Critical
   ↓
High
   ↓
Medium
   ↓
Low
   ↓
Informational
```

---

### 🔴 8. Clean up

Remove:

- Uploaded files
- Tools
- Payloads
- Shells
- Temporary accounts
- Temporary changes

where authorized and appropriate.

---

### 🔴 9. Document cleanup

Even after removing something, **record that it existed and was removed**.

---

### 🔴 10. Keep logs

Logs may be needed later to correlate:

```
Pentest activity ↔ Client alerts
```

---

### 🔴 11. Treat the lab like production

The module specifically recommends:

> **Go back through a second time and pentest it as if it were an actual production network.**

Use minimally invasive techniques and clean up after yourself.

---

### 🔴 12. Retesting depends on scope

If retesting is included in the **Scope of Work**, coordinate remediation and retesting.

---

# 29. Quick Revision Sheet

## Engagement Closeout

```
1. Stop testing
2. Notify client
3. Confirm report timeline
4. Recap attack path
5. Organize findings
6. Collect final evidence
7. Clean up
8. Preserve logs
9. Deliver report
10. Review with client
11. Retest if in scope
12. Archive project
13. Lessons learned
14. Close project
```

---

# 30. Attack Path — One-Line Memory Trick

Remember:

> **ACCESS → FOOTHOLD → ENUMERATE → MOVE → ESCALATE → COMPROMISE → DOCUMENT → CLEAN**

Or:

```
A → F → E → M → E → C → D → C
```

**Access → Foothold → Enumeration → Movement → Escalation → Compromise → Documentation → Cleanup**

---

# 31. Findings Documentation — Memory Trick

For every finding, remember:

> **What? Where? How? Evidence? Impact? Fix?**

```
WHAT?
What is the vulnerability?

WHERE?
Where does it exist?

HOW?
How was it exploited?

EVIDENCE?
What proves it?

IMPACT?
What can an attacker achieve?

FIX?
How should it be remediated?
```

---

# 32. Final CPTS Takeaway

The biggest lesson from this section is that **a penetration test doesn't end when you obtain Domain Admin or complete the technical objective.**

A professional penetration test ends when you have:

**Tested → Documented → Communicated → Cleaned → Reported → Reviewed → Retested (if applicable) → Closed**

The technical exploitation is only one part of the job.

A professional pentester must be able to **prove what happened, explain how it happened, demonstrate the business impact, clean up their activity, communicate with the client, and produce a report that another person can understand and act upon.**

That is exactly the mindset you should use when you redo the **Inlanefreight Enterprise Network** lab without the guide.