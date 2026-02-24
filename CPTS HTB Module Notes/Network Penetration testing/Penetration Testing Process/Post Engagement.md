## 🎯 Purpose of Post-Engagement

Post-Engagement ensures:

- Client systems are returned to original state
    
- All evidence is properly documented
    
- The report is accurate, professional, and actionable
    
- The client can reproduce findings
    
- Legal and contractual obligations are met
    
- Data is handled securely
    
- The project is formally and cleanly closed
    

---

## 🧹 1. Cleanup (Critical and Often Overlooked)

You **must leave no trace** of your testing artifacts.

### Remove:

- Uploaded tools, payloads, scripts
    
- Created user accounts
    
- Persistence mechanisms
    
- Configuration changes
    
- Temporary files
    
- Reverse shells / bind shells
    
- Port forwards, tunnels, cron jobs, services, registry keys
    

If you **cannot** remove something:

- Notify client
    
- Document in report appendix
    

Even if you _do_ remove it:

- Document it anyway (for alert correlation)
    

---

## 🗂️ 2. Documentation Before Disconnecting

Before sending the “testing complete” email:

You must have:

- Screenshots
    
- Command outputs
    
- Hostnames/IPs
    
- Proof of exploitation
    
- Logs and scan outputs
    
- Evidence of compromised accounts
    
- Evidence of privilege escalation
    
- Evidence of lateral movement
    
- Evidence of data access/exfiltration (if applicable)
    

⚠️ Never keep:

- PII
    
- Real sensitive client data
    
- Credentials (after report is done)
    

---

## 📝 3. What the Report MUST Contain

A professional pentest report includes:

### Executive Section (non-technical)

- Business impact
    
- Risk summary
    
- Attack story in plain English
    

### Technical Findings

Each finding must include:

- Risk rating
    
- Impact
    
- Affected hosts
    
- Steps to reproduce
    
- Remediation advice
    
- References
    

### Attack Chain (if applicable)

Shows how multiple issues led to compromise.

### Recommendations

- Near-term
    
- Medium-term
    
- Long-term
    

### Appendices

- Scope
    
- OSINT findings
    
- Cracked passwords analysis
    
- Open ports/services
    
- Compromised hosts/accounts
    
- Artifacts created
    
- Scan outputs
    
- AD analysis (if relevant)
    

---

## 👥 4. Report Review Meeting

This is **very important** professionally.

You:

- Walk through findings
    
- Explain context
    
- Answer questions
    
- Clarify misunderstandings
    
- Emphasize root causes
    

You **do not** read the report word-for-word.

Clients often:

- Focus on high/medium findings
    
- Bring SMEs
    
- Ask detailed questions
    

---

## ✅ 5. Deliverable Acceptance (DRAFT → FINAL)

Process:

1. Send **DRAFT**
    
2. Client reviews, comments
    
3. Adjust / clarify
    
4. Issue **FINAL**
    

Some audit firms will **not accept DRAFT**, so FINAL is important.

---

## 🔁 6. Post-Remediation Testing (Retest)

Often included in contract.

You verify fixes.

Example table in retest report:

|#|Severity|Finding|Status|
|---|---|---|---|
|1|High|SQL Injection|Remediated|
|2|High|Broken Auth|Remediated|
|3|Medium|SMB Signing|Not Remediated|

You must show:

- Original exploit no longer works
    
- Scan proof
    
- Evidence of fix
    

---

## ⚖️ 7. Your Role in Remediation (Very Important)

You are an **auditor**, not an implementer.

You:

- Explain issue
    
- Give general remediation advice
    

You do NOT:

- Patch systems
    
- Rewrite code
    
- Change configs
    
- Log into AD to fix things
    

Why?

> To avoid conflict of interest and preserve assessment integrity.

---

## 🔐 8. Data Retention & Destruction

You will have:

- Credentials
    
- Screenshots
    
- Logs
    
- Sensitive info
    

Best practices (and often contractual):

- Store encrypted
    
- Keep for defined time
    
- Wipe from tester machines
    
- Use dedicated VM per client
    
- Recreate new VM for retests
    
- Follow PCI DSS / legal guidance
    

Evidence may be needed later.

---

## 🏁 9. Formal Close-Out

Final steps:

- Final report delivered
    
- Questions answered
    
- Retest done (if applicable)
    
- Systems wiped
    
- Artifacts archived securely
    
- Invoice sent
    
- Client satisfaction follow-up
    

---

## 💼 The Professional Lesson

Clients remember:

> Communication, professionalism, clarity, and respect.

Not:

> The crazy exploit chain you pulled off.

This is where you grow from:

**Hacker → Consultant → Trusted Advisor**

---

## 🧠 Key Takeaways

Post-Engagement is where you:

- Protect the client
    
- Protect yourself legally
    
- Deliver professional value
    
- Turn technical skill into business impact
    
- Build long-term client trust
    

This stage is **as important** as exploitation.

![[Pasted image 20260205121853.png]]