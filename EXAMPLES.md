# 📋 APOA Examples

**Real-world scenarios for Agentic Power of Attorney — because "the future of AI" shouldn't require you to log into eleven different websites.**

The [README](README.md) covers three core scenarios: buying a home, coordinating healthcare, and surviving new parenthood. This document goes further. Each example below maps to a real category of traditional power of attorney, adapted for the digital world and the AI agents we keep being promised will change our lives.

They will. Once we let them actually *do things.*

---

## Table of Contents

1. [👴 Aging Parent Financial Management](#-aging-parent-financial-management)
2. [💼 Freelancer / Contractor Operations](#-freelancer--contractor-operations)
3. [⚰️ Estate Settlement After a Death](#️-estate-settlement-after-a-death)
4. [🎖️ Military Deployment](#️-military-deployment)
5. [🎓 College Application Tracking](#-college-application-tracking)
6. [🏗️ Home Renovation](#️-home-renovation)
7. [📄 Divorce Proceedings](#-divorce-proceedings)

---

## 👴 Aging Parent Financial Management

**Traditional POA type:** Durable Financial Power of Attorney

Your dad is 78. He's sharp, but the sheer volume of accounts, bills, Medicare paperwork, and insurance correspondence is becoming overwhelming. He's asked you to help keep things on track. You said yes, because you love him. You did not realize this would become a part-time job.

```yaml
authorization:
  type: "durable_financial"
  principal: "Juan Doe (on behalf of Robert Doe)"
  agent: "ElderCareFinBot"
  services:
    - service: "medicare.gov"
      scope: ["claims:read", "coverage:read", "eob:read"]
    - service: "socialsecurity.gov"
      scope: ["benefits:read", "payment_status:read"]
    - service: "bankofamerica.com"
      scope: ["accounts:read", "transactions:read", "bills:read"]
      constraints:
        transfers: false
        new_payees: false
    - service: "aetnamedicare.com"
      scope: ["claims:read", "prior_auth:read", "formulary:read"]
    - service: "turbotax.com"
      scope: ["returns:read", "documents:read"]
      constraints:
        filing: false  # read and organize only
  rules:
    - "Alert me if any bill is within 5 days of its due date"
    - "Flag any transaction over $500 that doesn't match recurring patterns"
    - "Track Medicare claim status and flag denials immediately"
    - "Generate monthly financial summary for family review"
    - "Never initiate payments, transfers, or account changes"
  expires: "2027-02-28"
  renewal: "annual_review"
  revocable: true
```

**Today:** You spend every other Sunday at your dad's kitchen table with a shoebox of mail, three browser tabs, and a growing sense of dread that you missed something important three weeks ago.

**With APOA:** Your agent monitors everything, flags the anomalies, and generates a clean summary you can review with Dad over coffee. The shoebox can finally retire.

---

## 💼 Freelancer / Contractor Operations

**Traditional POA type:** Limited Business Power of Attorney

You're a freelance designer. You are also, against your will, an accountant, a collections agent, a contract negotiator, a project manager, and a customer service department. The actual design work — the thing you're good at, the thing people pay you for — gets maybe 60% of your time. The rest is spent chasing invoices, tracking expenses, and wondering why QuickBooks is like that.

```yaml
authorization:
  type: "limited_business"
  principal: "Juan Doe"
  agent: "FreelanceOps"
  services:
    - service: "quickbooks.com"
      scope: ["invoices:read", "invoices:create_draft", "expenses:read", "payments:read"]
      constraints:
        send_invoice: false  # draft only, human sends
    - service: "stripe.com"
      scope: ["payments:read", "payouts:read", "disputes:read"]
    - service: "gmail.com"
      scope: ["messages:read"]
      constraints:
        labels: ["client-communications"]  # only reads client-tagged emails
        send: false
    - service: "calendly.com"
      scope: ["events:read", "availability:read"]
    - service: "notion.so"
      scope: ["projects:read", "tasks:read", "tasks:update_status"]
  rules:
    - "Flag any invoice unpaid after 30 days"
    - "Draft follow-up invoice reminders at 15, 30, and 45 days"
    - "Alert me to any Stripe disputes immediately"
    - "Generate weekly revenue and pipeline summary"
    - "Track project deadlines and alert me 3 days before any deliverable is due"
    - "Never send emails, invoices, or communications on my behalf"
  expires: "2026-12-31"
  revocable: true
```

**Today:** You spent three hours this week not designing. You sent nine follow-up emails about unpaid invoices. You forgot about a deliverable due Thursday. You are questioning your life choices.

**With APOA:** Your agent tracks the money, flags the deadlines, drafts the awkward "just following up!" emails, and lets you actually do your job. The life choices remain questionable, but at least you're getting paid on time.

---

## ⚰️ Estate Settlement After a Death

**Traditional POA type:** Executor Authority (Letters Testamentary)

Someone you love has died. I'm sorry. And now, in addition to grieving, you've been named executor of their estate. Which means you get to spend the next six to eighteen months navigating probate courts, tracking down accounts, notifying institutions, filing tax returns for a dead person, and dealing with the absolute *labyrinth* of bureaucracy that the United States has built around the simple fact of human mortality.

This is, without exaggeration, one of the most common reasons people hire attorneys. Not because the law is complex — because the *logistics* are overwhelming.

```yaml
authorization:
  type: "executor"
  principal: "Juan Doe (Executor of Estate of Robert Doe)"
  agent: "EstateSettlementBot"
  services:
    - service: "bankofamerica.com"
      scope: ["accounts:read", "transactions:read", "statements:read"]
      constraints:
        transfers: false
        closures: false
    - service: "fidelity.com"
      scope: ["accounts:read", "holdings:read", "beneficiary:read"]
    - service: "irs.gov"
      scope: ["transcripts:read", "filing_status:read"]
    - service: "courts.state.gov"
      scope: ["case_status:read", "filings:read", "deadlines:read"]
    - service: "usps.com"
      scope: ["mail_forwarding:read"]
  rules:
    - "Compile complete inventory of all financial accounts and current balances"
    - "Track all probate court deadlines and alert 14 days before each"
    - "Monitor for any incoming claims against the estate"
    - "Flag any automatic payments or subscriptions still active"
    - "Generate monthly estate status report"
    - "Never close accounts, transfer funds, or make distributions"
  expires: "2027-06-01"  # estimated estate settlement
  revocable: true
```

**Today:** You're spending evenings and weekends on hold with banks, filling out death certificate forms for the eighth time, and Googling "what is probate" at 11pm. While grieving. *This is the system working as designed, apparently.*

**With APOA:** Your agent compiles the inventory, tracks the deadlines, monitors for claims, and keeps everything organized — so you can focus on what actually matters right now, which is not a phone tree at Bank of America.

---

## 🎖️ Military Deployment

**Traditional POA type:** Military Power of Attorney (10 U.S.C. § 1044b)

You're deploying overseas for nine months. Your spouse is handling everything at home — mortgage payments, car insurance, kids' school enrollment, medical appointments, tax filings. A military power of attorney is already one of the most common legal documents in the armed forces. But even with a human POA, the day-to-day logistics of managing a household across a dozen digital services is exhausting for the person left behind.

```yaml
authorization:
  type: "military"
  principal: "SGT Juan Doe"
  agent: "HomeFrontBot"
  delegate: "Maria Doe"  # spouse retains oversight
  services:
    - service: "navyfederal.org"
      scope: ["accounts:read", "transactions:read", "bills:read", "payments:read"]
      constraints:
        transfers: false
        new_accounts: false
    - service: "tricare.mil"
      scope: ["claims:read", "referrals:read", "appointments:read"]
    - service: "dodea.edu"
      scope: ["enrollment:read", "grades:read", "communications:read"]
    - service: "usaa.com"
      scope: ["policies:read", "claims:read", "payments:read"]
    - service: "militaryonesource.mil"
      scope: ["benefits:read", "resources:read"]
  rules:
    - "Send weekly financial summary to both SGT Doe and Maria Doe"
    - "Alert Maria if any bill is within 3 days of due date"
    - "Track TRICARE referral status and flag expirations"
    - "Monitor school communications and flag action items"
    - "Never make payments, submit claims, or modify accounts"
  expires: "2027-03-01"  # deployment end date
  revocable: true
  co_principal: "Maria Doe"  # spouse can also revoke
```

**Today:** Your spouse is managing a full household, possibly with kids, while also tracking accounts, insurance claims, school paperwork, and benefit deadlines across a half-dozen government and military portals — some of which were built during the Clinton administration and have the UI to prove it.

**With APOA:** The agent handles the monitoring and deadline tracking, Maria gets a clean weekly summary, and both of you have visibility into what's happening at home. It won't make deployment easy, but it'll make the logistics one less thing to worry about.

---

## 🎓 College Application Tracking

**Traditional POA type:** Limited / Special Power of Attorney

Your kid is applying to twelve colleges. *Twelve.* Each one has its own portal. Each portal has its own login. Each login was created by your seventeen-year-old, who uses the same password for everything and has already forgotten which email they used for three of them.

There are recommendation letters to track, test scores to send, financial aid deadlines that vary by school, and supplemental essays that are each due on slightly different dates for reasons that no one has ever satisfactorily explained.

```yaml
authorization:
  type: "limited_special"
  principal: "Juan Doe (parent of Alex Doe)"
  agent: "CollegeTracker"
  services:
    - service: "commonapp.org"
      scope: ["applications:read", "requirements:read", "submissions:read"]
    - service: "collegeboard.org"
      scope: ["scores:read", "score_sends:read"]
    - service: "fafsa.gov"
      scope: ["application:read", "status:read", "sar:read"]
    - service: "coalition.org"
      scope: ["applications:read", "requirements:read"]
    - service: "gmail.com"
      scope: ["messages:read"]
      constraints:
        labels: ["college-apps"]
        send: false
  rules:
    - "Track application status across all schools and generate unified dashboard"
    - "Alert 7 days before any deadline (application, financial aid, housing)"
    - "Confirm receipt of recommendation letters and test scores at each school"
    - "Flag any missing requirements by school"
    - "Monitor for admission decisions and financial aid offers"
    - "Never submit applications, essays, or forms"
  expires: "2026-05-01"  # decision day
  revocable: true
```

**Today:** You have a spreadsheet. It's color-coded. It was accurate for approximately one week in October and has been a source of family tension ever since. Your kid swears they submitted the UPenn supplement. They did not submit the UPenn supplement.

**With APOA:** Your agent monitors every portal, tracks every deadline, confirms every submission, and generates a single dashboard that tells you exactly where things stand — without having to interrogate a teenager over dinner. Family dinners improve by approximately 40%.

---

## 🏗️ Home Renovation

**Traditional POA type:** Limited / Special Power of Attorney

You're renovating your kitchen. This means you now have relationships with a general contractor, a plumber, an electrician, a cabinet maker, a tile supplier, your city's permitting office, and a countertop fabricator who is apparently booked through 2028 but *might* have a cancellation.

Each one communicates through a different channel. Some use email. Some use text. One uses a portal you've never heard of. The permit office has a website that looks like it was designed as a punishment.

```yaml
authorization:
  type: "limited_special"
  principal: "Juan Doe"
  agent: "RenoTracker"
  services:
    - service: "buildertrend.com"
      scope: ["project:read", "schedule:read", "budget:read", "change_orders:read"]
      constraints:
        approve_changes: false
    - service: "permitportal.cityofsd.gov"
      scope: ["applications:read", "inspection_schedule:read", "status:read"]
    - service: "homedepot.com"
      scope: ["orders:read", "delivery_status:read"]
    - service: "gmail.com"
      scope: ["messages:read"]
      constraints:
        labels: ["renovation"]
        send: false
  rules:
    - "Track project timeline and alert me to any schedule slippage"
    - "Monitor permit application status and flag inspection dates"
    - "Track all material orders and delivery windows"
    - "Flag any change orders or budget overruns immediately"
    - "Generate weekly project status summary"
    - "Never approve change orders, make purchases, or respond to contractors"
  expires: "2026-09-01"  # estimated project completion
  revocable: true
```

**Today:** You have seventeen unread texts from your contractor, a permit inspection you forgot about, and two deliveries arriving on the same day that your plumber can't be there. The countertop fabricator has not called back. It has been eleven days. You are starting to understand why people move instead of renovate.

**With APOA:** Your agent tracks the project timeline, monitors every delivery and permit, flags budget overruns the moment they happen, and gives you a single weekly summary. You still won't hear from the countertop fabricator, but at least you'll know about everything else.

---

## 📄 Divorce Proceedings

**Traditional POA type:** Limited Power of Attorney / Litigation Support

Let's be honest about this one: divorce is a logistical nightmare wrapped in an emotional crisis. Even an amicable split involves dividing accounts, tracking court filings, monitoring compliance with temporary orders, managing shared expenses during separation, and keeping up with deadlines that carry real legal consequences if you miss them.

This is not a scenario where you want to be refreshing a court portal at midnight wondering if your ex's attorney filed something.

```yaml
authorization:
  type: "limited_litigation"
  principal: "Juan Doe"
  agent: "DivorceTracker"
  services:
    - service: "courts.ca.gov"
      scope: ["case:read", "filings:read", "deadlines:read", "hearing_schedule:read"]
    - service: "bankofamerica.com"
      scope: ["joint_accounts:read", "transactions:read"]
      constraints:
        individual_accounts: false  # joint accounts only
        transfers: false
    - service: "fidelity.com"
      scope: ["joint_accounts:read", "holdings:read"]
      constraints:
        individual_accounts: false
        trading: false
    - service: "gmail.com"
      scope: ["messages:read"]
      constraints:
        labels: ["divorce-legal"]
        send: false
  rules:
    - "Alert me immediately on any new court filing"
    - "Track all deadlines and flag 14 days before each"
    - "Monitor joint account transactions and flag anything unusual"
    - "Generate weekly summary of all case activity and financial changes"
    - "Flag any transaction that may violate temporary court orders"
    - "Never communicate with opposing counsel or the court"
    - "Never access individual (non-joint) accounts"
  expires: "2027-01-01"  # estimated finalization
  revocable: true
```

**Today:** You're checking the court portal every morning, monitoring shared bank accounts for unexpected withdrawals, and forwarding legal emails to your attorney while trying to maintain some semblance of a normal life. It is all-consuming in a way that nobody warns you about.

**With APOA:** Your agent monitors the filings, watches the joint accounts, tracks every deadline, and gives you a clean weekly summary. You and your attorney stay informed without the constant mental overhead of wondering what you might have missed. It won't make divorce easy — nothing does — but it removes the logistical anxiety from an already difficult time.

---

## Patterns Across These Examples

If you've read this far — first of all, thank you, and also, *are you okay?* — you may have noticed some patterns:

**Every scenario follows the same structure:**
1. A human grants bounded authority to an agent
2. The agent monitors multiple services that don't talk to each other
3. The agent surfaces what matters and ignores what doesn't
4. The agent *never* takes action without explicit human authorization for anything consequential

**The constraints are always the most important part.** What the agent *can't* do matters more than what it can. Every APOA authorization is defined as much by its boundaries as by its permissions. This is by design. It's the whole point.

**The expiration is never optional.** Every authorization has an end date. Some are event-driven (closing day, deployment end, decision day). Some are calendar-based. None are forever. Because "forever" is not a delegation strategy — it's an abdication.

**The principal always stays in control.** The agent watches, organizes, tracks, and alerts. The human decides, approves, signs, and commits. That's the deal. That's the whole deal.

---

<p align="center">
  🐴
  <br>
  <em><strong>Proxy</strong> doesn't make decisions for you. Proxy makes sure you don't miss the ones that matter.</em>
</p>
