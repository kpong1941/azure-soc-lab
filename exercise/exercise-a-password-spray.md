# Exercise A: Password Spray Attack Simulation & Detection

## Objective
Simulate a password spray attack against Azure AD user accounts, detect it using KQL in Log Analytics, and configure an automated Sentinel analytics rule to generate incidents automatically.

## What is a Password Spray Attack?
A password spray attack tries one common password against many accounts rather than many passwords against one account. This technique evades account lockout policies that trigger after multiple failed attempts on a single account. It is one of the most common credential-based attacks in cloud environments.

## Environment
- **Tenant:** karenuongicloud.onmicrosoft.com
- **Target accounts:** testuser1 through testuser5
- **Tool used:** PowerShell with MSAL.PS module
- **Detection platform:** Microsoft Sentinel / Log Analytics (SOC-Lab-Workspace)

---

## Steps Taken

### 1. Created Test User Accounts
Created 5 test user accounts in Entra ID with weak passwords to serve as spray targets:
- testuser1@karenuongicloud.onmicrosoft.com
- testuser2@karenuongicloud.onmicrosoft.com
- testuser3@karenuongicloud.onmicrosoft.com
- testuser4@karenuongicloud.onmicrosoft.com
- testuser5@karenuongicloud.onmicrosoft.com

### 2. Simulated the Password Spray via PowerShell
Ran the following PowerShell script from a local machine to simulate the spray using intentionally wrong credentials:

```powershell
Install-Module -Name MSAL.PS -Force

$users = @(
  'testuser1@karenuongicloud.onmicrosoft.com',
  'testuser2@karenuongicloud.onmicrosoft.com',
  'testuser3@karenuongicloud.onmicrosoft.com',
  'testuser4@karenuongicloud.onmicrosoft.com',
  'testuser5@karenuongicloud.onmicrosoft.com'
)

foreach ($u in $users) {
  try {
    Get-MsalToken -ClientId '04b07795-8ddb-461a-bbee-02f9e1bf7b46' `
      -TenantId '<tenant-id>' `
      -UserCredential (New-Object PSCredential($u, (ConvertTo-SecureString 'WrongPass1' -AsPlainText -Force)))
  } catch { Write-Host "Failed: $u" }
}
```

**Expected output:**
```
Failed: testuser1@karenuongicloud.onmicrosoft.com
Failed: testuser2@karenuongicloud.onmicrosoft.com
Failed: testuser3@karenuongicloud.onmicrosoft.com
Failed: testuser4@karenuongicloud.onmicrosoft.com
Failed: testuser5@karenuongicloud.onmicrosoft.com
```

Each failure generates a `ResultType: 50126` (invalid credentials) entry in Entra ID SigninLogs.

### 3. Verified Failed Logins in Entra ID Sign-in Logs
Navigated to **Entra ID → Sign-in Logs** and filtered by **Status: Failure**. Observed a burst of failures from the same IP address, targeting multiple accounts within the same short timeframe — the hallmark pattern of a spray attack.

### 4. Detected the Attack with KQL
Ran the following query in **Log Analytics (SOC-Lab-Workspace)**:

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailedAttempts > 3
```

**What this query does:**
- `ResultType != 0` filters for all non-successful sign-in attempts
- `bin(TimeGenerated, 1h)` groups events into 1-hour windows
- `summarize` counts failures per user per hour
- `where FailedAttempts > 3` surfaces accounts that crossed the detection threshold

All 5 test users appeared in the results, each showing multiple failed attempts within the same 1-hour window.

### 5. Configured Automated Detection Rule in Sentinel
Navigated to **Microsoft Sentinel → Analytics → Rule Templates** and enabled the built-in rule:

> *"Password spray attack against Azure AD application"*

**Rule configuration:**
- Severity: Medium
- Query schedule: Every 1 hour
- Lookback window: Last 1 day
- Incident creation: Enabled

After enabling the rule and re-running the spray script, a **Sentinel incident was automatically created** in the Microsoft Defender portal under **Incidents & Alerts → Incidents**.

---

## Key Findings

| Finding | Detail |
|---|---|
| Attack type | Password spray (one password, many accounts) |
| Affected accounts | testuser1 through testuser5 |
| Detection method | SigninLogs ResultType 50126 clustered across accounts |
| Time to incident creation | ~30-45 minutes after spray (log ingestion + rule schedule) |

---

## Key Takeaways
- Password spray attacks are specifically designed to stay below per-account lockout thresholds — detecting them requires cross-account correlation, not single-account monitoring
- The clustered pattern (same timestamp, same IP, multiple accounts) is the primary detection signal
- Sentinel's built-in analytics rules provide production-ready detection without needing to write custom logic from scratch
- Log Analytics ingestion delay (~15-30 minutes) is an important operational consideration for real-time detection workflows
