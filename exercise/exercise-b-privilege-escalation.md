# Exercise B: Privilege Escalation Detection

## Objective
Simulate a privilege escalation attack by assigning Global Administrator to a test attacker account, detect the escalation and subsequent role removal using AuditLogs in Log Analytics, and understand how attacker cleanup behavior appears in logs.

## What is Privilege Escalation?
Privilege escalation occurs when an attacker who has compromised a lower-privileged account elevates it to a higher privilege level — in this case, Global Administrator, the highest privilege role in Azure AD. Attackers use this to gain unrestricted access across the entire tenant. They often remove the role afterward to cover their tracks.

## Environment
- **Tenant:** karenuongicloud.onmicrosoft.com
- **Attacker account:** attacker@karenuongicloud.onmicrosoft.com
- **Role targeted:** Global Administrator
- **Detection platform:** Log Analytics (SOC-Lab-Workspace)

---

## Steps Taken

### 1. Assigned Global Administrator Role to Attacker Account
Navigated to **Entra ID → Roles and administrators → Global Administrator** and added `attacker@karenuongicloud.onmicrosoft.com` as an eligible member.

This action immediately generates an entry in AuditLogs with `OperationName: Add member to role`.

### 2. Detected the Escalation with KQL
Ran the following query in **Log Analytics (SOC-Lab-Workspace)**:

```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources contains "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources
```

**What this query does:**
- Filters AuditLogs specifically for role assignment events
- Narrows to Global Administrator role changes only
- Projects the three most critical investigation fields: when it happened, who did it, and who was affected

**Key fields in the results:**
| Field | Significance |
|---|---|
| TimeGenerated | When the escalation occurred — used to build attack timeline |
| InitiatedBy | The account that performed the action — in a real attack this would be the compromised account |
| TargetResources | Which user was assigned the role |

In a real incident, an unexpected `InitiatedBy` value (a regular user account, a service account, or activity outside business hours) is the primary red flag indicating a malicious escalation.

### 3. Removed the Role to Simulate Attacker Cleanup
Navigated back to **Entra ID → Roles and administrators → Global Administrator** and removed the `attacker` account from the role.

Attackers commonly perform this cleanup step after completing their objective to reduce visibility and avoid triggering prolonged alerts.

### 4. Detected the Role Removal with KQL
Ran the following query to capture the cleanup event:

```kql
AuditLogs
| where OperationName == "Remove member from role"
| project TimeGenerated, InitiatedBy, TargetResources
```

---

## Key Findings

| Finding | Detail |
|---|---|
| Escalation detected | Global Administrator assigned to attacker account |
| Cleanup detected | Role removed shortly after assignment |
| Detection method | AuditLogs OperationName filtering |
| Suspicious pattern | Escalation followed by de-escalation within a short window |

---

## Key Takeaways
- AuditLogs are the definitive paper trail for all administrative actions in Entra ID — every role change, user creation, and policy modification is logged
- The combination of an escalation event immediately followed by a de-escalation event is **more suspicious** than leaving the role assigned, because it indicates deliberate cleanup behavior
- In a real SOC investigation, these two events would be correlated with SigninLogs to build a full attack timeline — was there a suspicious login from an unusual location immediately before the escalation?
- `InitiatedBy` is the most critical field — monitoring for unexpected accounts performing privileged role assignments should be a baseline detection in any Azure environment
