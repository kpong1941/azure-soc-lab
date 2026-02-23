# KQL Detection Queries — Azure SOC Lab

All queries written and tested against SOC-Lab-Workspace (Log Analytics) in the karenuongicloud.onmicrosoft.com tenant.

---

## Exercise A: Password Spray Detection

### Basic Failed Login Detection
```kql
SigninLogs
| where ResultType != 0
| where TimeGenerated > ago(1h)
| project TimeGenerated, UserPrincipalName, ResultType, IPAddress
```

### Password Spray Pattern Detection
Surfaces accounts with more than 3 failed attempts within a 1-hour window:
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailedAttempts > 3
```

### Spray Summary by User and Source IP
```kql
SigninLogs
| where ResultType != 0
| where TimeGenerated > ago(1h)
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| order by FailedAttempts desc
```

---

## Exercise B: Privilege Escalation Detection

### Detect Global Administrator Role Assignment
```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources contains "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources
```

### Detect Role Removal (Attacker Cleanup)
```kql
AuditLogs
| where OperationName == "Remove member from role"
| project TimeGenerated, InitiatedBy, TargetResources
```

### Detect All Privileged Role Changes
```kql
AuditLogs
| where OperationName in ("Add member to role", "Remove member from role")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

---

## Exercise C: Network Flow Log Analysis

### Detect Malicious Flow Traffic
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
| summarize count() by SrcIP_s, DestPort_d
| order by count_ desc
```

### Check All Recent Audit Activity
```kql
AuditLogs
| where TimeGenerated > ago(1h)
| take 10
```
