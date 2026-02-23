# Exercise C: NSG Misconfiguration Analysis & Remediation

## Objective
Identify a critical network security group (NSG) misconfiguration on an Azure VM, remediate it using the principle of least privilege, and deploy Virtual Network flow logs to enable ongoing network traffic monitoring in Sentinel.

## What is an NSG Misconfiguration?
Network Security Groups act as Azure's built-in firewall for virtual machines. A critical misconfiguration occurs when administrative ports like RDP (3389) or SSH (22) are left open to the entire internet (`0.0.0.0/0`). Automated scanners discover open RDP and SSH ports within minutes of a VM being deployed, making this one of the most exploited misconfigurations in cloud environments.

## Environment
- **Tenant:** karenuongicloud.onmicrosoft.com
- **Region:** Australia East
- **Resource Group:** soc-lab-rg
- **Virtual Network:** vnet-australiaeast
- **Log Analytics Workspace:** SOC-Lab-Workspace

---

## Steps Taken

### 1. Identified the Misconfiguration
Navigated to **Virtual Machine → Networking → Inbound port rules** and reviewed all active NSG rules.

**Critical finding identified:**
| Port | Protocol | Source | Action | Severity |
|---|---|---|---|---|
| 3389 (RDP) | TCP | Any (0.0.0.0/0) | Allow | **Critical** |

RDP was open to the entire internet — any IP address in the world could attempt to connect to this VM. This is a critical misconfiguration that would be an immediate escalation in a real SOC environment.

### 2. Remediated the Misconfiguration
Rather than enabling Microsoft Defender for Cloud's Just-in-Time VM Access (which requires a paid Defender for Servers plan), the NSG rule was manually updated to implement the same principle:

**Steps taken:**
1. Navigated to **VM → Networking → Inbound port rules**
2. Clicked the RDP rule (port 3389)
3. Changed **Source** from `Any` to the specific WAN IP address of the authorized machine
4. Saved the rule

**Result after remediation:**
| Port | Protocol | Source | Action |
|---|---|---|---|
| 3389 (RDP) | TCP | [Authorized WAN IP] | Allow |

RDP is now only accessible from one specific IP address. The attack surface has been reduced from the entire internet to a single authorized machine.

**Note:** In a production environment, the recommended approach is **Just-in-Time VM Access** via Microsoft Defender for Cloud, which keeps the port closed by default and only opens it on-demand for a specific IP and time-limited window (e.g., 3 hours). This is superior to a static IP restriction because it eliminates standing access entirely.

### 3. Deployed Virtual Network Flow Logs
Configured flow logging to capture all network traffic data and send it to Log Analytics for Sentinel analysis.

**Navigation:** Portal → Network Watcher → Flow logs → Create

**Configuration:**
| Setting | Value |
|---|---|
| Flow Log Type | Virtual Network |
| Virtual Network | vnet-australiaeast |
| Storage Account | flowlogsstoragekong |
| Retention | 7 days |
| Flow Logs Version | Version 2 |
| Log Analytics | SOC-Lab-Workspace |
| Traffic Analytics | Disabled (cost management) |

Deployment completed successfully. Network traffic data from the VM's virtual network is now being captured and sent to SOC-Lab-Workspace where it can be queried in Sentinel.

**Note:** Traffic Analytics was disabled to manage lab costs. In a production SOC environment, enabling Traffic Analytics provides visual traffic maps and anomaly detection on top of raw flow log data, which significantly accelerates threat hunting.

---

## Key Findings

| Finding | Severity | Status |
|---|---|---|
| RDP (3389) open to 0.0.0.0/0 | Critical | Remediated |
| No network flow logging configured | Medium | Remediated |

---

## KQL Query for Flow Log Analysis
Once flow logs have been ingested into Log Analytics, the following query can be used to detect port scanning behavior:

```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
| summarize count() by SrcIP_s, DestPort_d
| order by count_ desc
```

---

## Key Takeaways
- Open RDP and SSH ports are among the most exploited misconfigurations in cloud environments — automated scanners find them within minutes of VM deployment
- The principle of least privilege applies to network rules just as it does to identity: only the minimum required access should be permitted, from only the required sources
- Just-in-Time VM Access is the gold standard for administrative port management in Azure, eliminating standing network access entirely
- Virtual Network flow logs provide the network visibility layer that Sentinel needs to detect lateral movement, port scanning, and data exfiltration at the network level
- Flow log retention periods (7-90 days) should align with organizational compliance requirements in production environments


## Lab Note
Virtual Network flow log data did not populate in Log Analytics or the storage account during this lab, which is a known limitation of trial Azure subscriptions. The flow log configuration was verified as correct:
- Status: Enabled
- Region: Australia East (matching VNet region)
- Version: 2
- Log Analytics workspace: SOC-Lab-Workspace
- Microsoft.Insights and Microsoft.Network resource providers: Registered

In a production environment with a paid subscription, flow log data would appear in Log Analytics within 60 minutes of configuration and could be 
queried using AzureNetworkAnalytics_CL.
