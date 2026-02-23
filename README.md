# Azure SOC Lab

## Overview
Hands-on security operations lab simulating real-world attacks in Microsoft Azure and detecting them using Microsoft Sentinel and KQL (Kusto Query Language). All exercises were performed in a personal Azure tenant in the Australia East region.

## Environment
| Resource | Details |
|---|---|
| Azure Tenant | karenuongicloud.onmicrosoft.com |
| Region | Australia East |
| Log Analytics Workspace | SOC-Lab-Workspace |
| SIEM | Microsoft Sentinel (via Microsoft Defender Portal) |

## Test Accounts Used
| Account | Purpose |
|---|---|
| analyst@karenuongicloud.onmicrosoft.com | SOC analyst perspective |
| attacker@karenuongicloud.onmicrosoft.com | Simulated threat actor |
| testuser1-5@karenuongicloud.onmicrosoft.com | Target accounts for spray simulation |

## Labs Completed

### [Exercise A: Password Spray Attack Simulation & Detection](exercises/exercise-a-password-spray.md)
Simulated a password spray attack against multiple Azure AD accounts using PowerShell and the MSAL.PS module. Detected the attack using KQL in Log Analytics and configured an automated Sentinel analytics rule to generate incidents.

### [Exercise B: Privilege Escalation Detection](exercises/exercise-b-privilege-escalation.md)
Simulated a privilege escalation attack by assigning Global Administrator to a test attacker account. Detected both the escalation and subsequent role removal using AuditLogs in Log Analytics, demonstrating attacker cleanup behavior.

### [Exercise C: NSG Misconfiguration Analysis & Remediation](exercises/exercise-c-nsg-analysis.md)
Identified a critical network misconfiguration — RDP (port 3389) open to the entire internet (0.0.0.0/0). Remediated the issue by restricting access to a specific WAN IP and deployed Virtual Network flow logs to enable ongoing network traffic monitoring in Sentinel.

## Tools & Technologies
- Microsoft Azure / Entra ID
- Microsoft Sentinel
- Microsoft Defender Portal
- Log Analytics Workspace
- KQL (Kusto Query Language)
- PowerShell / MSAL.PS module
- Azure Network Watcher
- Microsoft Defender for Cloud

## Key Skills Demonstrated
- Threat simulation and attack pattern recognition
- KQL query writing for security detection
- Sentinel analytics rule configuration and incident management
- Identity and access management monitoring via AuditLogs
- Network security group analysis and remediation
- Cloud security log ingestion and pipeline configuration
