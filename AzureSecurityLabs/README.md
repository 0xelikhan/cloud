# Azure Security Portfolio

---

## Table of Contents

- [Project 1 - Zero-Trust Fortress](#project-1--zero-trust-fortress)
- [Project 2 - Detection Engineering](#project-2--detection-engineering)
- [Project 3 - Multi-Cloud Threat Detection (AWS + Sentinel)](#project-3--multi-cloud-threat-detection-aws--sentinel)
- [Project 4 - Security Automation (SOAR)](#project-4--security-automation-soar)
- [Project 5 - Threat Hunting](#project-5--threat-hunting)
- [Project 6 - Sentinel Workbooks & Dashboards](#project-6--sentinel-workbooks--dashboards)
- [Project 7 - Azure Security Workshop (N-Tier Labs)](#project-7--azure-security-workshop-n-tier-labs)

---

## Architecture

Built this in three phases, each one locking down a different layer. Phase 1 stands up the network and resources with zero public exposure. Phase 2 adds Bastion for management and a firewall for egress control. Phase 3 wires up Sentinel, detection rules, and a Logic App that automatically blocks attacker IPs.

Every connection authenticates through Azure RBAC and Managed Identity.

```
                    ┌─────────────────────────────────────────────┐
                    │           spoke-prod-vnet (10.20.0.0/16)    │
                    │                                             │
                    │  ┌─────────────┐  ┌──────────────────────┐  │
                    │  │ web-subnet  │  │ db-subnet            │  │
                    │  │ web-vm-01   │  │ SQL Private Endpoint  │  │
 hub-vnet           │  │ (no pub IP) │  └──────────────────────┘  │
 (10.10.0.0/16)     │  └──────┬──────┘  ┌──────────────────────┐  │
 ┌───────────┐      │         │         │ pe-subnet            │  │
 │ Bastion   │◄─────┤  VNet   │         │ KV Private Endpoint  │  │
 │ Firewall  │ Peer │  Peer   │         └──────────────────────┘  │
 └───────────┘      │         │                                   │
                    └─────────┼───────────────────────────────────┘
                              │
                    Managed Identity ──► Key Vault ──► SQL Database
```

### How the credential flow actually works

This is the part I'm most proud of because there are zero passwords anywhere in the code or config:

1. The VM hits the IMDS endpoint at `169.254.169.254/metadata/identity/oauth2/token` with `resource=https://vault.azure.net` and `api-version=2018-02-01`. IMDS hands back a JWT with the VM's Managed Identity `oid` as the subject, audience set to `https://vault.azure.net`, TTL of about 24 hours. It caches the token so subsequent calls don't roundtrip to Entra ID.

2. The VM presents that token to Key Vault's data plane at `https://core-security-kv.vault.azure.net/secrets/sql-database-password?api-version=7.4`. DNS for the vault's FQDN hits the Private DNS Zone `privatelink.vaultcore.azure.net`, which returns the Private Endpoint's NIC IP (`10.20.3.x`) instead of the public VIP. The request never touches the public internet.

3. Key Vault checks the token against Azure RBAC. The evaluation chain goes: explicit deny assignments at any scope → role assignments from narrowest scope outward (resource → resource group → subscription → management group). The `Key Vault Secrets User` role grants exactly one data action: `Microsoft.KeyVault/vaults/secrets/getSecret/action`. That's it. Can't list, can't write, can't delete. Authorization passes, secret comes back.

4. The VM opens a TDS connection to SQL Database through the Private Endpoint in `db-subnet`. DNS for `core-security-server.database.windows.net` resolves through `privatelink.database.windows.net` to `10.20.2.x`. Authenticates with the retrieved `sqladmin` credential over the encrypted TDS channel.


---

# Project 1 - Zero-Trust Fortress

## Phase 1: Secure Foundation

### The Network

Two VNets, peered together. Hub-spoke pattern.

**Hub (`hub-vnet`, 10.10.0.0/16):** Contains `AzureFirewallSubnet` (10.10.1.0/26) and `AzureBastionSubnet` (10.10.2.0/26). Both names are required exactly as-is by the Azure resource providers. `/26` is the minimum supported prefix for both.

I left Bastion, DDoS, and Firewall disabled during VNet creation and deployed them manually in Phase 2. The portal's integrated deployment bundles default to Standard SKUs, and I wasn't about to burn $400/month on a lab firewall when Basic does the job.

**Spoke (`spoke-prod-vnet`, 10.20.0.0/16):** Three /24 subnets:

| Subnet | CIDR | What goes here |
|--------|------|---------------|
| `web-subnet` | 10.20.1.0/24 | The VM. 251 usable IPs (Azure reserves 5 per subnet: .0 network, .1 gateway, .2-.3 DNS, .255 broadcast) |
| `db-subnet` | 10.20.2.0/24 | SQL Database Private Endpoint NIC |
| `pe-subnet` | 10.20.3.0/24 | Key Vault Private Endpoint NIC |

I put the Private Endpoints in their own subnets so I could apply NSGs per-subnet if needed. Worth noting: NSG rules don't apply to Private Endpoint traffic by default because the `PrivateEndpointNetworkPolicies` property is set to `Disabled`. You have to explicitly flip it to `NetworkSecurityGroupEnabled` at the subnet level if you want micro-segmentation.

**Peering:** Bidirectional links (`hub-to-spoke-peering` and `spoke-to-hub-peering`). Some things worth understanding about how peering works:

- It's non-transitive. If I peered a third VNet to the hub, it wouldn't automatically see the spoke. Each relationship is independent.
- Traffic stays on the Microsoft backbone. No public internet traversal, no encryption overhead. Sub-millisecond latency in the same region.
- After peering, each VNet's effective route table gets the peer's address space with next hop `VNetPeering`. These system routes beat any UDR with a less-specific prefix, which matters in Phase 2 when I add forced tunneling.
- Gateway transit isn't enabled here, but if the hub had a VPN Gateway, setting `AllowGatewayTransit` on the hub side and `UseRemoteGateways` on the spoke side would let spoke resources reach on-prem through the hub's gateway.

---

### The VM (web-vm-01)

Deployed into `web-subnet` with no public IP, no public inbound ports, and no boot diagnostics:

| Parameter | Value | Why |
|-----------|-------|-----|
| Image | Ubuntu Server 22.04 LTS Gen2 | Current LTS at deployment time. 24.04 and 26.04 LTS are now on the Marketplace |
| Size | `Standard_B1s` | 1 vCPU, 1 GiB. Burstable, accrues credits when idle, spends them under load. Fine for a lab |
| Public IP | **None** | No IPv4 or IPv6. NIC only has a private IP from the `web-subnet` DHCP range |
| Inbound ports | **None** | NSG with no inbound allow rules. Default deny; nothing is reachable |
| OS disk | Standard SSD (LRS) | Delete-with-VM enabled so I don't get billed for orphaned disks |
| Auto-shutdown | 00:00 UTC | Deallocates nightly, compute billing stops |

The VM is invisible to the internet. Before Bastion goes up in Phase 2, there's literally no way to reach it from outside.

---

### The Database (web-db-01)

General Purpose Serverless tier, Gen5, max 1 vCore, min 0.5, auto-pause after 60 minutes of inactivity. Billing is per-second based on `max(configured_min_vCores, actual_vCores_used)`. When it's paused, compute billing is zero and I only pay for storage. When a connection comes in, it auto-resumes with about 30-60 seconds of cold start.

The Private Endpoint (`web-db-01-pe`) gets a managed NIC injected into `db-subnet` by the Private Link resource provider. The NIC isn't directly editable. A Private DNS Zone (`privatelink.database.windows.net`) is auto-created and linked to the VNet with an A record pointing `core-security-server.database.windows.net` to the private IP. Public network access is disabled on the SQL Server, so anything trying to connect from outside the VNet gets a connection-refused.

---

### The Key Vault (core-security-kv)

Configured with the **Azure RBAC** permission model, which is now the default for new vaults since API version 2026-02-01. Vault access policies are the legacy model. Purge protection disabled (it's a lab), soft-delete at 7 days, public access disabled.

Same Private Endpoint pattern as the database: managed NIC in `pe-subnet`, Private DNS Zone `privatelink.vaultcore.azure.net`, FQDN resolves to `10.20.3.x` for anything inside the VNet.

---

### The Lockout

After deploying the Key Vault, I went to the Secrets blade and got hit with **HTTP 403: "You are unauthorized to view these contents."**

This is the RBAC model doing its job. Nobody has data plane access until you explicitly create a role assignment. Two layers had to be fixed:

**Identity:** Assigned myself `Key Vault Secrets Officer` (get, list, set, delete on secrets) at vault scope. Waited about 60 seconds for RBAC propagation.

**Network:** Even with a valid token, the vault rejected me because public access was disabled and I wasn't coming from a Private Endpoint. So I temporarily switched to `Selected networks`, added my client IP with a `/32` mask, and waited about 2 minutes for the firewall rule to propagate.

Both layers have to pass. Valid token + unauthorized network = denied. Authorized network + invalid token = denied. That's defense in depth, and seeing it enforce against myself was proof the Zero-Trust model is actually working.

After adding the `sql-database-password` secret, I immediately flipped public access back to `Disabled`. The vault is only reachable through its Private Endpoint from here on out.

---

### Managed Identity

Enabled a System-Assigned Managed Identity on `web-vm-01`. Azure creates a service principal in the tenant's Entra ID directory (formerly Azure AD) tied to the VM's lifecycle. If I delete the VM, the identity gets cleaned up automatically. The credentials are an X.509 certificate managed and rotated by the platform. Nothing is exposed to the OS.

Assigned the `Key Vault Secrets User` role at vault scope. This role has a single data action:
```
Microsoft.KeyVault/vaults/secrets/getSecret/action
```
No `listSecrets`, no write, no delete, no access to keys or certificates. Minimum permission needed for the credential retrieval pattern.

---

## Phase 2: Centralized Fortress

Phase 2 adds two things: a way in (Bastion) and a way to control what goes out (Firewall with forced tunneling).

```
BEFORE:  [web-vm-01] ──► Azure default SNAT ──► Internet  (no inspection)

AFTER:   [web-vm-01] ──► UDR 0.0.0.0/0 ──► Azure Firewall (10.10.1.4) ──► Internet
                                                    │
                                              no rules = no egress
```

The private flows (VM → Key Vault PE, VM → SQL PE) aren't affected by the UDR. Azure route selection uses longest-prefix match. VNet-local routes (`10.20.0.0/16`) and peered routes (`10.10.0.0/16`) are more specific than `0.0.0.0/0` and always win. Private Endpoint traffic stays on the VNet fabric.

---

### Bastion

Went with the **Basic** SKU. Bastion has four tiers now:

| SKU | Infrastructure | Instances | What you get |
|-----|---------------|-----------|-------------|
| Developer | Shared (free) | Shared | Single VM at a time, no VNet Peering, no dedicated subnet |
| Basic | Dedicated | 2 (fixed) | Browser-based RDP/SSH, VNet Peering, dedicated subnet |
| Standard | Dedicated | 2-50 | Basic + native client, shareable links, IP-based connect, file transfer |
| Premium | Dedicated | 2-50 | Standard + session recording, private-only deployment (no public IP) |

I picked Basic because it's the cheapest dedicated SKU that supports VNet Peering, which I need for hub-to-spoke connectivity. Developer doesn't support peering so it was out. Standard and Premium charge more per hour and I didn't need native client or session recording for this.

Connection path: browser → TLS/443 → Bastion public IP → `AzureBastionSubnet` → VNet Peering → `web-subnet` → VM port 22 (internal only).

---

### Firewall

The Basic SKU needs two subnets: `AzureFirewallSubnet` for the data plane and `AzureFirewallManagementSubnet` (10.10.3.0/26) for Azure's internal control plane traffic. Had to add the management subnet before deploying.

Basic gives 250 Mbps, which is plenty for a lab. Standard does L3-L7 with threat intelligence at 30 Gbps. Premium adds TLS inspection and IDPS at 100 Gbps. Two public IPs: `hub-firewall-ip` for data plane SNAT/DNAT and `hub-firewall-mgmt-ip` for management (Basic-only requirement).

One thing that matters for Phase 3: Azure Firewall evaluates rules in this order: DNAT → Network → Application, and within each category by ascending priority. A Network rule deny at priority 100 kills the packet before Application rules at priority 200 ever get a look. This is how the automated IP blocking works later.

---

### Forced Tunneling

Created a route table with one route: destination `0.0.0.0/0`, next hop `Virtual appliance`, next hop address `10.10.1.4` (the firewall's private IP). Associated it with `web-subnet`. The UDR overrides the system default route for internet-bound traffic. The firewall receives every packet, checks it against the policy's rule collections, and either forwards (allow match) or drops (default deny).

To verify, I connected via Bastion and ran `curl -m 10 https://www.google.com`. Timed out. The firewall has no allow rules, so everything is dropped. 

---

## Phase 3: Automated SOC

I wired up Sentinel as the SIEM, created a KQL detection rule, and built a Logic App that automatically extracts attacker IPs from incidents and adds them to a firewall blocklist. About 2-3 minutes from alert to block.

### Sentinel + Data Connectors

Provisioned Log Analytics Workspace `hub-sentinel-law`, enabled Sentinel on top of it. Connected two data sources:

**Defender for Cloud:** Ingests `SecurityAlert` records from Defender for Servers, Defender for SQL, etc. Used the subscription-based (legacy) connector via Content Hub.

**Azure Firewall:** Set up diagnostic settings on `hub-firewall` to stream `AZFWNetworkRule` logs to the workspace. Every log entry has source/dest IP, port, protocol, and the action taken (Allow/Deny), so I get full egress visibility in KQL.

---

### The Blocking Mechanism

Created an IP Group (`suspect-ip-group`) and a Network Rule Collection on the firewall policy:

| Collection | Priority | Action | Rule | Source | Dest | Ports |
|-----------|----------|--------|------|--------|------|-------|
| `block-attacker-collection` | **100** | **Deny** | `deny-suspect-group` | IP Group: `suspect-ip-group` | `*` | `*` |

Priority 100 means this evaluates before any allow rules (which start at 200+). And because Network rules run before Application rules in the firewall pipeline, any IP in the group gets blocked at the network layer no matter what.

---

### The Logic App

`sentinel-block-ip-playbook`, Consumption plan, System-Assigned Managed Identity with `Contributor` on the IP Group resource (needs `Microsoft.Network/ipGroups/write` for the PUT call).

```
1. Trigger: Sentinel incident creation
   ├── receives the full incident payload including entity arrays
   │
2. Extract IP entities from the incident's entity bag
   │
3. HTTP GET to Azure Management API, read current suspect-ip-group
   ├── URI: https://management.azure.com/subscriptions/{subId}/resourceGroups/
   │        core-security-rg/providers/Microsoft.Network/ipGroups/
   │        suspect-ip-group?api-version=2022-01-01
   ├── Auth: Managed Identity (audience: https://management.azure.com/)
   ├── returns current ipAddresses[] array
   │
4. Parse JSON, pull out properties.ipAddresses
   │
5. Send email alert (outside the loop)
   ├── Subject: "SENTINEL ALERT: Incident Detected!"
   │
6. For each IP:
   └── HTTP PUT, add the IP to suspect-ip-group
       ├── Auth: Managed Identity
       └── body includes the IP in the ipAddresses array
```

The runtime handles token acquisition, caching, and refresh automatically through the Managed Identity. The HTTP action specifies `Authentication: Managed Identity` with audience `https://management.azure.com/`, and the runtime handles the IMDS-equivalent token flow. No client secrets or certificates stored anywhere in the workflow.

---

### Detection Rule + Validation

Sentinel scheduled analytics rule:

| Parameter | Value |
|-----------|-------|
| Frequency | Every 5 minutes |
| Lookback | 1 hour |
| Trigger threshold | > 0 results |
| Alert grouping | Single incident |
| Automated response | `sentinel-block-ip-playbook` |

```kusto
SecurityAlert
| where TimeGenerated > ago(1h)
| where DisplayName contains "Brute force"
```

To test, I connected via Bastion and ran:
```bash
for i in {1..100}; do echo "wrongpassword" | su - nonexistantuser; done
```

Defender for Cloud picked up the brute-force pattern → `SecurityAlert` generated → Sentinel rule matched → incident created → Logic App fired → IP written to `suspect-ip-group` → firewall deny rule kicked in → email landed in my inbox. About 2-3 minutes from alert to block.

---

# Project 2 - Detection Engineering

Sentinel analytics rules query Log Analytics tables (`Event`, `SecurityAlert`, `AuditLogs`, `SigninLogs`, `AWSCloudTrail`). MDE custom detection rules query the Defender data store (`DeviceProcessEvents`, `DeviceLogonEvents`, etc.). Different backends, different rule types. AWS CloudTrail data only exists in the Sentinel workspace, so those detections have to be Sentinel analytics rules.

---

## RDP Brute Force Detection

| | |
|---|---|
| **MITRE** | TA0006 → T1110 |
| **Source** | `Event` table, EventID 4625, collected via AMA |
| **Rule** | Sentinel scheduled, 5-min frequency, 5-min lookback |
| **Threshold** | ≥5 failed logons from one IP in a 5-minute `bin()` |

```kql
Event
| where EventLog == "Security"
| where EventID == 4625
| extend ParamList = extract_all(@'<Param>(.*?)</Param>', tostring(ParameterXml))
| extend
    TargetUser   = tostring(ParamList[5]),
    LogonType    = tostring(ParamList[10]),
    Workstation  = tostring(ParamList[13]),
    SourceIp     = tostring(ParamList[18])
| where LogonType in ("3", "10")  // 3=Network, 10=RDP
| where SourceIp != "0.0.0.0" and SourceIp != ""
| summarize FailedCount = count()
    by SourceIp, TargetUser, Computer, bin(TimeGenerated, 5m)
| where FailedCount >= 5
```

AMA-collected 4625 events store fields inside `ParameterXml` as ordered `<Param>` elements, not named key-value pairs. The `extract_all` regex returns a zero-indexed array; positions 5, 10, 13, 18 correspond to TargetUserName, LogonType, WorkstationName, and IpAddress respectively. I picked a 5-minute bin because it's tight enough to catch automated attacks but wide enough to group manual attempts. Threshold of 5 filters out the usual mistyped-password noise (1-3 attempts) without missing scripted attacks.

**Investigation queries I use with this:**

```kql
// Who's hitting us the most
Event | where EventID == 4625
| summarize FailureCount = count() by SourceIp
| sort by FailureCount desc

// Did they get in after the failures?
Event | where EventID == 4624
| where SourceIp == "<attacker-ip>"
| project TimeGenerated, TargetUser, LogonType, Computer
```

**Test results:** 11 failed attempts in 5 minutes from a single IP. LogonType 10 confirmed RDP. No subsequent 4624. Incident created with correct entity mapping (IP, Account, Host).

---

## Suspicious PowerShell Downloader

| | |
|---|---|
| **MITRE** | TA0002 → T1059.001, also T1105 and T1027 |
| **Source** | `Event` table, EventID 4688 with command-line auditing enabled |

```kql
Event
| where EventLog == "Security"
| where EventID == 4688
| extend NewProcessName =
    extract(@"New Process Name:\s*([^\r\n]+)", 1, RenderedDescription),
         ProcessCommandLine =
    extract(@"Process Command Line:\s*([^\r\n]*)", 1, RenderedDescription)
| extend NewProcessNameLower = tolower(NewProcessName),
         CmdLower            = tolower(ProcessCommandLine)
| where NewProcessNameLower has @"\powershell.exe"
| where CmdLower has_any (
    "http://", "https://",
    "invoke-webrequest", "iwr",
    "downloadstring", "downloadfile",
    "new-object net.webclient",
    "start-bitstransfer", "bitsadmin",
    "frombase64string", "-encodedcommand",
    "iex "
)
| project TimeGenerated, Computer, NewProcessName, ProcessCommandLine
| order by TimeGenerated desc
```

Unlike MDE's `DeviceProcessEvents` which gives you `FileName` and `ProcessCommandLine` as proper columns, AMA-collected 4688 events bury everything in `RenderedDescription` as freetext. The `extract` calls parse out the process name and command line with regex. I used `has_any` instead of `contains` because `has` does word-boundary matching, which cuts false positives from legitimate paths that happen to contain the keywords.

**When this fires, the investigation path is:**

1. Check the parent process. `cmd.exe` → `powershell.exe` is probably interactive or a scheduled task. `wmiprvse.exe` → `powershell.exe` points to WMI lateral movement. `w3wp.exe` → `powershell.exe` is a web shell.
2. Search for the payload: `search "payload.ps1"` across all tables.
3. If Sysmon Event ID 3 or NSG flow logs exist, correlate the outbound connection to the URL in the command line.
4. Check if the executing user is privileged.

**Containment:** Kill the process tree, isolate the host via MDE or NSG, block the C2 at the firewall, revoke the user's sessions via Graph `revokeSignInSessions`, deploy Constrained Language Mode or WDAC policy.

---

## MDE Custom Detection Rules

Onboarded 3 devices into Defender for Endpoint (Windows 11 workstation, Server 2022 DC, physical laptop). 

One thing that tripped me up: MDE requires explicit provisioning through the Defender portal under Assets → Devices. Having an E5 license isn't enough. Device telemetry takes 1-4 hours to populate `DeviceProcessEvents` after onboarding, and full historical backfill takes about 24 hours.

### Encoded PowerShell (T1059.001 - High)

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "FromBase64String")
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, ReportId
```
Tested on ws01.corp.local, incident created with correct entity mapping. ✅

### Credential Dumping (T1003 - High)

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where (FileName in~ ("mimikatz.exe", "procdump.exe", "procdump64.exe")
    or ProcessCommandLine has_any ("sekurlsa", "lsadump", "lsass.exe", "lsass.dmp"))
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, ReportId
```

### PsExec Lateral Movement (T1021.002 - High)

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("psexec.exe", "psexec64.exe", "paexec.exe")
    or ProcessCommandLine has_any ("psexec", "\\\\", "-accepteula")
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, ReportId
```

### Registry Run Key Persistence (T1547.001 - Medium)

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "CurrentVersion\\Run"
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, ReportId
```
Added a test Run key on ws01.corp.local. Detection fired. ✅

### Network Recon via net.exe (T1087 - Medium)

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_any ("user", "group", "localgroup", "share", "view")
| summarize CommandCount = count(), Commands = make_set(ProcessCommandLine)
    by DeviceName, DeviceId, AccountName, bin(Timestamp, 5m)
| where CommandCount >= 3
| project Timestamp, DeviceName, DeviceId, AccountName, CommandCount, Commands
```
Ran 4 `net` commands in 5 minutes on the workstation. Incident showed the correlated pattern with `make_set` collecting the distinct command lines into a JSON array. 

---

## Entra ID Detections

### Privileged Role Assignment (T1098.003 - High)

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName == "Add member to role"
| where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = trim('"', tostring(TargetResources[0].modifiedProperties[1].newValue))
| extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| where RoleName in ("Global Administrator", "Security Administrator",
    "User Administrator", "Privileged Role Administrator", "Application Administrator")
| project TimeGenerated, TargetUser, RoleName, AssignedBy, SourceIP, Result
```
The `modifiedProperties[1].newValue` field wraps the role name in quotes, so `trim('"', ...)` strips them for clean filtering. These five roles are the highest-privilege directory roles. Any one of them getting assigned should trigger investigation.

### Bulk Account Provisioning (T1136.003 - Medium/High)

```kql
AuditLogs
| where OperationName == "Add user" | where Result == "success"
| extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend CreatedUser = tostring(TargetResources[0].userPrincipalName)
| summarize
    UserCount = count(), CreatedUsers = make_list(CreatedUser),
    UniqueIPs = dcount(SourceIP), SourceIPs = make_set(SourceIP)
    by CreatedBy, bin(TimeGenerated, 10m)
| where UserCount >= 3 or UniqueIPs >= 2
| extend Severity = iff(UniqueIPs >= 2, "High", "Medium")
```
If accounts are being created from multiple source IPs, that's either compromised automation or distributed access, so it escalates to High. `dcount()` uses HyperLogLog for approximate distinct count, which is fast and memory-efficient.

### Rapid Account Modification (T1098 - Medium/High)

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName has_any ("Update user", "Reset password",
    "Add member to role", "Remove member from role")
| where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| summarize ChangeCount = count(), Operations = make_set(OperationName),
    UniqueIPs = dcount(tostring(InitiatedBy.user.ipAddress))
    by TargetUser, Actor, bin(TimeGenerated, 10m)
| where ChangeCount >= 2
| extend ThreatLevel = case(ChangeCount >= 5, "High", UniqueIPs >= 2, "High", "Medium")
```

---

## ASIM and UEBA

### Multi-Source Brute Force via ASIM (T1110)

```kql
_Im_Authentication
| where TimeGenerated > ago(1h)
| where EventResult == "Failure"
| summarize FailureCount = count(), SourceIPs = make_set(SrcIpAddr)
    by TargetUsername, DvcHostname
| where FailureCount >= 5
```

The `_Im_Authentication` parser normalizes across every authentication source in the workspace. `TargetUsername` maps from Windows `TargetUserName`, Entra `UserPrincipalName`, and Defender for Identity `AccountName`. `EventResult` normalizes from Win32 NTSTATUS codes, Entra `ResultType`, etc. into `Success`/`Failure`. If I add a new data connector next week, the query just works without changes.

### UEBA High Priority (ML-based)

```kql
BehaviorAnalytics
| where TimeGenerated > ago(1h)
| where InvestigationPriority > 7
| where ActivityInsights has "True"
| project TimeGenerated, UserPrincipalName, InvestigationPriority, ActivityType, ActivityInsights
```

`InvestigationPriority` comes from Sentinel's UEBA ML models looking at login geography, resource access patterns, time-of-day deviations, and peer-group baselines. Score 7+ means statistically significant deviation. This catches the stuff that signature-based rules miss: insider threats, compromised accounts doing things that look normal individually but are anomalous for that specific user.

---

# Project 3 - Multi-Cloud Threat Detection (AWS + Sentinel)

Integrated AWS CloudTrail with Sentinel and built 4 detection rules targeting AWS-specific attack patterns plus a cross-cloud correlation rule that joins AWS and Azure telemetry.

### Pipeline

```
CloudTrail ──► S3 ──► S3 Event Notification ──► SQS (us-east-2)
                                                     │
                                           Sentinel polls every 5-10 min
                                                     │
                                                     ▼
                                           AWSCloudTrail table (Log Analytics)
```

Sentinel authenticates to AWS via `sts:AssumeRole` with an `ExternalId`. The `ExternalId` prevents confused-deputy attacks by ensuring only my specific Sentinel workspace can assume the role. The IAM trust policy restricts the principal to Sentinel's Azure-side service identity.

End-to-end latency is about 20-30 minutes (CloudTrail to S3: 5-15 min, S3 notification to SQS: instant, Sentinel poll: 5-10 min). Total cost: about $2-3/month.

---

### Detection 1: Rapid IAM Privilege Escalation (T1098 - High)

```kql
let PrivilegeChangeEvents = dynamic([
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreatePolicyVersion", "AddUserToGroup", "CreateUser",
    "DetachUserPolicy", "DetachRolePolicy", "DeleteUser"
]);
AWSCloudTrail
| where EventSource == "iam.amazonaws.com"
| where EventName in (PrivilegeChangeEvents)
| where isempty(ErrorCode)
| summarize ChangeCount = count(), ActionsPerformed = make_set(EventName)
    by UserIdentityArn, SourceIpAddress, bin(TimeGenerated, 5m)
| where ChangeCount >= 3
```

Individual IAM policy attachments happen all the time. Three or more in 5 minutes looks like an automated post-compromise privilege escalation script (Pacu, enumerate-iam, etc.). The `isempty(ErrorCode)` filter keeps it to successful API calls only. An attacker getting AccessDenied repeatedly is a different pattern (permission probing) that needs a different rule.

Tested by creating a user and attaching 3 policies in quick succession. ChangeCount=4.

---

### Detection 2: Cryptojacking GPU Launch (T1496 - High)

```kql
let CryptoMiningInstanceTypes = dynamic([
    "p3.", "p4.", "p4d.", "p5.",
    "g4dn.", "g4ad.", "g5.", "g5g.", "g6.",
    "dl1.", "inf1.", "inf2.", "trn1."
]);
AWSCloudTrail
| where EventSource == "ec2.amazonaws.com"
| where EventName == "RunInstances"
| where isempty(ErrorCode)
| extend InstanceType = tostring(parse_json(RequestParameters).instanceType)
| where InstanceType has_any (CryptoMiningInstanceTypes)
| project TimeGenerated, UserIdentityArn, SourceIpAddress, InstanceType, AWSRegion
```

Single-event threshold. GPU instances have basically zero legitimate base rate in most orgs. A `p3.16xlarge` runs about $24/hr and attackers spin up dozens across multiple regions as soon as they get credentials.

---

### Detection 3: S3 Public Access Removal (T1530 - High)

```kql
AWSCloudTrail
| where EventSource == "s3.amazonaws.com"
| where EventName in ("PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
    "PutBucketAcl", "PutBucketPolicy", "PutBucketCors")
| where isempty(ErrorCode)
| extend BucketName = tostring(parse_json(RequestParameters).bucketName)
| extend PublicAccessConfig = parse_json(RequestParameters).PublicAccessBlockConfiguration
| extend BlockPublicAcls = tostring(PublicAccessConfig.BlockPublicAcls)
| extend BlockPublicPolicy = tostring(PublicAccessConfig.BlockPublicPolicy)
| where BlockPublicAcls == "false" or BlockPublicPolicy == "false"
    or EventName in ("PutBucketAcl", "PutBucketPolicy", "DeleteBucketPublicAccessBlock")
```

Only fires when protections are being turned *off* (booleans set to `false`). Re-enablement events get filtered out.

This one taught me something: CloudTrail logs the event as `PutBucketPublicAccessBlock`, not `PutPublicAccessBlock` like some of the AWS docs reference. I spent a while wondering why my rule wasn't matching before I checked the actual CloudTrail data. Always validate event names against live logs.

---

### Detection 4: Cross-Cloud Correlation (T1078 - High)

This is the one I'm most proud of from this project. It joins suspicious AWS write operations with failed Entra ID sign-ins from the same source IP within a 1-hour window.

```kql
let timewindow = 1h;
let SuspiciousAWSEvents = dynamic(["AttachUserPolicy", "AttachRolePolicy", "CreateUser",
    "RunInstances", "PutBucketPublicAccessBlock", "CreateAccessKey"]);
let AWSSuspicious =
    AWSCloudTrail | where TimeGenerated > ago(timewindow)
    | where EventName in (SuspiciousAWSEvents) | where isempty(ErrorCode)
    | summarize AWSEventCount = count(), AWSActions = make_set(EventName, 10)
        by SourceIpAddress;
let AzureFailedLogins =
    SigninLogs | where TimeGenerated > ago(timewindow) | where ResultType != "0"
    | summarize FailedLoginCount = count(), TargetedUsers = make_set(UserPrincipalName, 5)
        by IPAddress;
AWSSuspicious
| join kind=inner AzureFailedLogins on $left.SourceIpAddress == $right.IPAddress
```

Most SOCs monitor each cloud in isolation. If someone's doing suspicious stuff in AWS and also brute-forcing Azure sign-ins from the same IP, those are two separate low-severity events in siloed dashboards but one high-severity event when correlated.

`let` subqueries stage the data before the join. `kind=inner` returns only IPs that show up in both datasets. `make_set(EventName, 10)` caps at 10 elements to keep memory reasonable. `$left/$right` handles the column name mismatch between CloudTrail's `SourceIpAddress` and SigninLogs' `IPAddress`.

### Slack Notification

Built a Logic App that posts to Slack when incidents are created. One gotcha: the alert description isn't at the incident level in the trigger payload. It's nested inside `object.properties.alerts[0].properties.description`. Timestamps get converted from UTC to Eastern with `convertTimeZone()` and `formatDateTime()`. Notifications land within about 2 minutes. ✅

### CSPM

Connected Defender for Cloud to AWS via CloudFormation StackSet. Pulled 272 recommendations, 2 High severity including "Eliminate root user for daily tasks." CSPM (foundational tier, free) checks configuration. CWP (Defender plans, paid) does runtime threat detection.

---

# Project 4 - Security Automation (SOAR)

4 Logic App playbookn, all running on System-Assigned Managed Identity.

| Playbook | Trigger | What it does | Auth |
|----------|---------|-------------|------|
| Auto-Comment-Incident | Automatic | Stamps every new incident with structured triage info (title, severity, timestamp, entities) | Sentinel Responder |
| Revoke-User-Sign-In | Manual | Loops through account entities, calls Graph `revokeSignInSessions` on each, tags incident `ContainmentActive` | Graph `User.ReadWrite.All` |
| Notify-High-Severity | Automatic | Emails the team for High-severity incidents with metadata, entities, and a direct portal link | Office 365 connector |
| Block-EntraIDUser | Manual | Sets `accountEnabled=false` via Graph for each account entity. Deployed from Content Hub. | Graph `User.ReadWrite.All` |

I made `Revoke-User-Sign-In` the default containment action instead of full account disable. Revoking sessions kills all refresh and access tokens within about 5 minutes (Azure's revocation SLA) but keeps the account's group memberships, role assignments, and audit trail intact for investigation. `Block-EntraIDUser` is the escalation for confirmed compromise where you need to completely lock the account.

I also built a fifth playbook for threat intelligence enrichment (querying an external TI API to auto-enrich incidents with IP reputation data), but ran into API authentication and rate limiting issues that I didn't fully resolve. The workflow logic and JSON parsing work, but the external API integration needs more configuration before it's production-ready. Keeping it out of the table until it's actually working.

---

# Project 5 - Threat Hunting

### Hunt 1: Off-Hours Admin Activity (T1562.001)

If a compromised admin account is being used, it's more likely to show up between midnight and 6 AM or on weekends when the real admin isn't around.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Remove member from role",
    "Add user", "Delete user", "Reset password", "Update user")
| where Result == "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend HourOfDay = hourofday(TimeGenerated - 5h)  // EST offset
| extend DayOfWeek = dayofweek(TimeGenerated - 5h)
| extend IsOffHours = iff(HourOfDay >= 0 and HourOfDay < 6, "Late Night",
    iff(DayOfWeek == 0d or DayOfWeek == 6d, "Weekend", "Business Hours"))
| where IsOffHours != "Business Hours"
```

---

### Hunt 2: Rapid Privilege Escalation (T1098.003)

Looking for 2+ role assignments to the same user within a 15-minute window. Legitimate onboarding is usually one role at a time. Multiple in quick succession looks like post-compromise automation.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role" | where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = trim('"', tostring(TargetResources[0].modifiedProperties[1].newValue))
| summarize RoleCount = count(), Roles = make_list(RoleName),
    FirstAssignment = min(TimeGenerated), LastAssignment = max(TimeGenerated)
    by TargetUser, bin(TimeGenerated, 15m)
| where RoleCount >= 2
| extend TimeSpan = datetime_diff('minute', LastAssignment, FirstAssignment)
| extend RiskScore = case(
    RoleCount >= 5, 9,
    RoleCount >= 3, 7,
    TimeSpan < 5, 8,
    5)
| order by RiskScore desc
```

Scoring: 5+ roles in 15 min = 9 (critical), 3-4 roles = 7, 2 roles in under 5 min = 8 (speed suggests automation), default = 5.

---

### Hunt 3: Mass Account Modifications (T1098)

If someone's resetting passwords or changing MFA settings on a bunch of accounts in a short window, that's either a help desk doing scheduled work or an attacker locking people out and setting up persistence. The risk score tells you which.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Update user", "Reset password",
    "Update user authentication methods")
| where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| summarize
    ModificationCount = count(),
    AffectedUsers = make_set(TargetUser),
    Operations = make_set(OperationName),
    SourceIPs = make_set(SourceIP),
    FirstMod = min(TimeGenerated),
    LastMod = max(TimeGenerated)
    by Actor, bin(TimeGenerated, 30m)
| where ModificationCount >= 5
| extend TimeWindow = datetime_diff('minute', LastMod, FirstMod)
| extend RiskScore = case(
    ModificationCount >= 10, 9,
    ModificationCount >= 7, 7,
    TimeWindow < 10, 8,
    5)
| order by RiskScore desc
```

10+ modifications in 30 minutes from one actor = RiskScore 9. If those modifications span fewer than 10 minutes, that bumps to 8 even at lower volume because the speed suggests scripting, not manual help desk work. `make_set(TargetUser)` collects the affected accounts so you can immediately see if they're targeting privileged users or random employees.

---

### Hunt 4: Impossible Travel / Suspicious IP Patterns (T1078)

If the same user is authenticating from two different countries within an hour, either they're on a very fast plane or their credentials are compromised. Three or more countries is almost certainly an attacker testing stolen creds from distributed infrastructure.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| extend SourceIP = IPAddress
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| summarize
    AuthCount = count(),
    SuccessCount = countif(ResultType == 0),
    FailureCount = countif(ResultType != 0),
    Countries = make_set(Country),
    Cities = make_set(City),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, UserPrincipalName
| extend CountryCount = array_length(Countries)
| where CountryCount >= 2 or FailureCount >= 5
| extend RiskScore = case(
    CountryCount >= 3, 9,
    FailureCount >= 10, 8,
    CountryCount == 2 and SuccessCount > 0, 7,
    5)
| order by RiskScore desc
```

Scoring: 3+ countries = 9 (almost certainly compromised), 10+ failures from one IP = 8 (brute force), 2 countries with at least one success = 7 (impossible travel with confirmed access, which is the most dangerous scenario). `countif` lets me split success and failure counts in a single `summarize` without needing separate queries.

---

### Hunt 5: Failed Login Spikes (T1110)

This hunt tells apart brute force from password spraying. Brute force hits one user hard (`dcount(UserPrincipalName) == 1`, high fail count). Spraying hits many users lightly (`dcount(UserPrincipalName) >= 5`, moderate per-user count). The distinction matters because the response is different: brute force means lock that account, spraying means investigate the source infrastructure.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| extend FailureReason = ResultDescription
| summarize
    FailCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    TargetedUsers = make_set(UserPrincipalName),
    FailureReasons = make_set(FailureReason)
    by IPAddress, bin(TimeGenerated, 5m)
| where FailCount >= 10
| extend RiskScore = case(
    FailCount >= 50, 9,
    FailCount >= 25, 7,
    UniqueUsers >= 5, 8,
    5)
| order by RiskScore desc, FailCount desc
```

50+ failures in 5 minutes = 9. 5+ unique users targeted = 8 (password spraying, which is harder to detect because per-user volume is low). **This hunt got promoted to an analytics rule** because it consistently found real stuff with low false positives. When a hunting query keeps producing actionable results, it should graduate to automated detection.

### Schedule

| Cadence | Hunts |
|---------|-------|
| Daily | Failed Login Spikes, Suspicious IP Patterns |
| Weekly | Off-Hours Activity, Privilege Escalation, Mass Modifications |

---

# Project 6 - Azure Security Workshop (N-Tier Labs)

9 labs working through the [Azure N-Tier Reference Architecture](https://docs.microsoft.com/en-us/azure/architecture/reference-architectures/n-tier/n-tier-sql-server). Four-tier deployment (Jumpbox → Web → Business → SQL) in one VNet, Jumpbox as the only public entry point.

### Lab 1 - NSG Segmentation

Enforced inter-tier isolation so the web tier can't talk directly to the database. Only the business tier and jumpbox have SQL access.

| Priority | Rule | Source | Port | Action |
|----------|------|--------|------|--------|
| 110 | AllowFromBiz | 10.0.2.0/24 | * | Allow |
| 120 | AllowFromSQL | 10.0.3.0/24 | * | Allow |
| 130 | AllowRDPFromJB | 10.0.0.128/25 | 3389/TCP | Allow |
| 140 | DenyFromVNet | VirtualNetwork | * | **Deny** |
| 150 | DenyFromInternet | Internet | * | **Deny** |

Rules evaluate in priority order. First match wins. A packet from `web-subnet` (10.0.1.0/24) doesn't match 110, 120, or 130, hits the Deny at 140, and drops. Never reaches the default allow rules at 65000+.

### Lab 2 - NSG Flow Logs + Traffic Analytics

Enabled Flow Logs (v2) streaming to a storage account, linked to Traffic Analytics via Log Analytics for geo visualization and flow quantification. Network Watcher Topology for resource mapping.

### Lab 3 - Firewall Egress Control

UDR routing `0.0.0.0/0` through the firewall. Application rule allows HTTP/HTTPS to `github.com` only. Network rule allows UDP/53 to `168.63.129.16` (Azure's wireserver DNS). Everything else gets denied. Tested: `github.com` loads fine, `bbc.com` returns "Action: Deny. No rule matched."

### Lab 4 - Application Gateway + WAF

Layer 7 reverse proxy in a dedicated subnet. WAF in Detection mode, OWASP 3.x CRS. Optional DVWA deployment for SQL injection (CRS 942) and XSS (CRS 941) testing.

### Lab 5 - Defender for Cloud

Enabled Defender CSPM and Defender for Servers (formerly Security Center Standard tier) with AMA auto-provisioning. Reviewed Secure Score and prioritized recommendations.

### Lab 6 - Disk Encryption

Applied ADE using Key Vault as the KEK protector. `az vm encryption enable --volume-type All`. Verified with `az vm encryption show`, confirmed the Defender for Cloud recommendation cleared.

### Lab 7 - Site-to-Site VPN with BGP

IPSec/IKEv2 tunnel between an Azure VPN Gateway (BGP ASN 65515) and a pfSense firewall simulating on-prem (192.168.0.0/16, BGP ASN 65501). Phase 1: IKEv2, AES-256-CBC, SHA-256, DH Group 2. Phase 2: ESP, AES-256, PFS. Opened UDP 500/4500 on the NSG. BGP peered for dynamic route exchange. Verified: tunnel connected on both sides, telnet from pfSense to Web VM on port 80 confirmed connectivity. ✅

### Lab 8 - Entra ID Security

Bulk user provisioning via CSV + PowerShell. Configured SSPR with SMS. Enabled per-user MFA with E5 trial licensing. Set up Identity Protection risk policies (Medium+ sign-in risk → require MFA, High user risk → require password change). Tested with Tor Browser: user without MFA registration got blocked, user with MFA got prompted and authenticated successfully. Also registered an app with `IdentityRiskEvent.Read.All` Graph permission and wrote a PowerShell script to query the `identityRiskEvents` beta API for risk data. Set up RBAC with `Virtual Machine Contributor` at resource group scope.

### Lab 9 - DDoS Protection

Enabled DDoS Protection Standard, ran an authorized TCP SYN flood via BreakingPoint Cloud against the Application Gateway's public VIP. Watched the endpoint go down, then watched Azure's mitigation kick in within minutes. Azure Monitor showed the inbound packet rate spike, the "Under DDoS attack" flag flip, and the malicious traffic get scrubbed while legitimate traffic came back.

---

