# SPL Reference Guide

A consolidated Splunk Processing Language (SPL) reference covering fundamentals, data manipulation, threat hunting, Windows security monitoring, and incident response workflows.

---

## Table of Contents

1. [Search Fundamentals](#search-fundamentals)
2. [Data Types and Syntax](#data-types-and-syntax)
3. [Filtering and Operators](#filtering-and-operators)
4. [Data Manipulation Commands](#data-manipulation-commands)
5. [Working with Time](#working-with-time)
6. [Strings and Arrays](#strings-and-arrays)
7. [Multi-Query Techniques](#multi-query-techniques)
8. [Formatting and Output](#formatting-and-output)
9. [Index and Source Discovery](#index-and-source-discovery)
10. [Windows Security Event Monitoring](#windows-security-event-monitoring)
11. [Sysmon Queries](#sysmon-queries)
12. [Threat Hunting](#threat-hunting)
13. [Incident Response Workflows](#incident-response-workflows)
14. [Quick Reference Tables](#quick-reference-tables)
15. [Tips and Gotchas](#tips-and-gotchas)

---

## Search Fundamentals

### Basic Search Structure

```spl
index=* source="*" EventCode=1 "powershell"
```

Searches all indexes for events matching the criteria. You can omit `source` or use wildcards; specify it when you have many sources with colliding event codes.

### Wildcards and Text Matching

```spl
index=* "*net.exe*"
index=* "192.168"
index=* "powershell" (NOT "*net.exe*")
index=* "HOST123" "*cmd.exe*"
```

You can chain `(NOT ...)` clauses to progressively exclude noise without rewriting the query.

### Field-Specific Searches

```spl
index=* Image="*\\powershell.exe"
index=* Image=*.exe
index=* User="NT AUTHORITY\\SYSTEM"
index=* User!=Administrator
index=* (Image="*cmd.exe" OR Image="*powershell.exe")
```

### Time Filtering

```spl
index=* earliest=-24h
index=* earliest=-15m
index=* earliest="10/01/2024:00:00:00" latest="10/02/2024:00:00:00"
```

---

## Data Types and Syntax

### The Pipe Operator

Each `|` sends output to the next command, like chaining building blocks:

```spl
index=* | head 10 | table User, Computer
```

1. Get all events
2. Take only the first 10
3. Display only User and Computer

### DNS Lookup

```spl
| lookup dnslookup clientip as dest_ip OUTPUT clienthost as dest_host
```

### DNS Independent IP Resolution

```spl
| inputlookup tHostInfo
| search src_ip=$IPADDRESS$ OR src_host=$HOSTNAME$
```

### Get Current User Context

```spl
| rest /services/authentication/current-context splunk_server=local
```

---

## Filtering and Operators

### WHERE — Basic Filtering

```spl
| where User="Administrator"
| where bytes_sent > 1000000
| where NOT User="SYSTEM"
| where EventCode=4624 AND User!="SYSTEM"
```

### WHERE with Pattern Matching (regex)

```spl
| where match(Process, "powershell")
| where match(Process, "(?i)powershell")                         # case-insensitive
| where NOT match(Company, "(?i)(Microsoft|Google|Adobe)")       # exclude multiple
```

### NOT vs !=

Empty strings are considered "not existing." If a field can be empty or have a value and you want empty strings, use `NOT` rather than `!=`.

### Exclude Noise

```spl
index=* source="*Sysmon*" EventCode=1
    NOT Image="*\\Windows\\System32\\*"
    NOT User="NT AUTHORITY\\SYSTEM"
```

### Focus on Suspicious Paths

```spl
index=* source="*Sysmon*" EventCode=1
    (Image="*\\Temp\\*" OR Image="*\\AppData\\*" OR Image="*\\Public\\*" OR Image="*\\Tasks\\*")
```

---

## Data Manipulation Commands

### table — Select Fields to Display

```spl
| table User, Computer, EventCode, _time
```

### fields — Include or Exclude

```spl
| fields User, Computer | fields - _raw
```

### dedup — Remove Duplicates

```spl
| dedup User
```

### eval — Create or Modify Fields

```spl
| eval UserType=if(User="Administrator", "Admin", "Standard")
```

### coalesce — First Non-Null Value

```spl
| eval Username=coalesce(User, AccountName, "Unknown")
```

### rename

Use `rename` after a command rather than `as` inside `stats ... by`:

```spl
| stats count by data.user | rename data.user to user
```

This also works when counting by multiple items:

```spl
| stats count by data.user, data.email | rename data.user to user
```

### stats — Aggregate Data

Common functions: `count`, `values()`, `dc()` (distinct count), `min()`, `max()`, `avg()`, `sum()`, `earliest()`, `latest()`.

```spl
| stats count by User
| stats count(User) as UniqueUsers, avg(Duration) as AverageDuration
| stats values(User) as LoggedInUsers, values(Computer) as Computers by SourceIP
```

### sort

```spl
| sort User              # ascending (default)
| sort -count            # descending
| sort User, -_time      # multi-field
```

### Lower-Case All Fields

```spl
| foreach "*" [eval <<FIELD>>=lower('<<FIELD>>')]
```

### Remove Domain from Device Name

```spl
| rex field=dest "^(?<dest>.*?)[\.|$]"
```

### Normalize User Field from WinEventLog

```spl
| eval user=lower(if(match(user,".*\\\\.*"), replace(user,".*\\\\",""), user))
```

---

## Working with Time

### Make Time Human-Readable

```spl
| eval mytime=strftime(_time, "%Y-%m-%d %H:%M:%S")
```

### Get Earliest and Latest Times for a Field

```spl
| stats earliest(_time) as firstTime latest(_time) as lastTime by dest
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
```

### Events Over Time (Timechart)

```spl
index="my_log" | timechart count span=1hr
```

Or manually:

```spl
index="my_log"
| bin span=1hr _time
| stats count by _time
```

### Use of `now` and Relative Time

```spl
| eval yesterday=relative_time(now(), "-1d@d")
```

### Event Frequency Calculation

```spl
| stats count by signature
| eval days = 10
| eval events_perShift = round(count / ((days * 24)/4), 3)
| eval events_perDay = round(count / days, 2)
| eval events_perWeek = round(count / (days / 7), 2)
| sort - count
| fields - count days
| table signature events_perShift events_perDay events_perWeek
| addcoltotals labelfield=signature label=Total
```

---

## Strings and Arrays

### String Matching (with Whitespace Suppression)

```spl
| rex field=context.MessageStatus "(?<messageStatus>\w+)"
| eval status=if(messageStatus="undelivered", "fail", "success")
```

### String Replacement (sed mode)

```spl
| rex mode=sed field=your_field "regex_statement"
# Example: strip all spaces
| rex mode=sed field=my_field "s/ //g"
```

### String Concatenation

```spl
| eval word = "foo" . "bar"
# Result: foobar
```

### Substrings

```spl
| eval short = substr(word, 1, 3)
# "foobar" → "oob"
```

### Array Contains a Value

```spl
"array_name{}"=value
"dictionary_name.array_name{}.dictionary2.deep_nested_array{}"=value
```

### Extract Value from Array by Index

```spl
| eval variable_name = mvindex('array_name{}', array_index)
```

### Multivalue to CSV

```spl
| eval mv_foo_csv = mvjoin(mv_foo, ", ")
```

Or:

```spl
| fields mv_foo
| mvcombine mv_foo delim=","
| nomv mv_foo
```

### Nested Dictionary Fields in eval

Rename first, then use in eval:

```spl
| rename signals.ip_address as ip_addr
| eval ip_addr=if(isnull(ip_addr), "null", ip_addr)
```

---

## Multi-Query Techniques

### Subsearches

Funnel output of one query into another. If unsupported, use cross-referencing:

```spl
index=*
    (endpoint="/userinfo" AND request-id="random-hash") OR user="random-hash"
| stats count by useragent
```

This searches all logs and cross-references a request ID from API logs with the user agent from nginx logs.

### Joins

```spl
sourcetype=suspicious_ips
| join type=left ip_address [
    search search_name=valid_ips
    | stats count by ip_address, search_name
]
| search NOT search_name=valid_ips
```

Always include the `search` keyword inside the subsearch bracket. Join types: `inner`, `left`. Use `max=0` for unlimited matches.

### Sankey (Multi-Stage)

**2-stage:**

```spl
| table src_ip dest_port dest_ip
| appendpipe [stats count by src_ip dest_port | rename src_ip as source, dest_port as target]
| appendpipe [stats count by dest_port dest_ip | rename dest_port as source, dest_ip as target]
| search source=*
| fields source target count
```

**3-stage:**

```spl
| table src_ip signature category dest_ip
| appendpipe [stats count by src_ip signature | rename src_ip as source, signature as target]
| appendpipe [stats count by signature category | rename signature as source, category as target]
| appendpipe [stats count by category dest_ip | rename category as source, dest_ip as target]
| search source=*
| fields source target count
```

---

## Formatting and Output

### Formatting Patterns for Downstream Systems (e.g., JIRA)

1. Use `rex` to extract values
2. Use `eval` to assign temporary variables
3. Use `mvexpand` to split multi-value results into separate rows
4. Use `stats list(<field>) as <name> by <group_fields>` to recombine rows
5. Use `nomv` to help JIRA recognize multi-value rows, then `rex` to replace spaces with newlines

### Group by IP Octet

**2 octets:**

```spl
| rex field=src_ip "(?<subnet>\d+\.\d+)+\.\d+\.\d+"
| stats count by subnet
```

**3 octets:**

```spl
| rex field=ip "(?<subnet>\d+\.\d+\.\d+)\.\d+"
| stats count by subnet
```

### Better FieldSummary with Event Coverage

```spl
index=pa_log sourcetype="pan:traffic" | fieldsummary
| eventstats max(count) as total
| eval event_coverage = round(((count / total)*100), 2)."%"
```

### CPE Extraction

```spl
| dedup agent_names
| fields installed_software{} agent_names sourcetype
| rename installed_software{} as installed_software
| mvexpand installed_software
| eval installed_software1 = split(installed_software, ":")
| eval vendor = mvindex(installed_software1, 2)
| eval product = mvindex(installed_software1, 3)
| eval version = mvindex(installed_software1, 4)
| eval service_pack = mvindex(installed_software1, 5)
| rename installed_software as cpe
| table agent_names product vendor version service_pack cpe
```

---

## Index and Source Discovery

### List All Indexes with Events

```spl
| eventcount summarize=false index=*
| search count!=0
| dedup index
| fields - server
```

### List All Non-Internal Indexes

```spl
| eventcount summarize=false index=*
| search count!=0 NOT index IN (audit_summary, cim_modactions, endpoint_summary, lastchanceindex, notable, notable_summary, risk, summary, tc_app_logs, threat_activity)
| dedup index
| fields - server
```

### List Sourcetypes in an Index

```spl
| metadata type=sourcetypes index=foo
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| eval recentTime=strftime(recentTime, "%Y-%m-%d %H:%M:%S")
```

### Search Time in a Lookup (e.g., Incident Review)

```spl
| inputlookup incident_review_lookup
| addinfo
| eval yesterday=relative_time(now(), "-1d@d")
| where (time >= yesterday AND time <= info_max_time)
```

### Find Hosts That Haven't Checked In

```spl
| stats latest(_time) as lastTime earliest(_time) as firstTime by hostnames
| eval recent = if(lastTime > relative_time(now(), "-30d"), 1, 0)
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| where recent=0
```

---

## Windows Security Event Monitoring

### Authentication

**Successful Logons (bucketed by 12-hour blocks):**

```spl
index="yourindex" source="WinEventLog:security" EventCode=4624 Logon_Type IN (2,7,10,11) NOT user IN ("DWM-*", "UMFD-*")
| eval Workstation_Name=lower(Workstation_Name)
| eval host=lower(host)
| eval hammer=_time
| bucket span=12h hammer
| stats values(Logon_Type) as "Logon Type" count sparkline by user, host, hammer, Workstation_Name
| rename hammer as "12 hour blocks" host as "Target Host" Workstation_Name as "Source Host"
| convert ctime("12 hour blocks")
| sort - "12 hour blocks"
```

**Successful Logins (excluding machine accounts):**

```spl
index="*" EventCode=4624 host="TARGETHOST"
| regex Account_Name!=".*\$"
| table _time, Account_Name, Logon_Type, Source_Network_Address, Workstation_Name
```

**Failed Logons (bucketed by 5-minute blocks):**

```spl
index="yourindex" source="WinEventLog:security" EventCode=4625
| eval Workstation_Name=lower(Workstation_Name)
| eval host=lower(host)
| eval hammer=_time
| bucket span=5m hammer
| stats count sparkline by user, host, hammer, Workstation_Name
| rename hammer as "5 minute blocks" host as "Target Host" Workstation_Name as "Source Host"
| convert ctime("5 minute blocks")
```

**Failed Logins (aggregated):**

```spl
index="*" EventCode=4625
| regex Account_Name!=".*\$"
| stats count by Account_Name, Source_Network_Address
| sort -count
```

**User Logon, Logoff, and Session Duration:**

```spl
index="yourindex" source="wineventlog:security" action=success Logon_Type=2
    (EventCode=4624 OR EventCode=4634 OR EventCode=4779 OR EventCode=4800 OR EventCode=4801 OR EventCode=4802 OR EventCode=4803 OR EventCode=4804)
    user!="anonymous logon" user!="DWM-*" user!="UMFD-*" user!=SYSTEM user!=*$
    (Logon_Type=2 OR Logon_Type=7 OR Logon_Type=10)
| convert timeformat="%a %B %d %Y" ctime(_time) AS Date
| streamstats earliest(_time) AS login, latest(_time) AS logout by Date, host
| eval session_duration=logout-login
| eval h=floor(session_duration/3600)
| eval m=floor((session_duration-(h*3600))/60)
| eval SessionDuration=h."h ".m."m "
| convert timeformat=" %m/%d/%y - %I:%M %P" ctime(login) AS login
| convert timeformat=" %m/%d/%y - %I:%M %P" ctime(logout) AS logout
| stats count AS auth_event_count, earliest(login) as login, max(SessionDuration) AS session_duration, latest(logout) as logout, values(Logon_Type) AS logon_types by Date, host, user
```

**Track Specific User Activity:**

```spl
index="*" (User="username" OR Account_Name="username")
| table _time, EventCode, ComputerName, Image, CommandLine, ProcessId
| sort _time
```

### Brute Force and Account Attacks

**Username Guessing Brute Force:**

```spl
index="yourindex" sourcetype=windows EventCode=4625 OR EventCode=4624
| bin _time span=5m as minute
| rex "Security ID:\s*\w*\s*\w*\s*Account Name:\s*(?<username>.*)\s*Account Domain:"
| stats count(Keywords) as Attempts,
    count(eval(match(Keywords,"Audit Failure"))) as Failed,
    count(eval(match(Keywords,"Audit Success"))) as Success by minute, username
| where Failed>=4
| stats dc(username) as Total by minute
| where Total>5
```

**Locked-Out Account Timechart:**

```spl
index="yourindex" sourcetype="WinEventLog:Security" EventCode=4625 AND Status=0xC0000234
| timechart count by user
| sort -count
```

**Failed Authentication to Non-Existing Account:**

```spl
index="yourindex" source="WinEventLog:security" sourcetype="WinEventLog:Security" EventCode=4625 Sub_Status=0xC0000064
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Which\sLogon\sFailed:\s+Security\sID:\s+\S.*\s+\w+\s\w+\S\s.(?<uacct>\S.*)"
| stats count by Date, uacct, host
| rename count as "Attempts"
| sort - Attempts
```

**Failed Attempt to Login to a Disabled Account:**

```spl
index="yourindex" source="WinEventLog:security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") Security_ID!="NULL SID" Account_Name!="*$"
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Which\sLogon\sFailed:\s+\S+\s\S+\s+\S+\s+Account\sName:\s+(?<facct>\S+)"
| stats count by Date, facct, host, Keywords
| rename facct as "Target Account" host as "Host" Keywords as "Status" count as "Count"
```

**Find Passwords Entered as Usernames:**

```spl
index="yourindex" source=WinEventLog:Security TaskCategory=Logon Keywords="Audit Failure"
| eval password=if(match(User_Name, "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\W])(?=.{10,})"), "Yes", "No")
| stats count by password, User_Name
| search password=Yes
```

**Failed RDP Attempt:**

```spl
index="yourindex" source=WinEventLog:Security Logon_Type=10 EventCode=4625
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Failed:\s+.*\s+Account\sName:\s+(?<TargetAccount>\S+)\s"
| stats count by Date, TargetAccount, Failure_Reason, host
| sort - Date
```

### Pass-the-Hash Detection

```spl
index="yourindex" (EventCode=4624 Logon_Type=3) OR (EventCode=4625 Logon_Type=3) Authentication_Package="NTLM" NOT Account_Domain=YOURDOMAIN NOT Account_Name="ANONYMOUS LOGON"
```

### Password and Account Changes

**AD Password Change Attempts:**

```spl
index="yourindex" source="WinEventLog:Security" EventCode=4723 src_user!="*$" src_user!="_svc_*"
| eval daynumber=strftime(_time, "%Y-%m-%d")
| chart count by daynumber, status
| eval daynumber = mvindex(split(daynumber, "-"), 2)
```

**User Account Created:**

```spl
index="*" EventCode=4720
| table _time, Account_Name, Target_User_Name, host
```

**Number of Accounts Created (Gauge):**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=624 OR EventCode=4720)
| eval NewAccount=case(EventCode=624, "New Account Created", EventCode=4720, "New Account Created")
| stats count(NewAccount) as creation
| gauge creation 1 5 15 25
```

**Disabled Account Re-Enabled:**

```spl
index="yourindex" sourcetype=WinEventLog:Security EventCode=4722
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "ID:\s+\w+\\\(?<sourceaccount>\S+)\s+"
| rex "Account:\s+Security\sID:\s+\w+\\\(?<targetaccount>\S+)\s+"
| stats count by Date, sourceaccount, targetaccount, Keywords, host
| rename sourceaccount as "Source Account" targetaccount as "Target Account"
| sort - Date
```

**Account Deleted Within 24 Hours of Creation:**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=4726 OR EventCode=4720)
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Subject:\s+\w+\s\S+\s+\S+\s+\w+\s\w+:\s+(?<SourceAccount>\S+)"
| rex "Target\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<DeletedAccount>\S+)"
| rex "New\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<NewAccount>\S+)"
| eval SuspectAccount=coalesce(DeletedAccount, NewAccount)
| transaction SuspectAccount startswith="EventCode=4720" endswith="EventCode=4726"
| eval duration=round(((duration/60)/60)/24, 2)
| eval Age=case(duration<=1, "Critical", duration>1 AND duration<=7, "Warning", duration>7, "Normal")
| table Date, index, host, SourceAccount, SuspectAccount, duration, Age
| rename duration as "Days Account was Active"
| sort + "Days Account was Active"
```

**Time Between Account Creation and Deletion (Minutes):**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=4726 OR EventCode=4720)
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Subject:\s+\w+\s\S+\s+\S+\s+\w+\s\w+:\s+(?<SourceAccount>\S+)"
| rex "Target\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<DeletedAccount>\S+)"
| rex "New\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<NewAccount>\S+)"
| eval SuspectAccount=coalesce(DeletedAccount, NewAccount)
| transaction SuspectAccount startswith="EventCode=4720" endswith="EventCode=4726"
| eval duration=round(duration/60, 2)
| eval Age=case(duration<=240, "Critical", duration>240 AND duration<=1440, "Warning", duration>1440, "Normal")
| table Date, index, host, SourceAccount, SuspectAccount, duration, Age
| rename duration as "Minutes Account was Active" index as "SSP or Index"
| sort + "Minutes Account was Active"
```

**User Added to Group:**

```spl
index="*" (EventCode=4732 OR EventCode=4728)
| table _time, Account_Name, Target_User_Name, Group_Name
```

**Changes to Windows User Group by Account:**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4746 OR EventCode=4751 OR EventCode=4756 OR EventCode=4161 OR EventCode=4185)
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Member:\s+\w+\s\w+:.*\\\(?<TargetAccount>.*)"
| rex "Account\sName:\s+(?<SourceAccount>.*)"
| stats count by Date, TargetAccount, SourceAccount, Group_Name, host, Keywords
| sort - Date
| rename SourceAccount as "Administrator Account" TargetAccount as "Target Account"
```

### Rights and Privileges

**Time Between Rights Granted and Revoked:**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=4717 OR EventCode=4718)
| rex "Access\sGranted:\s+Access\sRight:\s+(?<RightGranted>\w+)"
| rex "Access\sRemoved:\s+Access\sRight:\s+(?<RightRemoved>\w+)"
| eval Rights=coalesce(RightGranted, RightRemoved)
| eval status=case(EventCode=4717, "New Rights Granted by:", EventCode=4718, "Rights Removed by:")
| transaction Rights user startswith="Granted" endswith="Removed"
| where duration > 0
| eval duration = duration/60
| eval n=round(duration, 2)
| eval Date=strftime(_time, "%Y/%m/%d")
| table Date, host, status, Security_ID, user, Rights, n
| rename Security_ID as "Source Account" user as "Target Account" n as "Minutes between Rights Granted Then Removed"
| sort - date
```

**Privilege Escalation Detection:**

```spl
index="yourindex" sourcetype="WinEventLog:Security" (EventCode=576 OR EventCode=4672 OR EventCode=577 OR EventCode=4673 OR EventCode=578 OR EventCode=4674)
| stats count by user
```

### Audit and System Events

**Windows Audit Logs Cleared:**

```spl
index="yourindex" source=WinEventLog:security (EventCode=1102 OR EventCode=517)
| eval Date=strftime(_time, "%Y/%m/%d")
| stats count by Client_User_Name, host, index, Date
| sort - Date
| rename Client_User_Name as "Account Name"
```

**Console Lock Duration:**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=4800 OR EventCode=4801)
| eval Date=strftime(_time, "%Y/%m/%d")
| transaction host Account_Name startswith=EventCode=4800 endswith=EventCode=4801
| eval duration = round(duration/60, 2)
| table host, Account_Name, duration, Date
| rename duration as "Console Lock Duration in Minutes"
| sort - date
```

**Weekend User Activity:**

```spl
index="yourindex" sourcetype="WinEventLog:Security" (date_wday=saturday OR date_wday=sunday)
| stats count by Account_Name, date_wday
```

### File and Object Access

**Successful File Access (requires object access auditing):**

```spl
index="yourindex" sourcetype=WinEventLog (Relative_Target_Name!="\\\"" Relative_Target_Name!="*.ini") user!="*$"
| bucket span=1d _time
| stats count by Relative_Target_Name, user, _time, status
| rename _time as Day
| convert ctime(Day)
```

**File Deletion Attempts:**

```spl
index="yourindex" sourcetype="WinEventLog:Security" EventCode=564
| eval Date=strftime(_time, "%Y/%m/%d")
| stats count by Date, Image_File_Name, Type, host
| sort - Date
```

### Services

**New Service Installation:**

```spl
index="yourindex" sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601)
| eval Date=strftime(_time, "%Y/%m/%d")
| eval Status=coalesce(Keywords, Type)
| stats count by Date, Service_Name, Service_File_Name, Service_Account, host, Status
```

**Find Suspicious Services:**

```spl
index="*" source="WinEventLog:System" EventCode=7045
    (Service_Name="*temp*" OR Service_Name="*update*")
| table _time, Computer, Service_Name, Service_File_Name
```

---

## Sysmon Queries

### Common Sysmon Event Codes

| Code | Description |
|------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded (DLL) |
| 8 | CreateRemoteThread |
| 11 | File Created |
| 13 | Registry Value Set |
| 15 | File Stream Created (ADS / Zone.Identifier) |
| 22 | DNS Query |

### Process Information

```spl
index=* source="*Sysmon*" EventCode=1
| table _time, Computer, User, Image, CommandLine
```

**With parent process context:**

```spl
index=* source="*Sysmon*" EventCode=1
| table _time, Computer, User, ParentImage, ParentCommandLine, Image, CommandLine
```

### Network Connections

```spl
index=* EventCode=3
| table _time, Computer, Image, User, DestinationIp, DestinationPort, DestinationHostname
```

### File Creation

```spl
index=* EventCode=11
| table _time, Computer, Image, TargetFilename, CreationUtcTime
```

### Registry Modifications

```spl
index=* EventCode=13
| table _time, Computer, Image, TargetObject, Details, EventType
```

### Process with Network Activity (Join)

```spl
index=* EventCode=1 Image="*\\rundll32.exe"
| join ProcessGuid
    [search index=* source="*Sysmon*" EventCode=3]
| table _time, Computer, Image, CommandLine, DestinationIp, DestinationPort
```

### Parent-Child Relationships

```spl
index=* EventCode=1
    ParentImage="*\\explorer.exe"
    Image!="*\\Windows\\*"
| table _time, Computer, ParentImage, Image, CommandLine
```

### Process Genealogy

```spl
index=* Image="*\\suspicious.exe"
| table _time, ComputerName, User, ProcessId, ParentProcessId, ParentImage, CommandLine
| sort _time
```

---

## Threat Hunting

### Zerologon Detection

```spl
index="yourindex" (sourcetype="<windows_sourcetype_security>" OR source="windows_source_security") EventCode="4742" OR EventCode="4624" AND (src_user="*anonymous*" OR member_id="*S-1-0*")
| eval local_system=mvindex(upper(split(user,"$")), 0)
| search host=local_system
| table _time, EventCode, dest, host, ComputerName, src_user, Account_Name, local_system, user, Security_ID, member_id, src_nt_domain, dest_nt_domain
```

### Hunt with IOCs

```spl
index="*" ("malicious.exe" OR
    "192.168.1.100" OR
    "evil.com" OR
    "45.142.212.100" OR
    "C:\\Temp\\payload.ps1" OR
    "HKLM\\Software\\Evil" OR
    "SHA256_hash_here" OR
    "MD5_hash_here")
| table _time, host, source, User, Image, CommandLine, Message
```

### Processes with Network Connections from Untrusted Companies

Identifies executables that were both created and made network connections, excluding known vendors. Useful for finding payloads, reverse shells, and lateral movement tools.

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
| where NOT match(Company, "(?i)(Microsoft|Google|VMware)")
| eval ProcessGuid=coalesce(ProcessGuid, ProcessGuid)
| stats values(Image) as Process,
    values(CommandLine) as CommandLine,
    values(Company) as Company,
    values(User) as User,
    values(DestinationIp) as DestIP,
    values(DestinationPort) as DestPort,
    values(DestinationHostname) as DestHost,
    values(SourceIp) as SourceIP,
    values(SourcePort) as SourcePort,
    min(_time) as ProcessStart,
    values(EventCode) as EventCodes
    by ProcessGuid
| where EventCodes="1" AND EventCodes="3"
| table ProcessStart, Process, User, CommandLine, SourceIP, DestIP, DestPort, DestHost, Company
| sort -ProcessStart
```

### Rare Processes Making External Connections

```spl
index=* EventCode=3
| where NOT match(DestinationIp, "^(10\.|172\.|192\.168\.)")
| stats count by Image
| where count < 5
| sort count
```

### File Download Detection

**Web download commands:**

```spl
index="*" ("IWR" OR "Invoke-WebRequest" OR "wget" OR "curl" OR "DownloadString" OR "DownloadFile")
| table _time, host, User, CommandLine, ParentImage
```

**Zone.Identifier (Mark of the Web):**

```spl
index="*" EventCode=15 TargetFilename="*:Zone.Identifier"
| table _time, host, User, TargetFilename, Image
```

**Dangerous file types downloaded:**

```spl
index="*" EventCode=15 (TargetFilename="*.exe:Zone.Identifier" OR
    TargetFilename="*.ps1:Zone.Identifier" OR
    TargetFilename="*.zip:Zone.Identifier" OR
    TargetFilename="*.dll:Zone.Identifier" OR
    TargetFilename="*.scr:Zone.Identifier")
| table _time, host, User, TargetFilename, Image
```

### PowerShell Activity

**All PowerShell events:**

```spl
(index="*" source="*PowerShell*") OR
(index="*" EventCode=1 Image="*powershell.exe") OR
(index="*" EventCode=4104)
| table _time, host, User, ScriptBlockText, CommandLine, Message
```

**Encoded commands:**

```spl
index="*" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR ScriptBlockText="*FromBase64String*")
| table _time, host, User, CommandLine, ScriptBlockText
```

**PowerShell downloads:**

```spl
index=* "IEX" "DownloadString"
| table _time, Computer, User, CommandLine
```

### Remote Execution Detection

**WinRM / PSRemoting:**

```spl
index="*" "TaskCategory=Execute a Remote Command"
| table _time, host, User, CommandLine, Message
```

**Remote process creation (via WinRM/WinRS):**

```spl
index="*" EventCode=1 (ParentImage="*\\wsmprovhost.exe" OR ParentImage="*\\winrshost.exe")
| table _time, host, User, Image, CommandLine, ParentImage
```

### Lateral Movement — Users on Multiple Computers

```spl
index=* EventCode=4624
| stats values(Computer) as Computers,
    dc(Computer) as ComputerCount
    by User
| where ComputerCount > 1
```

### Network Investigation

**Top destinations:**

```spl
index="*" EventCode=3
| stats count by DestinationIp
| sort -count
| head 20
```

**Investigate a specific IP:**

```spl
index="*" DestinationIp="192.168.100.100"
| table _time, User, Image, ProcessId, host, DestinationPort
```

**Connections from a specific host:**

```spl
index="*" (SourceHostname="WK3.domain.com" OR host="WK3")
| stats count by DestinationIp
| sort -count
| head 20
```

### File Operations

**First instance of file creation:**

```spl
index="*" EventCode=11 TargetFilename="*some.exe"
| sort _time
| head 1
| table _time, host, User, Image, TargetFilename
```

**First execution of a binary:**

```spl
index="*" EventCode=1 Image="*\\some.exe"
| sort _time
| head 1
| table _time, ComputerName, User, CommandLine, ParentImage, ProcessId
```

**Get binary hash:**

```spl
index="*" EventCode=1 Image="*\\suspicious.exe"
| table _time, ComputerName, User, Image, SHA256, CommandLine
```

---

## Incident Response Workflows

### IOC-First Approach

1. Start with the IOCs from the threat intelligence report (hashes, IPs, domains, filenames).
2. Run the IOC hunt query above.
3. Reference any mentioned TTPs, if the report mentions phishing, look for macro-enabled file execution; if it mentions WinRAR for exfiltration, hunt for `.rar` activity.
4. Use `| sort _time | head 1` on findings to establish the earliest timestamp, then build a time range to hunt within.

### Establishing a Timeline

Use `| sort _time | head 1` to find the first occurrence of any suspicious artifact, then expand your search window around that point.

### Excluding Machine Accounts

Add `| regex Account_Name!=".*\$"` to filter out computer accounts from authentication queries.

### Tracking Lateral Movement

Focus on Logon_Type 3 (Network) and Logon_Type 10 (RemoteInteractive). Correlate source IPs across event types to trace attacker movement.

---

## Quick Reference Tables

### Common Windows Security Event Codes

| EventCode | Description |
|-----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential logon |
| 4672 | Special privileges assigned |
| 4697 | Service installed |
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 | Password change attempt |
| 4726 | User account deleted |
| 4728 | Member added to global group |
| 4732 | Member added to local group |
| 4742 | Computer account changed |
| 4800 | Workstation locked |
| 4801 | Workstation unlocked |
| 1102 | Audit log cleared |

### Common Logon Types

| Type | Description |
|------|-------------|
| 2 | Interactive (console) |
| 3 | Network |
| 7 | Unlock |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |

### Essential Fields

| Field | Description |
|-------|-------------|
| `_time` | When it happened |
| `Computer` / `host` | What machine |
| `User` / `Account_Name` | Who did it |
| `Image` | What program ran |
| `CommandLine` | How it was invoked |
| `ParentImage` | What started it |
| `TargetFilename` | File created or modified |
| `DestinationIp` | Outbound connection target |
| `ProcessId` / `ProcessGuid` | Unique process identifiers |
| `EventCode` | Type of event |

### Command Quick Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `\|` | Pipe to next command | `index=* \| head 10` |
| `where` | Filter results | `\| where User="admin"` |
| `where NOT` | Exclude results | `\| where NOT User="SYSTEM"` |
| `match()` | Regex pattern match | `\| where match(field, "pattern")` |
| `as` | Rename in stats | `\| stats count as Total` |
| `rename` | Rename fields | `\| rename old as new` |
| `sort` | Order results | `\| sort -count` |
| `table` | Display specific fields | `\| table User, _time` |
| `stats` | Aggregate data | `\| stats count by User` |
| `values()` | Unique values | `\| stats values(IP) by User` |
| `dc()` | Distinct count | `\| stats dc(host) by User` |
| `eval` | Create/modify fields | `\| eval x=a+b` |
| `coalesce()` | First non-null value | `\| eval x=coalesce(a,b)` |
| `dedup` | Remove duplicates | `\| dedup User` |
| `rex` | Regex extraction | `\| rex field=src "(?<subnet>...)"` |
| `transaction` | Group related events | `\| transaction user startswith=... endswith=...` |
| `timechart` | Time-based chart | `\| timechart count span=1hr` |
| `bin` | Bucket time/values | `\| bin span=5m _time` |

---

## Tips and Gotchas

1. **Start broad, then narrow.** Begin with `index=* "keyword"`, then add filters one pipe at a time.
2. **Test each pipe incrementally.** Run the query after adding each new pipe to see its effect.
3. **Use NOT to reduce noise.** Chain `NOT Image="*\\trusted.exe"` to exclude known-good processes.
4. **Wildcards are your friend.** `*` matches anything in field values.
5. **Case sensitivity.** Use `(?i)` in regex for case-insensitive matching.
6. **Check available fields.** Run a basic search and look at "Interesting Fields" in the sidebar.
7. **Exclude machine accounts.** Append `| regex Account_Name!=".*\$"` for auth queries.
8. **Always check first occurrence.** Use `| sort _time | head 1` to find the origin point.
9. **Track process lineage.** Always include `ParentImage` and `ParentProcessId` to understand execution chains.
10. **`stats count by X` is not the same as `stats count by X as Y`.** Use `| rename` after the stats command for reliable field renaming.
11. **Empty strings and NOT.** `!=` doesn't match empty/null fields; `NOT` does.
12. **Always put `search` in join subsearches.** Omitting it causes silent failures.
