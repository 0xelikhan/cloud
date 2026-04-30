# Microsoft Sentinel — KQL Detection Queries

KQL detection queries written against the Microsoft Sentinel demo workspace. Mirrors the same MITRE ATT&CK coverage as the Sigma rules in [detection-rules](https://github.com/YOUR-USERNAME/detection-rules) — demonstrating the ability to write detections natively in each platform's query language.

**Free access:** https://aka.ms/lademo — no Azure subscription needed.

## Coverage
| Query file | Technique | MITRE ID |
|------------|-----------|----------|
| lsass-dump.kql | LSASS memory access | T1003.001 |
| powershell-encoded.kql | PowerShell encoded command | T1059.001 |
| registry-run-key.kql | Registry run key persistence | T1547.001 |
| smb-lateral.kql | SMB admin share access | T1021.002 |
| pass-the-hash.kql | NTLM lateral movement | T1550.002 |
| dns-tunneling.kql | DNS C2 | T1071.004 |
| kerberoasting.kql | Kerberos service ticket abuse | T1558.003 |

## Screenshots
<!-- Add after build -->
![KQL query results in Sentinel Logs blade](screenshots/kql-query-results.png)
![Sentinel analytics rule created from KQL](screenshots/sentinel-analytics-rule.png)
