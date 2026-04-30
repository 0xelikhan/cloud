# Splunk — SPL Detection Queries

SPL queries covering the same MITRE ATT&CK techniques as the Sigma rules and KQL queries. Splunk is deployed in the on-prem lab (10.10.10.25) with Wazuh alerts forwarded in. These queries demonstrate multi-platform detection engineering — same scenario, three different query languages.

## Coverage
| Query file | Technique | MITRE ID |
|------------|-----------|----------|
| lsass-dump.spl | LSASS memory access | T1003.001 |
| powershell-encoded.spl | PowerShell encoded command | T1059.001 |
| registry-run-key.spl | Registry persistence | T1547.001 |
| smb-lateral.spl | SMB admin share access | T1021.002 |
| pass-the-hash.spl | NTLM lateral movement | T1550.002 |
| dns-tunneling.spl | DNS C2 | T1071.004 |

## Screenshots
<!-- Add after build -->
![Splunk SPL detection query results](screenshots/splunk-spl-results.png)
![Splunk saved alert](screenshots/splunk-saved-alert.png)
