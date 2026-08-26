# VulnTrack Architecture

## Data flow

Scanner -> scan_results.json
Host Enumerator -> host_info.json
Vulnerability Engine -> vulnerability_results.json
CPE Engine -> cpe_results.json
CVE Engine -> cve_results.json
Risk Engine -> risk_results.json
Report Generator -> reports/vulntrack_report.html

Each stage consumes explicit JSON evidence from the previous stage. This makes the assessment reproducible and auditable.
