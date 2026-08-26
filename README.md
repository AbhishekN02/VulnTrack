# VulnTrack v2.2

**Evidence-Based Vulnerability Assessment Laboratory**

VulnTrack is a defensive cybersecurity portfolio project that demonstrates an end-to-end vulnerability assessment workflow against authorized lab systems.

## Pipeline

```text
Authorized Lab Target
        |
        v
Nmap Service Discovery
        |
        v
Host Enumeration
        |
        v
Vulnerability Evidence
        |
        v
CPE Intelligence ----> Evidence confidence
        |
        v
CVE Intelligence ----> Only when CPE evidence is sufficient
        |
        v
Risk Prioritization
        |
        v
Professional HTML Report
```

## Features

- Nmap TCP service discovery
- Host/OS enumeration
- Evidence-based service findings
- NVD CPE intelligence
- Conservative CVE correlation
- Risk prioritization
- Confidence-aware findings
- Remediation recommendations
- Responsive dark security dashboard
- Dynamic security posture and risk-weighted distribution
- JSON evidence artifacts
- Reproducible assessment pipeline

## Important design principle

VulnTrack does **not** assign a CVE merely because a service is open.

A CVE correlation requires sufficiently reliable product/version evidence. If the evidence is insufficient, the engine reports:

```text
CPE: UNCONFIRMED
CVE: SKIPPED
```

This avoids unsupported vulnerability claims.

## Setup

Install Nmap separately and ensure `nmap.exe` is available in PATH.

Then:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run

For the safest portfolio demonstration, use localhost or a private lab target you own:

```powershell
python scanner.py
python host_enumerator.py
python vulnerability_engine.py
python cpe_engine.py
python cve_engine.py
python risk_engine.py
python report_generator.py
```

Or run the complete pipeline:

```powershell
python run_all.py
```

Open:

```text
reports\vulntrack_report.html
```

## Project Structure

```text
VulnTrack/
├── scanner.py
├── host_enumerator.py
├── vulnerability_engine.py
├── cpe_engine.py
├── cve_engine.py
├── risk_engine.py
├── report_generator.py
├── run_all.py
├── requirements.txt
├── data/
└── reports/
```

## Portfolio value

This project demonstrates practical understanding of:

- SOC / vulnerability assessment workflows
- Nmap
- Network service exposure
- CPE/CVE concepts
- NVD integration
- Evidence quality and confidence
- Risk prioritization
- Security reporting
- Python automation
- Defensive security engineering

> Use VulnTrack only against systems you are authorized to assess.

## Validation

Run the built-in checks before publishing changes:

```powershell
python -m py_compile *.py
python -m unittest discover -s tests -v
```

GitHub Actions runs the same checks on pushes and pull requests.

## Safety guardrail

The portfolio scanner accepts `localhost` and loopback/private IP targets only. Public IP targets are rejected by the scanner validation layer. This project is intended for authorized lab and defensive assessment use.
