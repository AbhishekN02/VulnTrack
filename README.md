# VulnTrack v2.2

> **Evidence-based vulnerability assessment platform for authorized security labs**

VulnTrack is a Python-based defensive security project that turns network and host evidence into a structured vulnerability-assessment workflow.

It combines **Nmap service discovery, host enumeration, vulnerability evidence, CPE intelligence, conservative CVE correlation, risk prioritization, and a professional HTML security report** into one reproducible pipeline.

**Designed for:** cybersecurity portfolios, SOC/security analyst practice, authorized lab assessments, and defensive security engineering.

---

## Why VulnTrack?

A basic port scanner can tell you that a service is open. VulnTrack goes further by asking:

- What service was actually observed?
- What host and OS evidence is available?
- How confident are we in the finding?
- Can the observed product be reliably mapped to a CPE?
- Is there enough evidence to correlate CVEs?
- What should be remediated first?
- Can the assessment be presented as a professional security report?

The project deliberately avoids turning weak evidence into a false vulnerability claim.

### Core principle

> **No reliable product/version evidence → no unsupported CVE attribution.**

When CPE evidence is insufficient, VulnTrack records the uncertainty and skips CVE correlation instead of guessing.

---

## Architecture

```text
                    AUTHORIZED LAB TARGET
                             |
                             v
                  +-----------------------+
                  |     Nmap Scanner      |
                  |   Ports 1-1000 / TCP  |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |  Host Enumeration     |
                  | OS / Build / Arch     |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  | Vulnerability Engine  |
                  | Service Evidence      |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |    CPE Intelligence   |
                  | Match + Confidence     |
                  +-----------+-----------+
                              |
                    sufficient evidence?
                       /             \
                     YES              NO
                      |                |
                      v                v
              +---------------+   CPE UNCONFIRMED
              | CVE Engine    |   CVE CORRELATION
              | NVD Correlation|     SKIPPED
              +-------+-------+
                      |
                      v
              +----------------+
              |  Risk Engine   |
              | Score / Priority|
              +-------+--------+
                      |
                      v
              +----------------+
              | HTML Dashboard |
              | Evidence Report|
              +----------------+
```

---

## Key Features

### Network discovery
- Nmap TCP service discovery
- Service/product/version collection
- Port state classification
- Authorized-target validation

### Host intelligence
- Hostname
- Operating system
- OS version/build
- Edition
- Architecture
- Processor evidence

### Vulnerability assessment
- Service exposure findings
- Severity classification
- Confidence levels
- Evidence-based recommendations

### CPE intelligence
- NVD CPE lookup
- Candidate filtering
- Windows generation/build evidence
- Candidate ranking
- Confidence-aware matching
- Explicit `UNCONFIRMED` state when evidence is insufficient

### CVE intelligence
- CVE correlation only after reliable CPE evidence
- Avoids unsupported CVE claims
- Records why correlation was skipped when necessary

### Risk prioritization
- Risk score
- Priority classification
- Exposure
- Confidence
- Remediation recommendation

### Security reporting
- Responsive dark security dashboard
- Dynamic security posture
- Risk-weighted distribution
- Attack-surface overview
- Finding details
- CPE/CVE intelligence
- Remediation priorities

---

## Example Assessment

A localhost assessment can produce evidence such as:

```text
127.0.0.1 | 135/tcp | msrpc
127.0.0.1 | 137/tcp | netbios-ns
127.0.0.1 | 445/tcp | microsoft-ds
```

The vulnerability engine may then identify service exposure such as:

```text
SMB Service Exposed          P2
Microsoft RPC Service       P3
Filtered Service            P4 / INFO
```

If the host evidence does not establish a sufficiently reliable product CPE, VulnTrack intentionally reports:

```text
CPE Status: UNCONFIRMED
CPE Confidence: VERY_LOW
CVE Correlation: SKIPPED
```

This is expected behavior, not a failed scan.

---

## Risk Model

VulnTrack's risk engine prioritizes findings using the evidence available to the assessment.

The report separates:

| Priority | Meaning |
|---|---|
| **P1** | Critical / highest remediation priority |
| **P2** | High remediation priority |
| **P3** | Medium remediation priority |
| **P4** | Informational / low-priority observation |

Risk scores are used for prioritization and dashboard visualization.

> **Risk score is not CVSS.**  
> A VulnTrack score should not be presented as an official CVSS score.

---

## Project Structure

```text
VulnTrack/
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── docs/
│   └── ARCHITECTURE.md
│
├── tests/
│   └── test_core.py
│
├── scanner.py
├── host_enumerator.py
├── vulnerability_engine.py
├── cpe_engine.py
├── cve_engine.py
├── risk_engine.py
├── report_generator.py
├── run_all.py
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

Runtime-generated assessment artifacts are intentionally kept out of the public repository.

---

## Requirements

- Python 3.10+ recommended
- Nmap installed separately
- Windows/Linux/macOS environment suitable for the installed Nmap build
- An authorized loopback or private lab target

### Nmap

Install Nmap separately and ensure the executable is available in your system `PATH`.

Verify:

```powershell
nmap --version
```

### Python dependencies

Create a virtual environment:

```powershell
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

---

## Usage

### Recommended: complete pipeline

```powershell
python run_all.py
```

When prompted, enter an authorized lab target such as:

```text
127.0.0.1
```

The pipeline runs:

```text
scanner.py
    ↓
host_enumerator.py
    ↓
vulnerability_engine.py
    ↓
cpe_engine.py
    ↓
cve_engine.py
    ↓
risk_engine.py
    ↓
report_generator.py
```

The generated dashboard is:

```text
reports\vulntrack_report.html
```

Open it with:

```powershell
start reports\vulntrack_report.html
```

### Run modules individually

```powershell
python scanner.py
python host_enumerator.py
python vulnerability_engine.py
python cpe_engine.py
python cve_engine.py
python risk_engine.py
python report_generator.py
```

Running the complete pipeline is recommended because each stage consumes evidence produced by the previous stage.

---

## Output Artifacts

During an assessment, VulnTrack can create structured JSON artifacts such as:

```text
data/
├── scan_results.json
├── host_info.json
├── vulnerability_results.json
├── cpe_results.json
├── cve_results.json
└── risk_results.json
```

The final report is generated at:

```text
reports/
└── vulntrack_report.html
```

These runtime artifacts may contain environment-specific information and should **not** be committed to a public repository unless intentionally sanitized.

---

## Validation & Testing

Compile the Python modules:

```powershell
python -m py_compile *.py
```

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

GitHub Actions also runs the project's automated checks on repository changes.

---

## Responsible Use

VulnTrack is intended for:

- systems you own;
- systems you are explicitly authorized to assess;
- localhost testing;
- private cybersecurity labs;
- educational environments.

The scanner includes a target-validation guardrail designed to restrict scanning to loopback/private IP targets or `localhost`.

**Do not use VulnTrack to scan public systems without explicit authorization.**

The project is a defensive assessment and learning tool. Finding an exposed service does not by itself prove that a system is vulnerable.

---

## Limitations

VulnTrack is a portfolio/lab project and should not be treated as a replacement for enterprise vulnerability-management platforms.

Important limitations include:

- Service detection may not identify an exact product/version.
- CPE matching can remain uncertain even when OS/build evidence is available.
- CVE correlation is intentionally conservative.
- A skipped CVE correlation does not mean the host has no vulnerabilities.
- Risk scores are project-specific prioritization values, not official CVSS ratings.
- Nmap results depend on network conditions and the installed Nmap version.
- The tool does not provide authenticated enterprise-wide vulnerability management.

---

## Security Philosophy

VulnTrack emphasizes **evidence quality over impressive-looking vulnerability counts**.

A useful security assessment should be able to answer:

```text
What did we observe?
        ↓
How confident are we?
        ↓
What can we reliably identify?
        ↓
What can we safely correlate?
        ↓
What should be fixed first?
```

If the evidence is insufficient, the correct answer is:

```text
INSUFFICIENT EVIDENCE
```

—not a guessed CVE.

---

## Portfolio Highlights

This project demonstrates practical experience with:

- Python security automation
- Nmap
- Network service discovery
- Windows host enumeration
- Vulnerability assessment workflows
- CPE/CVE concepts
- NVD integration
- Evidence confidence
- Risk prioritization
- Security reporting
- Defensive engineering
- Automated testing
- GitHub Actions / CI

---

## Roadmap

Potential future improvements:

- authenticated Windows evidence collection;
- broader OS/product CPE matching;
- additional service-specific checks;
- richer remediation mappings;
- export to JSON/CSV/PDF;
- historical assessment comparison;
- configurable risk scoring;
- additional automated tests.

---

## License

VulnTrack is released under the **MIT License**. See [`LICENSE`](LICENSE).

---

## Author

**Abhishek N.**

Cybersecurity / SOC-focused portfolio project.

---

> **VulnTrack v2.2 — Evidence first. Confidence matters. Risk prioritized.**
