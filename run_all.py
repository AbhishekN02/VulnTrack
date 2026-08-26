import subprocess
import sys

STEPS = [
    ("scanner.py", True),
    ("host_enumerator.py", False),
    ("vulnerability_engine.py", False),
    ("cpe_engine.py", False),
    ("cve_engine.py", False),
    ("risk_engine.py", False),
    ("report_generator.py", False),
]

for script, needs_input in STEPS:
    print(f"\n===== RUNNING {script} =====")
    result = subprocess.run([sys.executable, script])
    if result.returncode != 0:
        print(f"[!] {script} failed. Pipeline stopped.")
        raise SystemExit(result.returncode)

print("\n[+] VulnTrack v2 pipeline completed.")
print("[+] Open: reports\\vulntrack_report.html")
