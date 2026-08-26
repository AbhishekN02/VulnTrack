import json
from pathlib import Path
from datetime import datetime, timezone

VULN = Path("data/vulnerability_results.json")
OUTPUT = Path("data/risk_results.json")

SEVERITY = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 60, "LOW": 30, "INFO": 10}
CONFIDENCE = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6, "VERY_LOW": 0.4}

def score(f):
    base = SEVERITY.get(f.get("severity", "INFO"), 10)
    confidence = CONFIDENCE.get(f.get("confidence", "LOW"), 0.5)
    exposure = 1.0 if f.get("type") == "SERVICE_EXPOSURE" else 0.6
    score = round(base * confidence * exposure)
    priority = "P1" if score >= 80 else "P2" if score >= 60 else "P3" if score >= 30 else "P4"
    return score, priority

def main():
    data = json.loads(VULN.read_text(encoding="utf-8"))
    records = []
    for f in data.get("findings", []):
        s, p = score(f)
        records.append({
            **f,
            "risk_score": s,
            "priority": p,
            "exposure": "NETWORK" if f.get("type") == "SERVICE_EXPOSURE" else "LOCAL"
        })
    records.sort(key=lambda x: x["risk_score"], reverse=True)

    summary = {
        "total_findings": len(records),
        "p1": sum(x["priority"] == "P1" for x in records),
        "p2": sum(x["priority"] == "P2" for x in records),
        "p3": sum(x["priority"] == "P3" for x in records),
        "p4": sum(x["priority"] == "P4" for x in records),
    }

    out = {
        "schema_version": "2.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "risk_method": "Severity × Evidence Confidence × Exposure",
        "findings": records,
        "summary": summary,
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(out, indent=4), encoding="utf-8")

    print("===== VULNTRACK RISK ENGINE =====")
    for r in records:
        print(f"{r['finding']} | {r['priority']} | score={r['risk_score']}")
    print(f"[+] Risk results saved to: {OUTPUT}")

if __name__ == "__main__":
    main()
