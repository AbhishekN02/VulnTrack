import json
from pathlib import Path
from datetime import datetime, timezone
import requests

CPE = Path("data/cpe_results.json")
OUTPUT = Path("data/cve_results.json")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def main():
    cpe = json.loads(CPE.read_text(encoding="utf-8"))
    status = cpe.get("status", "UNCONFIRMED")
    selected = cpe.get("selected_cpe")

    result = {
        "schema_version": "2.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "SKIPPED",
        "reason": "",
        "cve_findings": []
    }

    print("===== VULNTRACK CVE INTELLIGENCE =====")

    if status != "CONFIRMED" or not selected:
        result["reason"] = (
            "CVE correlation skipped because no sufficiently reliable "
            "CPE match was established."
        )
        print("[!] CVE correlation skipped.")
        print(f"[!] {result['reason']}")
    else:
        try:
            r = requests.get(
                NVD,
                params={"cpeName": selected},
                timeout=30
            )
            r.raise_for_status()
            for item in r.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                result["cve_findings"].append({
                    "cve": cve.get("id"),
                    "description": next(
                        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                        ""
                    ),
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                })
            result["status"] = "CORRELATED"
        except requests.RequestException as exc:
            result["reason"] = f"NVD CVE lookup failed: {exc}"

    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=4), encoding="utf-8")
    print(f"[+] CVE results saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
