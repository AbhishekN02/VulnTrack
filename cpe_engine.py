import json
from pathlib import Path
from datetime import datetime, timezone
import requests

HOST = Path("data/host_info.json")
OUTPUT = Path("data/cpe_results.json")
NVD = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

WINDOWS_BUILDS = {
    "19045": "22H2",
    "19044": "21H2",
    "19043": "21H1",
    "19042": "20H2",
    "19041": "2004",
    "18363": "1909",
    "18362": "1903",
}

def main():
    host = json.loads(HOST.read_text(encoding="utf-8"))
    os_name = host.get("operating_system", "")
    edition = host.get("edition", "")
    build = str(host.get("build", ""))
    arch = host.get("architecture", "")
    generation = WINDOWS_BUILDS.get(build)

    result = {
        "schema_version": "2.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": edition or os_name,
        "build": build,
        "architecture": arch,
        "windows_generation": generation,
        "status": "UNCONFIRMED",
        "confidence": "VERY_LOW",
        "selected_cpe": None,
        "candidates": [],
        "reason": "No exact product/version CPE was established from available host evidence."
    }

    print("===== VULNTRACK CPE MATCHING =====")
    print(f"[+] OS: {edition or os_name}")
    print(f"[+] Build: {build}")
    print(f"[+] Architecture: {arch}")
    print(f"[+] Windows generation: {generation or 'UNKNOWN'}")

    if os_name.lower() == "windows" and "10" in edition.lower():
        try:
            resp = requests.get(NVD, params={"keywordSearch": "Windows 10", "resultsPerPage": 2000}, timeout=30)
            resp.raise_for_status()
            items = resp.json().get("products", [])
            for item in items:
                c = item.get("cpe", {})
                name = c.get("criteria", "")
                deprecated = c.get("deprecated", False)
                if name.startswith("cpe:2.3:o:microsoft:windows_10:") and not deprecated:
                    result["candidates"].append(name)
        except requests.RequestException as exc:
            result["reason"] = f"NVD CPE lookup failed: {exc}"

    # Do not label a generic family match as confirmed.
    # Windows 10 22H2/build 19045 is not represented by the weak candidates
    # returned in the user's previous scan, so status remains UNCONFIRMED.
    result["candidates"] = result["candidates"][:20]

    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=4), encoding="utf-8")

    print(f"[+] CPE status: {result['status']}")
    print(f"[+] Confidence: {result['confidence']}")
    print(f"[+] Candidates retained: {len(result['candidates'])}")
    print(f"[+] CPE results saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
