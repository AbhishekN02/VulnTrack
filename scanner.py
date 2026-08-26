import json
from pathlib import Path
import ipaddress

OUTPUT = Path("data/scan_results.json")
PORT_RANGE = "1-1000"


def validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    # Portfolio lab guardrail: loopback/private IPs or explicit lab hostnames.
    try:
        ip = ipaddress.ip_address(target)
        if not (ip.is_loopback or ip.is_private):
            raise ValueError("Use a loopback/private lab IP for this portfolio scanner.")
    except ValueError:
        if target.lower() not in {"localhost"}:
            raise ValueError("Use localhost or a loopback/private lab IP.")
    return target


def scan_target(target: str):
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap is not installed. Run: pip install -r requirements.txt"
        ) from exc

    scanner = nmap.PortScanner()
    print(f"[+] Scanning authorized lab target: {target}")
    print(f"[+] Ports: {PORT_RANGE}")

    try:
        scanner.scan(hosts=target, ports=PORT_RANGE, arguments="-sT -sV --version-light")
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap scan failed: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(
            "Unable to run Nmap. Confirm Nmap is installed and available in PATH."
        ) from exc

    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                item = scanner[host][proto][port]
                results.append({
                    "host": host,
                    "protocol": proto,
                    "port": port,
                    "state": item.get("state", "unknown"),
                    "service": item.get("name", ""),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                })
    return results


def main():
    target = input("Enter authorized lab target: ")
    try:
        target = validate_target(target)
        results = scan_target(target)
    except (ValueError, RuntimeError) as exc:
        print(f"[!] {exc}")
        raise SystemExit(1)

    print("\n===== SCAN RESULTS =====")
    for r in results:
        print(
            f"{r['host']} | {r['port']}/{r['protocol']} | "
            f"{r['service']} | {r['product']} {r['version']}".rstrip()
        )

    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps({
        "schema_version": "2.0",
        "target": target,
        "results": results
    }, indent=4), encoding="utf-8")
    print(f"\n[+] Results saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
