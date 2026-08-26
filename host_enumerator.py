import json
import platform
from pathlib import Path
from datetime import datetime, timezone

OUTPUT = Path("data/host_info.json")


def main():
    info = {
        "schema_version": "2.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
    }

    # Windows edition/build can be supplemented with platform.version().
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            )
            info["edition"] = winreg.QueryValueEx(key, "ProductName")[0]
            info["build"] = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            winreg.CloseKey(key)
        except Exception:
            info["edition"] = "Unknown"
            info["build"] = "Unknown"

    print("===== VULNTRACK HOST ENUMERATION =====")
    for k, v in info.items():
        print(f"{k}: {v}")

    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(info, indent=4), encoding="utf-8")
    print(f"[+] Host information saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
