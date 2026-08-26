import json
from pathlib import Path
from datetime import datetime, timezone
from html import escape

DATA = Path("data")
OUT = Path("reports/vulntrack_report.html")


def load(name, default):
    path = DATA / name
    if not path.exists():
        return default
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value
    except (OSError, json.JSONDecodeError):
        return default


def esc(value, fallback="—"):
    if value is None or value == "":
        return fallback
    return escape(str(value))


def badge(text, cls):
    return f'<span class="badge {escape(str(cls))}">{escape(str(text))}</span>'


def normalize_scan(raw):
    if isinstance(raw, dict):
        return raw.get("results", [])
    return raw if isinstance(raw, list) else []


def normalize_findings(risk):
    if isinstance(risk, dict):
        return risk.get("findings", [])
    return []


def priority_class(priority):
    return {"P1": "p1", "P2": "p2", "P3": "p3", "P4": "p4"}.get(priority, "p4")


def severity_class(severity):
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }.get(str(severity).upper(), "info")


def calculate_posture(findings):
    """Portfolio posture indicator; explicitly not CVSS.

    The score subtracts 30% of the aggregate VulnTrack risk score and is
    capped to 0..100. This keeps the calculation transparent and stable.
    """
    total_risk = sum(float(f.get("risk_score", 0) or 0) for f in findings)
    score = max(0, min(100, round(100 - (total_risk * 0.30))))
    if score >= 80:
        label = "LOW EXPOSURE"
    elif score >= 60:
        label = "MODERATE EXPOSURE"
    elif score >= 40:
        label = "ELEVATED EXPOSURE"
    else:
        label = "HIGH EXPOSURE"
    return score, label


def main():
    host = load("host_info.json", {})
    scan = normalize_scan(load("scan_results.json", []))
    risk = load("risk_results.json", {})
    cpe = load("cpe_results.json", {})
    cve = load("cve_results.json", {})

    findings = normalize_findings(risk)
    summary = risk.get("summary", {}) if isinstance(risk, dict) else {}
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    open_ports = sum(str(x.get("state", "")).lower() == "open" for x in scan)
    filtered_ports = sum(str(x.get("state", "")).lower() == "filtered" for x in scan)
    closed_ports = sum(str(x.get("state", "")).lower() == "closed" for x in scan)
    cve_findings = cve.get("cve_findings", []) if isinstance(cve, dict) else []
    cve_count = len(cve_findings)

    p1 = int(summary.get("p1", sum(x.get("priority") == "P1" for x in findings)))
    p2 = int(summary.get("p2", sum(x.get("priority") == "P2" for x in findings)))
    p3 = int(summary.get("p3", sum(x.get("priority") == "P3" for x in findings)))
    p4 = int(summary.get("p4", sum(x.get("priority") == "P4" for x in findings)))
    total_findings = len(findings)
    actionable = sum(x.get("priority") in {"P1", "P2", "P3"} for x in findings)

    posture, posture_label = calculate_posture(findings)
    posture_angle = posture * 3.6

    top = findings[0] if findings else None
    risk_totals = {
        "P1": sum(float(x.get("risk_score", 0) or 0) for x in findings if x.get("priority") == "P1"),
        "P2": sum(float(x.get("risk_score", 0) or 0) for x in findings if x.get("priority") == "P2"),
        "P3": sum(float(x.get("risk_score", 0) or 0) for x in findings if x.get("priority") == "P3"),
        "P4": sum(float(x.get("risk_score", 0) or 0) for x in findings if x.get("priority") == "P4"),
    }
    max_risk = max(max(risk_totals.values(), default=0), 1)

    port_cards = []
    for item in scan:
        state = str(item.get("state", "")).lower()
        state_cls = "open" if state == "open" else "filtered" if state == "filtered" else "closed"
        service = str(item.get("service") or "unknown").upper()
        product = str(item.get("product") or "Product not identified")
        matching = next((f for f in findings if str(f.get("port")) == str(item.get("port"))), None)
        pri = matching.get("priority", "INFO") if matching else "INFO"
        risk_score = matching.get("risk_score") if matching else None
        port_cards.append(
            f'''<article class="port-card {state_cls}">
                <div class="port-head"><div class="port-number">{esc(item.get("port"))}</div>{badge(state.upper() or "UNKNOWN", state_cls)}</div>
                <div class="port-service">{escape(service)}</div>
                <div class="port-product">{escape(product)}</div>
                <div class="port-foot"><span>{escape(str(item.get("protocol") or "tcp").upper())}</span>
                <span>{badge(pri, priority_class(pri))}</span>{f'<strong>Risk {escape(str(risk_score))}</strong>' if risk_score is not None else ''}</div>
            </article>'''
        )
    port_cards_html = "".join(port_cards) or '<div class="empty">No port observations available.</div>'

    finding_cards = []
    for f in findings:
        priority = f.get("priority", "P4")
        severity = str(f.get("severity", "INFO")).upper()
        score = f.get("risk_score", 0)
        confidence = str(f.get("confidence", "LOW")).upper()
        evidence = f.get("evidence") or f"Observed {f.get('service', 'service')} on TCP/{f.get('port', 'unknown')}."
        recommendation = f.get("recommendation") or "Review the finding and apply appropriate controls."
        finding_cards.append(
            f'''<article class="finding-card">
                <div class="finding-top">
                  <div><div class="finding-title">{esc(f.get("finding", "Unnamed finding"))}</div>
                  <div class="finding-meta">{escape(str(f.get("protocol", "tcp")).upper())}/{esc(f.get("port"))} · {escape(str(f.get("exposure", "NETWORK")))} · {escape(confidence)} CONFIDENCE</div></div>
                  <div class="badges">{badge(priority, priority_class(priority))}{badge(severity, severity_class(severity))}</div>
                </div>
                <div class="finding-score"><strong>{escape(str(score))}</strong><span>VulnTrack risk score</span></div>
                <div class="evidence-row"><span class="label">EVIDENCE</span><p>{escape(evidence)}</p></div>
                <div class="evidence-row"><span class="label">RECOMMENDATION</span><p>{escape(recommendation)}</p></div>
                <div class="finding-foot"><span>CVE: {escape(str(f.get("cve") or "Not determined"))}</span><span>CVSS: {escape(str(f.get("cvss") or "Not determined"))}</span></div>
            </article>'''
        )
    findings_html = "".join(finding_cards) or '<div class="empty">No security findings were produced.</div>'

    def risk_bar(label, priority, count, cls):
        risk_value = risk_totals.get(priority, 0)
        width = round((risk_value / max_risk) * 100) if risk_value else 0
        display = f"{int(risk_value) if float(risk_value).is_integer() else risk_value:g}"
        return f'''<div class="bar-row"><div class="bar-label"><span>{label}</span><strong>{count} finding{"s" if count != 1 else ""} · risk {display}</strong></div><div class="bar"><i class="{cls}" style="width:{width}%"></i></div></div>'''

    cpe_status = str(cpe.get("status", "UNCONFIRMED"))
    cpe_conf = str(cpe.get("confidence", "VERY_LOW"))
    cpe_good = cpe_status.upper() == "CONFIRMED"
    cpe_class = "good" if cpe_good else "warn"
    cpe_reason = cpe.get("reason") or "No exact product/version CPE was established from the available host evidence."
    selected_cpe = cpe.get("selected_cpe")

    cve_reason = cve.get("reason") or ("No evidence-backed CVE correlations were identified." if cve_count == 0 else "CVE correlations identified from the selected CPE.")

    remediation_items = []
    seen_recs = set()
    for f in sorted(findings, key=lambda x: float(x.get("risk_score", 0) or 0), reverse=True):
        rec = f.get("recommendation") or "Review finding."
        if rec in seen_recs:
            continue
        seen_recs.add(rec)
        remediation_items.append(f'''<div class="remedy"><div class="remedy-num">{len(remediation_items)+1:02d}</div><div><strong>{escape(str(f.get("finding", "Finding")))}</strong><p>{escape(rec)}</p></div><span>{badge(f.get("priority", "P4"), priority_class(f.get("priority", "P4")))}</span></div>''')
    remediation_html = "".join(remediation_items) or '<div class="empty">No remediation items available.</div>'

    cve_rows = "".join(
        f'''<tr><td><strong>{esc(item.get("cve"))}</strong></td><td>{esc(item.get("published"))}</td><td>{esc(item.get("last_modified"))}</td><td>{esc(item.get("description"), "No description")}</td></tr>'''
        for item in cve_findings[:25]
    )
    cve_table = f'''<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Published</th><th>Modified</th><th>Description</th></tr></thead><tbody>{cve_rows}</tbody></table></div>''' if cve_rows else '<div class="empty">CVE correlation was not asserted because reliable product identity was unavailable.</div>'

    host_name = host.get("hostname") or "Unknown host"
    os_name = host.get("edition") or host.get("operating_system") or "Unknown OS"
    build = host.get("build") or host.get("os_version") or "Unknown"
    arch = host.get("architecture") or "Unknown"
    target = scan[0].get("host") if scan else host.get("hostname") or "Unknown"

    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnTrack | Security Assessment</title>
<style>
:root{{--bg:#050914;--panel:#0b1220;--panel2:#0f1929;--panel3:#121f32;--line:#1d2c42;--text:#edf4ff;--muted:#8fa3bd;--blue:#36b7ff;--cyan:#55e6ff;--green:#48df78;--red:#ff5964;--orange:#ff9d35;--yellow:#ffd447;--purple:#a78bfa;--shadow:0 18px 50px rgba(0,0,0,.28)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:radial-gradient(900px 450px at 80% -5%,rgba(38,125,255,.16),transparent 65%),radial-gradient(700px 400px at -10% 20%,rgba(0,220,255,.07),transparent 65%),var(--bg);color:var(--text);font:14px Inter,Segoe UI,Arial,sans-serif}}.wrap{{max-width:1500px;margin:auto;padding:28px}}.muted{{color:var(--muted)}}
header{{display:flex;justify-content:space-between;gap:20px;align-items:center;padding:5px 0 22px;border-bottom:1px solid var(--line)}}.brand{{display:flex;gap:13px;align-items:center}}.shield{{width:44px;height:44px;border:1px solid #2b83c5;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,#102844,#091523);box-shadow:0 0 25px rgba(54,183,255,.12);font-size:21px}}.logo{{font-size:31px;font-weight:900;letter-spacing:-1.4px}}.logo span{{color:var(--blue)}}.sub{{color:var(--muted);margin-top:4px}}.header-right{{text-align:right}}.status{{display:inline-flex;gap:7px;align-items:center;padding:7px 11px;border:1px solid #205e43;border-radius:999px;background:#081b13;color:#63e68d;font-size:11px;font-weight:900;text-transform:uppercase;letter-spacing:.4px}}.dot{{width:7px;height:7px;background:var(--green);border-radius:50%;box-shadow:0 0 10px var(--green)}}.meta{{color:var(--muted);font-size:11px;margin-top:7px}}
.card{{background:linear-gradient(145deg,rgba(18,31,50,.96),rgba(8,16,28,.96));border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}}.pad{{padding:20px}}.hero{{display:grid;grid-template-columns:1.55fr .65fr;gap:16px;margin:20px 0 14px}}.hero-main{{padding:24px}}.eyebrow{{color:var(--cyan);font-size:10px;font-weight:900;letter-spacing:1.5px}}h1{{font-size:29px;letter-spacing:-.8px;margin:9px 0 7px}}.hero p{{color:#adbbcc;line-height:1.65;max-width:900px;margin:0}}.score-card{{padding:20px;display:flex;align-items:center;gap:18px}}.ring{{width:108px;height:108px;border-radius:50%;display:grid;place-items:center;position:relative;background:conic-gradient(var(--blue) {posture_angle}deg,#17263a 0)}}.ring:after{{content:"";position:absolute;inset:9px;border-radius:50%;background:#0b1421}}.ring-inner{{position:relative;z-index:2;text-align:center}}.score{{font-size:29px;font-weight:900}}.score small{{font-size:11px;color:var(--muted)}}.score-title{{font-size:15px;font-weight:900}}.score-note{{font-size:11px;color:var(--muted);line-height:1.5;margin-top:5px}}
.metrics{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:14px 0 18px}}.metric{{padding:17px}}.metric-label{{color:var(--muted);font-size:10px;font-weight:900;letter-spacing:.6px}}.metric-num{{font-size:29px;font-weight:900;margin:8px 0 2px}}.blue{{color:var(--blue)}}.p1c{{color:var(--red)}}.p2c{{color:var(--orange)}}.p3c{{color:var(--yellow)}}.p4c{{color:#7ec9ff}}.green{{color:var(--green)}}
.section-title{{display:flex;justify-content:space-between;align-items:end;margin:0 0 11px}}h2{{font-size:17px;margin:0}}.section-title span{{font-size:10px;color:var(--muted)}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}.grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}}.section{{margin-top:16px}}
.surface{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}.port-card{{background:#091321;border:1px solid var(--line);border-radius:13px;padding:16px;position:relative;overflow:hidden}}.port-card:before{{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--green)}}.port-card.filtered:before{{background:var(--yellow)}}.port-card.closed:before{{background:var(--red)}}.port-head{{display:flex;justify-content:space-between;align-items:center}}.port-number{{font-size:23px;font-weight:900}}.port-service{{font-weight:900;margin-top:12px}}.port-product{{font-size:11px;color:var(--muted);margin-top:4px;min-height:16px}}.port-foot{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px;color:var(--muted);font-size:10px}}
.badge{{display:inline-block;padding:5px 8px;border-radius:6px;font-size:9px;font-weight:900;letter-spacing:.3px}}.open{{background:#103b26;color:#65ec91}}.filtered{{background:#3c3208;color:#ffe17a}}.closed{{background:#43151d;color:#ff9ba2}}.p1{{background:#551820;color:#ff9ba2}}.p2{{background:#4f290c;color:#ffbd70}}.p3{{background:#514407;color:#ffe66f}}.p4{{background:#17365a;color:#8ed5ff}}.critical{{background:#551820;color:#ff9ba2}}.high{{background:#4f290c;color:#ffbd70}}.medium{{background:#514407;color:#ffe66f}}.low{{background:#214514;color:#a6efaa}}.info{{background:#17365a;color:#8ed5ff}}.confidence{{background:#183e61;color:#9bdbff}}
.bar-list{{display:grid;gap:14px}}.bar-label{{display:flex;justify-content:space-between;font-size:11px}}.bar{{height:10px;background:#182638;border-radius:99px;overflow:hidden;margin-top:7px}}.bar i{{display:block;height:100%;border-radius:99px}}.b1{{background:linear-gradient(90deg,#ff5964,#ff8d95)}}.b2{{background:linear-gradient(90deg,#ff7e27,#ffad4b)}}.b3{{background:linear-gradient(90deg,#e4bb22,#ffe066)}}.b4{{background:linear-gradient(90deg,#287bc4,#55c8ff)}}
.top-risk{{height:100%}}.risk-title{{font-size:17px;font-weight:900;margin-top:2px}}.risk-meta{{display:flex;gap:8px;flex-wrap:wrap;color:var(--muted);font-size:10px;margin-top:8px}}.risk-score{{font-size:25px;font-weight:900;margin-top:16px}}.risk-score span{{font-size:10px;color:var(--muted);font-weight:500}}.callout{{margin-top:12px;border-top:1px solid var(--line);padding-top:11px;color:#b9c8d8;font-size:12px;line-height:1.55}}
.hostgrid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.kv{{background:#091321;border:1px solid var(--line);border-radius:11px;padding:14px}}.kv small{{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}}.kv b{{font-size:12px;word-break:break-word}}
.finding-list{{display:grid;gap:11px}}.finding-card{{background:#091321;border:1px solid var(--line);border-radius:14px;padding:17px}}.finding-top{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}}.finding-title{{font-size:15px;font-weight:900}}.finding-meta{{font-size:10px;color:var(--muted);margin-top:6px}}.badges{{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}}.finding-score{{display:flex;align-items:baseline;gap:8px;margin-top:13px}}.finding-score strong{{font-size:25px}}.finding-score span{{color:var(--muted);font-size:10px}}.evidence-row{{display:grid;grid-template-columns:105px 1fr;gap:10px;margin-top:11px;padding-top:10px;border-top:1px solid var(--line)}}.evidence-row .label{{font-size:9px;color:var(--cyan);font-weight:900;letter-spacing:.7px}}.evidence-row p{{margin:0;color:#b9c7d6;font-size:11px;line-height:1.55}}.finding-foot{{display:flex;gap:18px;margin-top:12px;color:var(--muted);font-size:10px}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:560px}}th,td{{padding:11px;border-bottom:1px solid var(--line);text-align:left;font-size:11px;vertical-align:top}}th{{color:#9fb0c4;background:#0d1929;font-size:9px;text-transform:uppercase;letter-spacing:.6px}}tr:hover td{{background:#0d1a2a}}
.evidence{{display:flex;gap:12px;align-items:flex-start;border-radius:13px;padding:16px}}.evidence.warn{{border:1px solid #5a3b1d;background:linear-gradient(145deg,#21170d,#120d09)}}.evidence.good{{border:1px solid #20537a;background:linear-gradient(145deg,#0b1d30,#09131f)}}.evidence-icon{{font-size:18px}}.evidence h3{{font-size:13px;margin:0 0 5px}}.evidence p{{margin:0;color:#9fb0c4;font-size:11px;line-height:1.55}}.mono{{font:10px Consolas,monospace;color:#9fdcff;word-break:break-all;margin-top:8px}}
.remedy-list{{display:grid;gap:9px}}.remedy{{display:grid;grid-template-columns:34px 1fr auto;gap:11px;align-items:start;padding:12px;border:1px solid var(--line);border-radius:11px;background:#091321}}.remedy-num{{font-weight:900;color:var(--cyan)}}.remedy strong{{font-size:12px}}.remedy p{{margin:4px 0 0;color:#aebdcd;font-size:11px;line-height:1.5}}.empty{{color:var(--muted);padding:18px;text-align:center;border:1px dashed var(--line);border-radius:11px}}
.method{{padding:15px;border:1px solid #24405d;background:#091a2b;border-radius:13px;color:#b9c8d8;font-size:11px;line-height:1.6}}.method b{{color:#edf4ff}}footer{{margin-top:22px;border-top:1px solid var(--line);padding:17px 0;color:var(--muted);font-size:10px;line-height:1.6}}
@media(max-width:1150px){{.metrics{{grid-template-columns:repeat(3,1fr)}}.hero{{grid-template-columns:1fr}}.hostgrid{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:800px){{.grid2,.grid3{{grid-template-columns:1fr}}.surface{{grid-template-columns:1fr}}.metrics{{grid-template-columns:repeat(2,1fr)}}header{{display:block}}.header-right{{text-align:left;margin-top:12px}}}}@media(max-width:500px){{.metrics,.hostgrid{{grid-template-columns:1fr}}.wrap{{padding:16px}}h1{{font-size:24px}}.evidence-row{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff;color:#111}}.card,.finding-card,.port-card,.kv,.remedy{{box-shadow:none;background:#fff;border-color:#ccc}}.muted,.finding-meta,.risk-meta,.evidence-row p,.remedy p{{color:#444}}header{{border-color:#ccc}}}}
</style></head><body><div class="wrap">
<header><div class="brand"><div class="shield">🛡</div><div><div class="logo">Vuln<span>Track</span></div><div class="sub">Evidence-Based Vulnerability Assessment Platform</div></div></div><div class="header-right"><div class="status"><span class="dot"></span> Assessment Completed</div><div class="meta">{escape(generated)} · Target: {esc(target)}</div></div></header>

<section class="hero"><div class="card hero-main"><div class="eyebrow">EXECUTIVE SECURITY SUMMARY</div><h1>Security assessment of {escape(str(os_name))}</h1><p>VulnTrack observed <b>{actionable} actionable finding{'s' if actionable != 1 else ''}</b> and <b>{len(scan)} port observation{'s' if len(scan) != 1 else ''}</b>. The highest current priority is <b>{escape(str(top.get('finding') if top else 'No findings'))}</b>. CPE/CVE intelligence remains conservative and will not assert unsupported vulnerability attribution.</p></div><div class="card score-card"><div class="ring"><div class="ring-inner"><div class="score">{posture}<small>/100</small></div></div></div><div><div class="score-title">Security Posture</div><div class="score-note">{posture_label}<br>{total_findings} total observations · {cve_count} CVE correlations</div></div></div></section>

<section class="metrics"><div class="card metric"><div class="metric-label">ACTIONABLE FINDINGS</div><div class="metric-num blue">{actionable}</div><div class="muted">P1–P3 priorities</div></div><div class="card metric"><div class="metric-label">P1 CRITICAL</div><div class="metric-num p1c">{p1}</div><div class="muted">Immediate priority</div></div><div class="card metric"><div class="metric-label">P2 HIGH</div><div class="metric-num p2c">{p2}</div><div class="muted">Highest current risk</div></div><div class="card metric"><div class="metric-label">P3 MEDIUM</div><div class="metric-num p3c">{p3}</div><div class="muted">Review required</div></div><div class="card metric"><div class="metric-label">P4 / INFO</div><div class="metric-num p4c">{p4}</div><div class="muted">Observed / informational</div></div><div class="card metric"><div class="metric-label">CVE CORRELATIONS</div><div class="metric-num blue">{cve_count}</div><div class="muted">Evidence-backed</div></div></section>

<section class="section grid2"><div class="card pad"><div class="section-title"><h2>Risk Distribution</h2><span>Weighted by calculated VulnTrack risk score</span></div><div class="bar-list">{risk_bar('P1 Critical', 'P1', p1, 'b1')}{risk_bar('P2 High', 'P2', p2, 'b2')}{risk_bar('P3 Medium', 'P3', p3, 'b3')}{risk_bar('P4 Info', 'P4', p4, 'b4')}</div></div><div class="card pad top-risk"><div class="section-title"><h2>Top Risk Finding</h2><span>Highest calculated VulnTrack priority</span></div>{f'''<div class="risk-title">{esc(top.get('finding'))}</div><div class="risk-meta"><span>{escape(str(top.get('protocol','tcp')).upper())}/{esc(top.get('port'))}</span><span>{escape(str(top.get('exposure','NETWORK')))}</span><span>{escape(str(top.get('confidence','LOW')).upper())} CONFIDENCE</span>{badge(top.get('priority','P4'),priority_class(top.get('priority','P4')))}</div><div class="risk-score">{esc(top.get('risk_score',0))} <span>risk score</span></div><div class="callout">{escape(str(top.get('evidence') or top.get('recommendation') or 'Review finding evidence and recommendation.'))}</div>''' if top else '<div class="empty">No findings available.</div>'}</div></section>

<section class="section"><div class="section-title"><h2>Attack Surface</h2><span>{open_ports} open · {filtered_ports} filtered · {closed_ports} closed · {len(scan)} observed</span></div><div class="card pad"><div class="surface">{port_cards_html}</div></div></section>

<section class="section"><div class="section-title"><h2>Host Profile</h2><span>Observed endpoint evidence</span></div><div class="card pad hostgrid"><div class="kv"><small>Hostname</small><b>{esc(host_name)}</b></div><div class="kv"><small>Operating System</small><b>{esc(os_name)}</b></div><div class="kv"><small>Build</small><b>{esc(build)}</b></div><div class="kv"><small>Architecture</small><b>{esc(arch)}</b></div></div></section>

<section class="section"><div class="section-title"><h2>Security Findings</h2><span>{total_findings} observations · sorted by risk score</span></div><div class="finding-list">{findings_html}</div></section>

<section class="section grid2"><div class="card pad"><div class="section-title"><h2>Port Evidence</h2><span>Direct scan observations</span></div><div class="table-wrap"><table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th></tr></thead><tbody>{''.join(f'<tr><td><strong>{esc(x.get("port"))}</strong></td><td>{esc(x.get("protocol"))}</td><td>{badge(str(x.get("state","UNKNOWN")).upper(), "open" if str(x.get("state")).lower()=="open" else "filtered" if str(x.get("state")).lower()=="filtered" else "closed")}</td><td>{esc(x.get("service"))}</td><td>{esc(x.get("product"))}</td></tr>' for x in scan) or '<tr><td colspan="5">No observations.</td></tr>'}</tbody></table></div></div><div class="card pad"><div class="section-title"><h2>Assessment Method</h2><span>Evidence → confidence → priority</span></div><div class="method"><b>Risk model:</b> {escape(str(risk.get('risk_method','Severity × Evidence Confidence × Exposure')))}.<br><br><b>Posture score:</b> {posture}/100 is a portfolio-level indicator derived from the aggregate VulnTrack risk scores. It is <b>not CVSS</b> and is not an industry-standard severity rating.</div></div></section>

<section class="section grid2"><div class="card pad"><div class="section-title"><h2>CPE Intelligence</h2><span>Product identity confidence</span></div><div class="evidence {cpe_class}"><div class="evidence-icon">{'✓' if cpe_good else '⚠'}</div><div><h3>{escape(cpe_status)} · {escape(cpe_conf)}</h3><p>{escape(cpe_reason)}</p>{f'<div class="mono">Selected CPE: {escape(str(selected_cpe))}</div>' if selected_cpe else ''}</div></div></div><div class="card pad"><div class="section-title"><h2>CVE Intelligence</h2><span>Conservative correlation</span></div><div class="evidence {'good' if cve_count else 'warn'}"><div class="evidence-icon">{'✓' if cve_count else '⊘'}</div><div><h3>{cve_count} EVIDENCE-BACKED CORRELATION{'S' if cve_count != 1 else ''}</h3><p>{escape(cve_reason)}</p></div></div></div></section>

<section class="section"><div class="section-title"><h2>Remediation Priority</h2><span>Highest risk first</span></div><div class="card pad"><div class="remedy-list">{remediation_html}</div></div></section>

{f'<section class="section"><div class="section-title"><h2>CVE Correlations</h2><span>{cve_count} verified records</span></div><div class="card pad">{cve_table}</div></section>' if cve_count else ''}

<section class="section"><div class="method"><b>Security note:</b> VulnTrack intentionally avoids asserting a CVE when product/version evidence is insufficient. Risk scores are prioritization scores, not official CVSS scores. Run assessments only against systems you are authorized to assess.</div></section>
<footer><b>VulnTrack</b> — Evidence-based vulnerability assessment laboratory.<br>Target: {esc(target)} · {escape(str(os_name))} · Build {esc(build)} · {esc(arch)}</footer>
</div></body></html>'''

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    print(f"[+] Report generated: {OUT}")


if __name__ == "__main__":
    main()
