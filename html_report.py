#!/usr/bin/env python3
"""
AIRS Executive Report — standalone HTML (no Streamlit).

Generates one self-contained HTML page covering the three Prisma AIRS pillars,
mirroring the Streamlit exec_report.py but rendered to a static file:

  1. API-Intercept (AI Runtime Security) — OFFLINE, from an SCM Log Viewer CSV
     export. Per-key breakdown: requests (request/response split), benign vs.
     violations, blocked vs. alert, and reason-of-violation.
  2. Model Scanning — LIVE, via the model-security-client SDK.
  3. Red-Teaming — LIVE, via the AI Red-Teaming REST API.

The two live pillars need a service-account `credentials.json` (same format as
example-credentials.json) in this folder, network access, and — for Model
Scanning — the private SDK. Each degrades gracefully to an "unavailable" note
if its prerequisites are missing; the offline CSV pillar always renders.

Usage:
    python3 html_report.py                         # newest CSV in dir/cwd, last 7 days
    python3 html_report.py export.csv --days 30
    python3 html_report.py export.csv --group-by "AI Application Name"
"""
import argparse
import base64
import csv
import datetime as dt
import glob
import importlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, defaultdict

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

# ── config ────────────────────────────────────────────────────────────────────
SASE = "https://api.sase.paloaltonetworks.com"
AUTH = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
CREDS_FILE = "credentials.json"
CSV_GLOB = "ai_security_airs_api_intercept*.csv"
ENV_CSV = "API_INTERCEPT_CSV"

VIOLATION_VERDICT = "malicious"
BLOCK_ACTION = "block"
SUMMARY_TYPE = "ai-traffic"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_TOKEN = None


# ── auth + live API helpers (ported from exec_report.py) ───────────────────────
def load_credentials(explicit=None):
    candidates = ([explicit] if explicit else []) + \
                 [os.path.join(d, CREDS_FILE) for d in (SCRIPT_DIR, os.getcwd())]
    for p in candidates:
        if p and os.path.isfile(p):
            c = json.load(open(p, encoding="utf-8"))
            m = re.search(r"@(\d+)\.", c.get("client_id", ""))
            tsg = str(c.get("tsg_id") or (m[1] if m else ""))
            os.environ["MODEL_SECURITY_CLIENT_ID"] = c["client_id"]
            os.environ["MODEL_SECURITY_CLIENT_SECRET"] = c["client_secret"]
            os.environ["TSG_ID"] = os.environ["MODEL_SECURITY_TSG_ID"] = tsg
            return {"client_id": c["client_id"], "client_secret": c["client_secret"], "tsg_id": tsg}
    return None


def get_token(creds):
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    body = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "scope": f"tsg_id:{creds['tsg_id']}"}).encode()
    req = urllib.request.Request(AUTH, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Authorization", "Basic " + base64.b64encode(
        f"{creds['client_id']}:{creds['client_secret']}".encode()).decode())
    _TOKEN = json.load(urllib.request.urlopen(req, timeout=30))["access_token"]
    return _TOKEN


def api_get(creds, path):
    req = urllib.request.Request(SASE + path)
    req.add_header("Authorization", "Bearer " + get_token(creds))
    req.add_header("Accept", "application/json")
    return json.load(urllib.request.urlopen(req, timeout=60))


def install_model_security_sdk(creds):
    req = urllib.request.Request(SASE + "/aims/mgmt/v1/pypi/authenticate")
    req.add_header("Authorization", "Bearer " + get_token(creds))
    req.add_header("Accept", "application/json")
    index_url = json.load(urllib.request.urlopen(req, timeout=60))["url"]
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "model-security-client"],
                   capture_output=True, text=True)
    cmd = [sys.executable, "-m", "pip", "install",
           "model-security-client[gcp]>=1.1.1,<2", "--extra-index-url", index_url]
    return subprocess.run(cmd, capture_output=True, text=True)


def load_model_scanning(creds, days):
    try:
        from model_security_client.api import ModelSecurityAPIClient
    except ModuleNotFoundError:
        out = install_model_security_sdk(creds)
        if out.returncode != 0:
            raise RuntimeError("model-security-client SDK install failed "
                               "(needs Python 3.11–3.13, not 3.14).")
        importlib.invalidate_caches()
        from model_security_client.api import ModelSecurityAPIClient
    c = ModelSecurityAPIClient(base_url=SASE + "/aims", timeout=60.0)
    dd = lambda o: o.model_dump() if hasattr(o, "model_dump") else dict(o)
    now = dt.datetime.now(dt.timezone.utc); since = now - dt.timedelta(days=days)
    scans, skip = [], 0
    while True:
        page = [dd(x) for x in c.list_scans(limit=100, skip=skip,
                                            start_time=since, end_time=now).scans]
        scans += page; skip += len(page)
        if len(page) < 100:
            break
    verd = Counter(str(s.get("eval_outcome", "?")).split(".")[-1] for s in scans)
    reasons = Counter(); allowed_alerts = 0
    for s in scans:
        if (s.get("eval_summary") or {}).get("rules_failed"):
            if str(s.get("eval_outcome", "")).split(".")[-1] == "ALLOWED":
                allowed_alerts += 1
            try:
                v = c.get_scan_violations(scan_uuid=uuid.UUID(str(s["uuid"])), limit=100)
                for x in v.violations:
                    reasons[str(dd(x).get("rule_name") or dd(x).get("name"))] += 1
            except Exception:
                pass
    return {"total": len(scans), "verd": verd, "reasons": reasons,
            "allowed_alerts": allowed_alerts,
            "models": len({s.get("model_uri") for s in scans})}


def load_red_teaming(creds, days):
    now = dt.datetime.now(dt.timezone.utc); since = now - dt.timedelta(days=days)
    targets = api_get(creds, "/ai-red-teaming/mgmt-plane/v1/target").get("data", [])
    scans = api_get(creds, "/ai-red-teaming/data-plane/v1/scan").get("data", [])

    def parse(x):
        try:
            return dt.datetime.fromisoformat(str(x).replace("Z", "+00:00"))
        except Exception:
            return None
    recent = [s for s in scans if parse(s.get("created_at")) and parse(s["created_at"]) >= since]
    rows = [{"Scan": s.get("name"), "Target type": s.get("target_type"),
             "Status": s.get("status"), "When": str(s.get("created_at", ""))[:10]}
            for s in recent]
    return {"targets": len(targets), "scans": len(recent),
            "targets_scanned": len({s.get("target_id") for s in recent}),
            "status": Counter(s.get("status") for s in recent), "rows": rows}


# ── API-Intercept (offline CSV) ────────────────────────────────────────────────
def norm(row, key):
    return (row.get(key) or "").strip()


def direction(row):
    if norm(row, "Is Prompt").lower() == "true":
        return "request"
    if norm(row, "Is Response").lower() == "true":
        return "response"
    return "other"


def reason_label(itype, subtype):
    if itype and subtype:
        return f"{itype} / {subtype}"
    return itype or subtype or "(unspecified)"


def find_csv(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    if os.environ.get(ENV_CSV):
        p = os.path.expanduser(os.environ[ENV_CSV])
        return p if os.path.isfile(p) else None
    for d in (SCRIPT_DIR, os.getcwd()):
        hits = sorted(glob.glob(os.path.join(d, CSV_GLOB)), key=os.path.getmtime)
        if hits:
            return hits[-1]
    return None


TIME_COL = "Time Generated"


def parse_log_time(s):
    """Parse an SCM log timestamp like '2026-11-16 11:35:27 UTC' -> aware UTC datetime."""
    s = (s or "").strip().replace(" UTC", "")
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def load_intercept(csv_path, group_col, days=None):
    agg = {k: Counter() for k in
           ("total", "req_total", "resp_total", "benign", "violations",
            "viol_req", "viol_resp", "blocked", "alerted")}
    reasons = defaultdict(lambda: defaultdict(Counter))
    rows_read = 0
    rows_total = 0
    rows_skipped = 0
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        required = {group_col, "Verdict", "Action", "AI Incident Type",
                    "AI Incident Subtype", "Is Prompt", "Is Response"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"ERROR: CSV missing expected columns: {sorted(missing)}")
        # Date-window filter: only applied when --days is set AND the export has a
        # timestamp column. Older exports without it fall back to no filtering.
        cutoff = None
        if days is not None and TIME_COL in (reader.fieldnames or []):
            cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        for row in reader:
            rows_total += 1
            if cutoff is not None:
                ts = parse_log_time(row.get(TIME_COL))
                if ts is not None and ts < cutoff:
                    rows_skipped += 1
                    if rows_total % 250_000 == 0:
                        print(f"  ...processed {rows_total:,} rows", file=sys.stderr)
                    continue
            rows_read += 1
            grp = norm(row, group_col) or "(unknown)"
            itype = norm(row, "AI Incident Type")
            verdict = norm(row, "Verdict").lower()
            action = norm(row, "Action").lower()
            d = direction(row)
            if itype == SUMMARY_TYPE:
                agg["total"][grp] += 1
                if d == "request":
                    agg["req_total"][grp] += 1
                elif d == "response":
                    agg["resp_total"][grp] += 1
                if verdict == VIOLATION_VERDICT:
                    agg["violations"][grp] += 1
                    if d == "request":
                        agg["viol_req"][grp] += 1
                    elif d == "response":
                        agg["viol_resp"][grp] += 1
                    if action == BLOCK_ACTION:
                        agg["blocked"][grp] += 1
                    else:
                        agg["alerted"][grp] += 1
                else:
                    agg["benign"][grp] += 1
            elif itype and verdict == VIOLATION_VERDICT:
                c = reasons[grp][reason_label(itype, norm(row, "AI Incident Subtype"))]
                c["total"] += 1
                c[d] += 1
                c["block" if action == BLOCK_ACTION else "allow"] += 1
            if rows_total % 250_000 == 0:
                print(f"  ...processed {rows_total:,} rows", file=sys.stderr)
    return agg, reasons, rows_read, rows_total, rows_skipped


# ── HTML ───────────────────────────────────────────────────────────────────────
def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def card(label, value, cls=""):
    return (f'<div class="card"><div class="k">{esc(label)}</div>'
            f'<div class="v {cls}">{value}</div></div>')


def intercept_section(group_col, csv_name, rows_read, agg, reasons,
                      days=None, rows_total=None, rows_skipped=None):
    g_total = agg["total"]
    groups = sorted(g_total, key=lambda g: g_total[g], reverse=True)
    tot = sum(g_total.values()); ben = sum(agg["benign"].values())
    vio = sum(agg["violations"].values()); blk = sum(agg["blocked"].values())
    body = []
    for g in groups:
        rlist = sorted(reasons[g].items(), key=lambda kv: kv[1]["total"], reverse=True)
        if rlist:
            items = "".join(
                f'<li><span class="rname">{esc(r)}</span>'
                f'<span class="rc">{c["total"]} '
                f'<em class="dir">(req {c["request"]} · resp {c["response"]})</em> '
                f'<em class="blk">▰ {c["block"]} blocked</em> · '
                f'<em class="alw">▰ {c["allow"]} alert</em></span></li>'
                for r, c in rlist)
            reasons_cell = f'<ul class="reasons">{items}</ul>'
        else:
            reasons_cell = '<span class="none">— no violations —</span>'
        body.append(f"""
        <tr>
          <td class="app">{esc(g)}</td>
          <td class="num">{g_total[g]:,}<span class="sub2">{agg["req_total"][g]:,} req · {agg["resp_total"][g]:,} resp</span></td>
          <td class="num benign">{agg["benign"][g]:,}</td>
          <td class="num viol">{agg["violations"][g]:,}<span class="sub2">{agg["viol_req"][g]:,} req · {agg["viol_resp"][g]:,} resp</span></td>
          <td class="num block">{agg["blocked"][g]:,}</td>
          <td class="num alert">{agg["alerted"][g]:,}</td>
          <td>{reasons_cell}</td>
        </tr>""")
    # Window note: explain whether the CSV was date-filtered to the --days window.
    if days is None:
        window_note = ""
    elif rows_skipped:
        window_note = (f" · last {days} days "
                       f"({rows_skipped:,} of {rows_total:,} rows outside window excluded)")
    else:
        window_note = f" · last {days} days"
    return f"""
  <h2>API-Intercept (AI Runtime Security)</h2>
  <p class="src">Source: <strong>{esc(csv_name)}</strong> · grouped by <strong>{esc(group_col)}</strong> · {rows_read:,} log rows · {len(groups)} groups{window_note}</p>
  <div class="cards">
    {card("Total Requests", f"{tot:,}")}
    {card("Benign", f"{ben:,}", "benign")}
    {card("Violations", f"{vio:,}", "viol")}
    {card("Blocked", f"{blk:,}", "block")}
  </div>
  <table>
    <thead><tr>
      <th>{esc(group_col)}</th><th>Requests</th><th>Benign</th><th>Violations</th>
      <th>Blocked</th><th>Alert only</th><th>Reason of violation</th>
    </tr></thead>
    <tbody>{''.join(body)}</tbody>
  </table>"""


def model_scanning_section(ms, err):
    if ms is None:
        return f'<h2>Model Scanning</h2><p class="na">Unavailable — {esc(err)}</p>'
    v = ms["verd"]
    reasons = ""
    if ms["reasons"]:
        items = "".join(f'<li><span class="rname">{esc(r)}</span>'
                        f'<span class="rc">{n}</span></li>'
                        for r, n in ms["reasons"].most_common(8))
        reasons = f'<p class="src">Top violation reasons (occurrences)</p><ul class="reasons wide">{items}</ul>'
    else:
        reasons = '<p class="na">No violations in this window.</p>'
    return f"""
  <h2>Model Scanning</h2>
  <div class="cards">
    {card("Total scans", f"{ms['total']:,}")}
    {card("Allowed", f"{v.get('ALLOWED', 0):,}", "benign")}
    {card("Allowed w/ alerts", f"{ms['allowed_alerts']:,}", "alert")}
    {card("Blocked", f"{v.get('BLOCKED', 0):,}", "block")}
    {card("Unique models", f"{ms['models']:,}")}
  </div>
  {reasons}"""


def red_teaming_section(rt, err):
    if rt is None:
        return f'<h2>Red-Teaming</h2><p class="na">Unavailable — {esc(err)}</p>'
    table = ""
    if rt["rows"]:
        trs = "".join(
            f'<tr><td class="app">{esc(r["Scan"])}</td><td>{esc(r["Target type"])}</td>'
            f'<td>{esc(r["Status"])}</td><td class="num">{esc(r["When"])}</td></tr>'
            for r in rt["rows"])
        table = (f'<p class="src">Scans in window</p><table><thead><tr>'
                 f'<th>Scan</th><th>Target type</th><th>Status</th><th>When</th>'
                 f'</tr></thead><tbody>{trs}</tbody></table>')
    else:
        table = '<p class="na">No red-teaming scans in this window.</p>'
    return f"""
  <h2>Red-Teaming</h2>
  <div class="cards">
    {card("Targets configured", f"{rt['targets']:,}")}
    {card("Scans run", f"{rt['scans']:,}")}
    {card("Targets scanned", f"{rt['targets_scanned']:,}")}
  </div>
  {table}"""


def render_html(title, tenant, days, intercept_html, ms_html, rt_html):
    since = (dt.date.today() - dt.timedelta(days=days)).isoformat()
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0f172a; color:#e2e8f0;
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:32px; }}
  h1 {{ font-size:24px; margin:0 0 4px; color:#f8fafc; }}
  h2 {{ font-size:17px; margin:40px 0 12px; color:#f1f5f9; border-bottom:1px solid #334155; padding-bottom:8px; }}
  .caption {{ color:#94a3b8; margin:0 0 8px; font-size:13px; }}
  .src {{ color:#94a3b8; margin:14px 0 8px; font-size:13px; }}
  .na {{ color:#f59e0b; margin:12px 0; font-size:13px; background:#1e293b; border:1px solid #334155;
        border-left:3px solid #f59e0b; border-radius:8px; padding:12px 14px; }}
  .live {{ font-size:11px; color:#34d399; vertical-align:middle; margin-left:6px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:8px; }}
  .card {{ background:#1e293b; border:1px solid #334155; border-radius:12px; padding:16px 20px; min-width:150px; }}
  .card .k {{ color:#94a3b8; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  .card .v {{ font-size:26px; font-weight:700; margin-top:4px; }}
  .v.viol {{ color:#fbbf24; }} .v.block {{ color:#f87171; }} .v.benign {{ color:#34d399; }} .v.alert {{ color:#60a5fa; }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b; border:1px solid #334155; border-radius:12px; overflow:hidden; margin-top:4px; }}
  th,td {{ padding:12px 14px; text-align:left; border-bottom:1px solid #334155; vertical-align:top; }}
  th {{ background:#111827; color:#cbd5e1; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  tr:last-child td {{ border-bottom:none; }}
  td.app {{ font-weight:600; color:#f1f5f9; white-space:nowrap; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }}
  .sub2 {{ display:block; font-size:11px; color:#64748b; font-weight:400; }}
  .benign {{ color:#34d399; }} .viol {{ color:#fbbf24; }} .block {{ color:#f87171; }} .alert {{ color:#60a5fa; }}
  ul.reasons {{ margin:0; padding:0; list-style:none; }}
  ul.reasons.wide {{ max-width:640px; }}
  ul.reasons li {{ display:flex; justify-content:space-between; gap:16px; padding:3px 0; border-bottom:1px solid #1e293b; }}
  .rname {{ color:#e2e8f0; }} .rc {{ color:#94a3b8; font-variant-numeric:tabular-nums; white-space:nowrap; }}
  em.dir {{ color:#94a3b8; font-style:normal; }} em.blk {{ color:#f87171; font-style:normal; }} em.alw {{ color:#60a5fa; font-style:normal; }}
  .none {{ color:#64748b; font-style:italic; }}
</style></head><body>
  <h1>{esc(title)}</h1>
  <p class="caption">Tenant {esc(tenant)} · Last {days} days (since {since}) · Generated {dt.date.today()}</p>
  {intercept_html}
  {ms_html}
  {rt_html}
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Standalone AIRS executive HTML report")
    ap.add_argument("csv_path", nargs="?", help="API-Intercept CSV (default: newest in dir/cwd)")
    ap.add_argument("--group-by", default="API Key Name", help="Column to group API-Intercept by")
    ap.add_argument("--days", type=int, default=7, help="Time window for live pillars (default: 7)")
    ap.add_argument("--creds", default=None, help="Path to credentials.json (default: look in dir/cwd)")
    ap.add_argument("--out", default=os.path.join(SCRIPT_DIR, "airs_report.html"),
                    help="Output HTML path")
    args = ap.parse_args()

    # Pillar 1 — API-Intercept (offline, always attempted)
    csv_path = find_csv(args.csv_path)
    if csv_path:
        agg, reasons, rows_read, rows_total, rows_skipped = load_intercept(
            csv_path, args.group_by, args.days)
        intercept_html = intercept_section(args.group_by, os.path.basename(csv_path),
                                           rows_read, agg, reasons,
                                           days=args.days, rows_total=rows_total,
                                           rows_skipped=rows_skipped)
    else:
        intercept_html = (f'<h2>API-Intercept (AI Runtime Security)</h2>'
                          f'<p class="na">No CSV found. Pass a path or place a '
                          f'<code>{CSV_GLOB}</code> file here.</p>')

    # Live pillars — need credentials.json + network; SDK for model scanning.
    creds = load_credentials(args.creds)
    ms = rt = None
    ms_err = rt_err = "no credentials.json found"
    if creds:
        try:
            ms = load_model_scanning(creds, args.days)
        except Exception as e:
            ms_err = str(e) or e.__class__.__name__
        try:
            rt = load_red_teaming(creds, args.days)
        except urllib.error.HTTPError as e:
            rt_err = (f"HTTP {e.code} — service account not authorized for the "
                      f"AI Red-Teaming API") if e.code == 401 else f"HTTP {e.code}"
        except Exception as e:
            rt_err = str(e) or e.__class__.__name__

    html = render_html(
        "AIRS Executive Report",
        creds["tsg_id"] if creds else "—",
        args.days,
        intercept_html,
        model_scanning_section(ms, ms_err),
        red_teaming_section(rt, rt_err),
    )
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Wrote {args.out}")
    if not creds:
        print("NOTE: Model Scanning & Red-Teaming are blank — add credentials.json "
              "(see example-credentials.json) and re-run.")


if __name__ == "__main__":
    main()
