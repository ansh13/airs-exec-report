#!/usr/bin/env python3
"""
AIRS Executive Report  (Streamlit, cross-platform: Windows + macOS)
===================================================================
One page, three AIRS pillars, selectable time window:
    1. Model Scanning   (LIVE  — model-security-client SDK)
    2. Red-Teaming      (LIVE  — ai-red-teaming REST API)
    3. API-Intercept    (no reporting API — needs SCM CSV export)

AUTH: one service-account token for all SASE APIs. Credentials come from a JSON file
`credentials.json` in the folder you run from (used by all pillars):
    {"client_id": "svc@123.iam.panserviceaccount.com", "client_secret": "...", "tsg_id": "123"}
(tsg_id is optional — derived from client_id if omitted.)

RUN  (Python 3.12):
    pip install streamlit pandas model-security-client
    streamlit run scripts/exec_report.py
"""
import os, re, glob, json, uuid, csv, sys, subprocess, importlib, datetime as dt, urllib.request, urllib.parse, urllib.error, base64
from collections import Counter, defaultdict
csv.field_size_limit(sys.maxsize)   # log rows carry full scanned content in "Text Records"
import streamlit as st
import pandas as pd

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG — everything tunable lives here
# ══════════════════════════════════════════════════════════════════════════════
# API endpoints
SASE = "https://api.sase.paloaltonetworks.com"            # SASE management plane
AUTH = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"

# Credentials — a JSON file placed in the folder you run the script from (or next to the script).
# Format:  {"client_id": "svc@123.iam.panserviceaccount.com", "client_secret": "...", "tsg_id": "123"}
# tsg_id is optional — if omitted it is derived from the client_id.
CREDS_FILE = "credentials.json"

# API-Intercept CSV (SCM activity-log export) — same folder as above
CSV_DIRS = [os.path.dirname(os.path.abspath(__file__)), os.getcwd()]   # script dir first, then run dir
CSV_GLOB = "ai_security_airs_api_intercept*.csv"          # newest match wins
ENV_CSV  = "API_INTERCEPT_CSV"                            # optional explicit path override

# Cache lifetimes (seconds)
TTL_TOKEN = 1800                                          # OAuth token
TTL_DATA  = 600                                           # pillar data loaders

# Time-window selector
WINDOW_OPTIONS = [7, 30, 60, 90]                          # day choices in the sidebar
WINDOW_DEFAULT = 0                                        # index into WINDOW_OPTIONS (0 → 7 days)
# ══════════════════════════════════════════════════════════════════════════════


# ── 1. credentials — read from credentials.json ───────────────────────────────
def load_credentials():
    for d in CSV_DIRS:                                     # script dir first, then run dir
        p = os.path.join(d, CREDS_FILE)
        if os.path.isfile(p):
            c = json.load(open(p, encoding="utf-8"))
            m = re.search(r"@(\d+)\.", c.get("client_id", ""))
            tsg = str(c.get("tsg_id") or (m[1] if m else ""))
            # the model_security_client SDK reads credentials from these env vars
            os.environ["MODEL_SECURITY_CLIENT_ID"] = c["client_id"]
            os.environ["MODEL_SECURITY_CLIENT_SECRET"] = c["client_secret"]
            os.environ["TSG_ID"] = os.environ["MODEL_SECURITY_TSG_ID"] = tsg
            return {"client_id": c["client_id"], "client_secret": c["client_secret"], "tsg_id": tsg}
    return None


# ── 2. one OAuth token for the REST APIs (red-teaming) ────────────────────────
@st.cache_data(ttl=TTL_TOKEN)
def get_token():
    cid, sec, tsg = CREDS["client_id"], CREDS["client_secret"], CREDS["tsg_id"]
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": f"tsg_id:{tsg}"}).encode()
    req = urllib.request.Request(AUTH, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{cid}:{sec}".encode()).decode())
    return json.load(urllib.request.urlopen(req, timeout=30))["access_token"]


def api_get(path):
    req = urllib.request.Request(SASE + path)
    req.add_header("Authorization", "Bearer " + get_token())
    req.add_header("Accept", "application/json")
    return json.load(urllib.request.urlopen(req, timeout=60))


# ── 2b. install the Model Scanning SDK on demand (not on public PyPI) ──────────
# The model-security-client package lives on a private pip index. We fetch a
# short-lived authenticated index URL via OAuth, then pip-install into THIS env.
def install_model_security_sdk():
    req = urllib.request.Request(SASE + "/aims/mgmt/v1/pypi/authenticate")
    req.add_header("Authorization", "Bearer " + get_token())
    req.add_header("Accept", "application/json")
    index_url = json.load(urllib.request.urlopen(req, timeout=60))["url"]
    # Drop any broken public-PyPI stub first — its version=None poisons pip's
    # resolver and makes the real install fail. No-op if nothing is installed.
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "model-security-client"],
                   capture_output=True, text=True)
    cmd = [sys.executable, "-m", "pip", "install",
           "model-security-client[gcp]>=1.1.1,<2", "--extra-index-url", index_url]
    return subprocess.run(cmd, capture_output=True, text=True)


# ── 3. data loaders ───────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL_DATA)
def load_model_scanning(days):
    from model_security_client.api import ModelSecurityAPIClient
    c = ModelSecurityAPIClient(base_url=SASE + "/aims", timeout=60.0)
    d = lambda o: o.model_dump() if hasattr(o, "model_dump") else dict(o)
    now = dt.datetime.now(dt.timezone.utc); since = now - dt.timedelta(days=days)
    scans, skip = [], 0
    while True:
        page = [d(x) for x in c.list_scans(limit=100, skip=skip, start_time=since, end_time=now).scans]
        scans += page; skip += len(page)
        if len(page) < 100:
            break
    verd = Counter(str(s.get("eval_outcome", "?")).split(".")[-1] for s in scans)
    reasons = Counter()
    allowed_alerts = 0                          # allowed scans that still had violations
    for s in scans:
        if (s.get("eval_summary") or {}).get("rules_failed"):
            if str(s.get("eval_outcome", "")).split(".")[-1] == "ALLOWED":
                allowed_alerts += 1
            try:
                v = c.get_scan_violations(scan_uuid=uuid.UUID(str(s["uuid"])), limit=100)
                for x in v.violations:
                    reasons[str(d(x).get("rule_name") or d(x).get("name"))] += 1
            except Exception:
                pass
    return {"total": len(scans), "verd": verd, "reasons": reasons,
            "allowed_alerts": allowed_alerts,
            "models": len({s.get("model_uri") for s in scans})}


@st.cache_data(ttl=TTL_DATA)
def load_red_teaming(days):
    now = dt.datetime.now(dt.timezone.utc); since = now - dt.timedelta(days=days)
    targets = api_get("/ai-red-teaming/mgmt-plane/v1/target").get("data", [])
    scans = api_get("/ai-red-teaming/data-plane/v1/scan").get("data", [])
    def parse(x):
        try: return dt.datetime.fromisoformat(str(x).replace("Z", "+00:00"))
        except Exception: return None
    recent = [s for s in scans if parse(s.get("created_at")) and parse(s["created_at"]) >= since]
    rows = [{"Scan": s.get("name"), "Target type": s.get("target_type"),
             "Status": s.get("status"),
             "When": str(s.get("created_at", ""))[:10]} for s in recent]
    return {"targets": len(targets), "scans": len(recent),
            "targets_scanned": len({s.get("target_id") for s in recent}),
            "status": Counter(s.get("status") for s in recent), "rows": rows}


# ── 3b. API-Intercept loader (SCM activity-log CSV export) ────────────────────
# The Runtime Security scan API has no time-range query, but the SCM Log Viewer
# export ("Prisma AIRS AI Runtime Security API" log type) carries every scan event.
# Structure: ONE scan = MANY rows (one per detector subtype). Dedup by "Scan ID"
# for scan-level counts; attribute threats on rows where Vendor Severity fired.
def find_intercept_csv():
    if os.environ.get(ENV_CSV):
        p = os.path.expanduser(os.environ[ENV_CSV])
        return p if os.path.isfile(p) else None
    hits = []
    for d in CSV_DIRS:
        hits += glob.glob(os.path.join(d, CSV_GLOB))
    hits = sorted(set(hits), key=os.path.getmtime, reverse=True)
    return hits[0] if hits else None


def _parse_ts(s):
    s = (s or "").strip().replace(" UTC", "")
    try:
        return dt.datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


@st.cache_data(ttl=TTL_DATA)
def load_api_intercept(path, mtime, days):
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    scan = {}                      # scan_id -> (verdict, action, key_name, model, env)
                                   #   verdict/action aggregated with precedence across the scan's rows
    sev_rows = Counter()           # severity -> fired-row count
    gsev = defaultdict(Counter)    # guardrail -> {severity: count}  tenant-wide (excludes traffic)
    hit_scans = set()              # scans with >=1 detector hit
    tmin = tmax = None
    with open(path, newline="", encoding="utf-8", errors="ignore") as fh:
        r = csv.DictReader(fh)
        for row in r:
            ts = _parse_ts(row.get("Time Generated"))
            if ts is None or ts < since:
                continue
            tmin = ts if tmin is None or ts < tmin else tmin
            tmax = ts if tmax is None or ts > tmax else tmax
            sid = row.get("Scan ID")
            key_name = (row.get("API Key Name") or "").strip() \
                       or (row.get("AI Application Name") or "").strip()   # fallback for older exports
            verdict = row.get("Verdict", "").strip()
            action = row.get("Action", "").strip()
            prev = scan.get(sid)
            if prev:                            # a scan spans many rows; worst outcome wins
                if prev[0] == "malicious":
                    verdict = "malicious"
                if prev[1] == "block":
                    action = "block"
            scan[sid] = (verdict, action, key_name,
                         (row.get("AI Model Name") or "").strip(),
                         (row.get("AI App Environment") or "").strip())
            s = (row.get("Vendor Severity") or "").strip()
            if s and s != "LOG_SEVERITY_UNUSED":
                sev_rows[s.replace("LOG_SEVERITY_", "")] += 1
                hit_scans.add(sid)
                sub = (row.get("AI Incident Subtype") or "").strip()
                itype = (row.get("AI Incident Type") or "").strip()
                guard = sub or (itype.replace("ai-", "") if itype and itype != "ai-traffic" else "")
                if guard:                       # real guardrail only — skip generic traffic
                    gsev[guard][s.replace("LOG_SEVERITY_", "")] += 1
    verd = Counter(v[0] for v in scan.values())
    act = Counter(v[1] for v in scan.values())
    apps = Counter(v[2] for v in scan.values() if v[2] and v[2] != "None")
    models = Counter(v[3] for v in scan.values() if v[3] and v[3] != "None")
    envs = Counter(v[4] for v in scan.values() if v[4])
    return {"total": len(scan), "malicious": verd.get("malicious", 0),
            "benign": verd.get("benign", 0),
            "blocked": act.get("block", 0), "allowed": act.get("allow", 0),
            "hit_scans": len(hit_scans), "apps": apps, "models": models, "envs": envs,
            "sev": sev_rows, "guardrails": dict(gsev),
            "span": (tmin.date().isoformat(), tmax.date().isoformat()) if tmin else None}


# ── 4. UI ─────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="EXL-AIRS Weekly Report", layout="wide")
# Hide all Streamlit chrome (Deploy button, top-right menu, status icon, header
# bar, and footer) for everyone, regardless of how the app is launched —
# self-contained, does not rely on a .streamlit/config.toml.
st.markdown(
    """
    <style>
      [data-testid='stAppDeployButton'] {display: none;}   /* "Deploy" button      */
      [data-testid='stToolbar']         {display: none;}   /* top-right toolbar     */
      [data-testid='stStatusWidget']    {display: none;}   /* "Running…" status icon */
      [data-testid='stDecoration']      {display: none;}   /* colored top gradient  */
      #MainMenu                         {visibility: hidden;}  /* hamburger menu    */
      header                            {visibility: hidden;}  /* whole header bar  */
      footer                            {visibility: hidden;}  /* "Made with Streamlit" */
    </style>
    """,
    unsafe_allow_html=True,
)
st.title("EXL-AIRS Weekly Report")

CREDS = load_credentials()
if not CREDS:
    st.error(f"No credentials. Put **{CREDS_FILE}** in the folder you run this script from, "
             'with: {"client_id": "...", "client_secret": "...", "tsg_id": "..."}')
    st.stop()

days = WINDOW_OPTIONS[WINDOW_DEFAULT]   # fixed time window (no user selector)
since_str = (dt.date.today() - dt.timedelta(days=days)).isoformat()
st.caption(f"Tenant {CREDS['tsg_id']}  ·  Last {days} days (since {since_str})  ·  Generated {dt.date.today()}")

# --- 1. API-Intercept ---
st.header("API-Intercept (AI Runtime Security)")
csv_path = find_intercept_csv()
if not csv_path:
    st.warning("No SCM activity-log export found. The Runtime Security scan API has no time-range query, "
               "so this pillar reads the SCM Log Viewer **CSV export** (log type *Prisma AIRS AI Runtime "
               "Security API*). Place it in the folder you run this script from (name starts "
               "`ai_security_airs_api_intercept`) or set `API_INTERCEPT_CSV`.")
else:
    st.caption(f"Source: `{os.path.basename(csv_path)}`")
    with st.spinner("Parsing API-intercept log…"):
        ai = load_api_intercept(csv_path, os.path.getmtime(csv_path), days)
    if ai["span"]:
        st.caption(f"Events span {ai['span'][0]} → {ai['span'][1]}")
    # guardrail detections across the whole tenant (traffic excluded) — shown first
    st.caption("Top guardrail detections (tenant-wide)")
    if ai["guardrails"]:
        totals = Counter({g: sum(s.values()) for g, s in ai["guardrails"].items()})
        st.bar_chart(pd.DataFrame(totals.most_common(8), columns=["Guardrail", "Detections"]).set_index("Guardrail"),
                     horizontal=True)
    else:
        st.info("No guardrail detections in this export (only generic traffic events, which are excluded). "
                "Use the detailed activity-log export to see per-guardrail detections.")
    a, b, cc, dd = st.columns(4)
    a.metric("Total scans", f"{ai['total']:,}")
    b.metric("Malicious", f"{ai['malicious']:,}")
    cc.metric("Benign", f"{ai['benign']:,}")
    dd.metric("Blocked", f"{ai['blocked']:,}")
    if ai["apps"]:
        st.caption("Top API keys (by scans)")
        st.dataframe(pd.DataFrame(ai["apps"].most_common(6), columns=["API Key Name", "Scans"]),
                     use_container_width=True, hide_index=True)

st.divider()

# --- 2. Model Scanning ---
st.header("Model Scanning")
try:
    with st.spinner("Loading model scans…"):
        ms = load_model_scanning(days)
except ModuleNotFoundError:
    ms = None
    if st.session_state.get("sdk_install_tried"):
        # already auto-installed once this session and it still won't import
        st.warning("Model Scanning unavailable: the `model-security-client` SDK could not be made "
                   "importable. It supports Python 3.11–3.13 (not 3.14) — run the dashboard in e.g. a "
                   "3.12 venv. The other two pillars are unaffected.")
    else:
        st.session_state["sdk_install_tried"] = True        # guard: install at most once per session
        with st.spinner("Model Scanning SDK not found — installing it automatically…"):
            try:
                out = install_model_security_sdk()
            except Exception as e:
                st.warning(f"Model Scanning unavailable — auto-install could not start: {e}")
            else:
                if out.returncode == 0:
                    importlib.invalidate_caches()           # make the fresh package importable
                    st.cache_data.clear()
                    st.rerun()                              # reload; import should now succeed
                else:
                    st.warning("Model Scanning unavailable — auto-install failed "
                               "(the SDK supports Python 3.11–3.13, not 3.14). "
                               "The other two pillars are unaffected.")
                    st.code((out.stdout + "\n" + out.stderr)[-3000:])
except Exception as e:
    ms = None
    st.warning(f"Model Scanning unavailable: {e}")
if ms:
    v = ms["verd"]
    a, b, cc, dd, ee = st.columns(5)
    a.metric("Total scans", ms["total"])
    b.metric("Allowed", v.get("ALLOWED", 0))
    cc.metric("Allowed w/ alerts", ms["allowed_alerts"])
    dd.metric("Blocked", v.get("BLOCKED", 0))
    ee.metric("Unique models", ms["models"])
    if ms["reasons"]:
        st.caption("Top violation reasons (occurrences)")
        st.bar_chart(pd.DataFrame(ms["reasons"].most_common(6), columns=["Rule", "Count"]).set_index("Rule"),
                     horizontal=True)
    else:
        st.info("No violations in this window.")

st.divider()

# --- 3. Red-Teaming ---
st.header("Red-Teaming")
try:
    with st.spinner("Loading red-teaming…"):
        rt = load_red_teaming(days)
except urllib.error.HTTPError as e:
    rt = None
    if e.code == 401:
        st.warning("Red-Teaming unavailable (HTTP 401): this service account isn't authorized for the "
                   "AI Red-Teaming API. Grant it red-teaming access, or it may be entitled only for model scanning.")
    else:
        st.warning(f"Red-Teaming unavailable (HTTP {e.code}).")
except Exception as e:
    rt = None
    st.warning(f"Red-Teaming unavailable: {e}")
if rt:
    a, b, cc = st.columns(3)
    a.metric("Targets configured", rt["targets"])
    b.metric("Scans run", rt["scans"])
    cc.metric("Targets scanned", rt["targets_scanned"])
    if rt["rows"]:
        st.caption("Scans in window")
        st.dataframe(pd.DataFrame(rt["rows"]), use_container_width=True, hide_index=True)
    else:
        st.info(f"No red-teaming scans in the last {days} days.")

st.divider()
if st.button("Refresh data"):
    st.cache_data.clear()
    st.rerun()
