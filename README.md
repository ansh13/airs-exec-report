# AIRS Executive Report

A single-page **Streamlit** dashboard that pulls together the three Prisma AIRS pillars into one executive-level view, for a selectable time window:

| Pillar | Source | Mode |
|---|---|---|
| **API-Intercept** (AI Runtime Security) | SCM Log Viewer CSV export | Offline (CSV) |
| **Model Scanning** | `model-security-client` SDK | Live API |
| **Red-Teaming** | AI Red-Teaming REST API | Live API |

> A great tool for Prisma AIRS, built by the TME team.

Cross-platform — runs on both Windows and macOS.

---

## Why these three run differently

- **Model Scanning** and **Red-Teaming** have queryable APIs, so the dashboard pulls them live over a time window.
- **API-Intercept** (AI Runtime Security) has **no time-range query API**, so this pillar reads an SCM **Log Viewer CSV export** instead. One scan = many CSV rows (one per detector subtype); the script dedupes by `Scan ID` for scan-level counts.

---

## Prerequisites

- Python 3.11, 3.12, or 3.13 (the Model Scanning SDK does not support 3.14)
- A Prisma SASE **service account** with access to the AIRS APIs
- (Optional, for the API-Intercept pillar) an SCM activity-log CSV export

### Install (use a virtual environment)

A virtual environment keeps these packages isolated and avoids the macOS
"externally-managed-environment" (PEP 668) error. **Create it with Python 3.11–3.13**
(not 3.14, or the Model Scanning SDK won't install).

**macOS / Linux**

```bash
# use an explicit 3.12 (or 3.11/3.13) so you don't accidentally get 3.14
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Windows (Command Prompt)**

```bat
py -3.12 -m venv .venv
.\.venv\Scripts\activate.bat
pip install -r requirements.txt
```

Once active, your prompt shows `(.venv)`. Re-activate it (the `source ...` /
`Activate` line) in each new terminal before running the app. Run `deactivate`
when you're done.

> **The `model-security-client` SDK is optional and auto-installs.** It powers only the **Model Scanning** pillar, and it is **not on public PyPI** — it installs from the Palo Alto private pip index. If it isn't present when you open the dashboard, the app **automatically fetches the private index URL (using your `credentials.json`) and pip-installs the SDK into the running environment, then reloads** — no action needed. If the install can't succeed (most commonly because you're on **Python 3.14**, which the SDK doesn't support), the Model Scanning section shows a notice and the other two pillars keep working. The SDK supports Python **3.11–3.13**.
>
> If you ever need to install it manually, obtain the private index URL via the OAuth exchange, then:
> ```bash
> # 1) bearer token
> TOKEN=$(curl -s -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
>   -u "CLIENT_ID:CLIENT_SECRET" -d "grant_type=client_credentials" -d "scope=tsg_id:TSG_ID" \
>   | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
> # 2) exchange for the pip index URL
> curl -s -H "Authorization: Bearer $TOKEN" \
>   "https://api.sase.paloaltonetworks.com/aims/mgmt/v1/pypi/authenticate"
> # 3) install from that index
> pip install "model-security-client[gcp]>=1.1.1,<2" --extra-index-url <URL_FROM_STEP_2>
> ```

---

## Setup

### 1. Credentials

Copy the example file and fill in your real service-account values:

```bash
cp example-credentials.json credentials.json
```

```json
{
  "client_id": "svc@123456789.iam.panserviceaccount.com",
  "client_secret": "YOUR_SERVICE_ACCOUNT_SECRET",
  "tsg_id": "123456789"
}
```

- `tsg_id` is **optional** — if omitted, it is derived from the numeric part of `client_id`.
- The same single token is used for all SASE API calls.
- `credentials.json` is **git-ignored** — it will never be committed. Only `example-credentials.json` is tracked.

### 2. (Optional) API-Intercept CSV

To populate the API-Intercept pillar, export the log from SCM:

> **SCM → Log Viewer → log type _Prisma AIRS AI Runtime Security API_ → Export (CSV)**

Then either:

- drop the file next to the script (its name must start with `ai_security_airs_api_intercept`), **or**
- point the script at it explicitly:

  ```bash
  export API_INTERCEPT_CSV=/path/to/your/export.csv
  ```

If no CSV is found, the other two pillars still work — this pillar just shows a notice.

---

## Where the script looks for files

The script searches for `credentials.json` and the API-Intercept CSV in this order:

1. **The script's own folder** (where `exec_report.py` lives)
2. The directory you launched the command from

So the simplest setup is to keep `credentials.json` and the CSV **in the same folder as `exec_report.py`**.

The `API_INTERCEPT_CSV` environment variable overrides the CSV search entirely.

---

## Run

```bash
streamlit run exec_report.py
```

Streamlit opens the dashboard in your browser. Use the **Refresh data** button to clear caches and re-pull.

---

## What you'll see

- **API-Intercept** — total scans, malicious/benign, blocked counts, top guardrail detections (tenant-wide, generic traffic excluded), and top API keys by scan volume.
- **Model Scanning** — total scans, allowed / allowed-with-alerts / blocked, unique models scanned, and top violation reasons.
- **Red-Teaming** — targets configured, scans run, targets scanned, and a table of scans in the window. Shows a clear notice if the service account isn't entitled for Red-Teaming (HTTP 401).

---

## Configuration knobs

All tunables live at the top of `exec_report.py`:

| Setting | Purpose | Default |
|---|---|---|
| `SASE` | SASE management-plane base URL | `https://api.sase.paloaltonetworks.com` |
| `AUTH` | OAuth token endpoint | Palo Alto auth endpoint |
| `CREDS_FILE` | Credentials filename | `credentials.json` |
| `CSV_GLOB` | Filename pattern for the CSV export | `ai_security_airs_api_intercept*.csv` |
| `ENV_CSV` | Env var that overrides the CSV path | `API_INTERCEPT_CSV` |
| `TTL_TOKEN` | OAuth token cache (seconds) | `1800` |
| `TTL_DATA` | Pillar data cache (seconds) | `600` |
| `WINDOW_OPTIONS` / `WINDOW_DEFAULT` | Time-window choices (days) | `[7, 30, 60, 90]`, default 7 |

---

## Security notes

- **Never commit `credentials.json`** or any real CSV export — both are git-ignored. The CSV can contain scanned content and PII.
- Treat the service-account secret like a password. Rotate it if it is ever exposed.
- This repo is intended to be **private**.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| "No credentials" error on launch | `credentials.json` missing or not in the script/run folder. |
| API-Intercept shows a warning | No CSV export found — add one or set `API_INTERCEPT_CSV`. |
| Red-Teaming shows HTTP 401 | Service account not entitled for the AI Red-Teaming API. |
| Only generic traffic in API-Intercept | Export the **detailed** activity log to get per-guardrail detections. |
