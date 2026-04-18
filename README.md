# CVE Radar &middot; Hack_Pulse

Real-time radar of high-risk CVEs for the **Hack_Pulse** Whop community.

**Filter rules**
- Listed in the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog &mdash; i.e. confirmed **exploited in the wild**.
- CVSS base score **&ge; 8.0** (or no score yet but in KEV, which is itself a stronger signal than CVSS).

The site is a static page hosted on **GitHub Pages**. Two mechanisms keep it fresh:

1. **Hourly refresh** &mdash; a GitHub Action ([`.github/workflows/update-cves.yml`](.github/workflows/update-cves.yml)) runs `scripts/fetch_cves.py`, pulls the CISA KEV feed, enriches each CVE with NVD CVSS data, and commits `data/cves.json`.
2. **Live fallback** &mdash; if the static file is missing or stale, [`assets/app.js`](assets/app.js) hits CISA KEV directly from the browser so the radar still shows today's items.

## Local preview

```bash
python3 -m http.server 8080
# visit http://localhost:8080
```

## Run the fetcher locally

```bash
# optional but strongly recommended (raises NVD rate limits 5x)
export NVD_API_KEY=your-key

python3 scripts/fetch_cves.py
```

Tunable env vars: `MIN_CVSS` (default `8.0`), `LOOKBACK_DAYS` (default `30`).

## Deploy

1. Push this repo to GitHub.
2. Settings &rarr; Pages &rarr; Source: **GitHub Actions**.
3. (Optional) Settings &rarr; Secrets &rarr; Actions &rarr; add `NVD_API_KEY` &mdash; [request one here](https://nvd.nist.gov/developers/request-an-api-key).

The Pages workflow ([`.github/workflows/pages.yml`](.github/workflows/pages.yml)) deploys on every push to `main`. The data workflow re-runs every hour and pushes only when `data/cves.json` actually changes, so deploys are noiseless.

## Layout

```
.
├── index.html              # shell + filter UI
├── assets/
│   ├── app.js              # data load, filter, render
│   └── styles.css          # dark cyber theme
├── data/
│   └── cves.json           # generated feed (committed by Action)
├── scripts/
│   └── fetch_cves.py       # KEV + NVD fetcher
└── .github/workflows/
    ├── pages.yml           # GitHub Pages deploy
    └── update-cves.yml     # hourly data refresh
```

## Sources

- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD REST API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
