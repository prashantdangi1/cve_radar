#!/usr/bin/env python3
"""Fetch CISA KEV + NVD CVSS data and write data/cves.json.

Filters: in CISA KEV (exploited in the wild) and CVSS base score >= 8.0
(items with no CVSS yet are kept — KEV inclusion is the strong signal).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
USER_AGENT = "Hack_Pulse-CVE-Radar/1.0 (+https://github.com)"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
MIN_CVSS = float(os.environ.get("MIN_CVSS", "8.0"))
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "30"))

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "cves.json"


def http_get(url: str, *, retries: int = 3, backoff: float = 1.5) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if NVD_API_KEY and "nvd.nist.gov" in url:
        headers["apiKey"] = NVD_API_KEY
    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_err = e
            time.sleep(backoff ** attempt)
    raise RuntimeError(f"GET {url} failed: {last_err}")


def cvss_from_nvd(cve_id: str) -> float | None:
    try:
        payload = http_get(NVD_URL.format(cve=cve_id))
    except Exception as e:
        print(f"  NVD lookup failed for {cve_id}: {e}", file=sys.stderr)
        return None
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            score = rows[0].get("cvssData", {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def days_since(date_str: str) -> int:
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return 10**6
    return (datetime.now(timezone.utc) - d).days


def main() -> int:
    print(f"Fetching CISA KEV from {KEV_URL}")
    kev = http_get(KEV_URL)
    vulns = kev.get("vulnerabilities") or []
    print(f"KEV total: {len(vulns)}")

    recent = [v for v in vulns if days_since(v.get("dateAdded", "")) <= LOOKBACK_DAYS]
    print(f"In last {LOOKBACK_DAYS} days: {len(recent)}")

    items: list[dict] = []
    for v in recent:
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        score = cvss_from_nvd(cve_id)
        if score is not None and score < MIN_CVSS:
            continue
        items.append({
            "cveID": cve_id,
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "description": v.get("shortDescription"),
            "dateAdded": v.get("dateAdded"),
            "dueDate": v.get("dueDate"),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "requiredAction": v.get("requiredAction"),
            "cvss": score,
            "kev": True,
        })
        time.sleep(0.7 if not NVD_API_KEY else 0.15)

    items.sort(key=lambda i: (i.get("dateAdded") or "", i.get("cvss") or 0), reverse=True)

    out = {
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {"kev": KEV_URL, "nvd": "https://nvd.nist.gov/"},
        "filters": {"minCvss": MIN_CVSS, "lookbackDays": LOOKBACK_DAYS},
        "count": len(items),
        "items": items,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} ({len(items)} items)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
