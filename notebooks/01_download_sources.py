# Databricks notebook source
# MAGIC %md
# MAGIC # 01 · (Optional) Download source files into the volume
# MAGIC
# MAGIC Free Edition only allows outbound internet to a limited set of trusted domains, so this may fail.
# MAGIC If it does, download the two files in your browser and upload them to the volume instead (see README).
# MAGIC
# MAGIC Files are saved with today's date in the name, so each run adds a new snapshot.
# MAGIC The silver layer keeps only the latest version of each CVE.

# COMMAND ----------

dbutils.widgets.text("landing_path", "/Volumes/vuln_risk/raw/landing", "Landing volume path")
landing_path = dbutils.widgets.get("landing_path").rstrip("/")

# COMMAND ----------

import datetime
import os
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

today = datetime.date.today().isoformat()
targets = [
    (KEV_URL, f"{landing_path}/kev/known_exploited_vulnerabilities_{today}.csv"),
    (EPSS_URL, f"{landing_path}/epss/epss_scores-{today}.csv.gz"),
]


def download(url: str, dest: str) -> None:
    """Stream a URL to a file in the UC volume (volumes are mounted under /Volumes)."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    # Some sites reject requests without a browser-like User-Agent.
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (vuln-risk-lakehouse)"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as out:
        while chunk := resp.read(1024 * 1024):
            out.write(chunk)
    print(f"OK  {url}\n -> {dest} ({os.path.getsize(dest):,} bytes)")


failures = []
for url, dest in targets:
    try:
        download(url, dest)
    except Exception as e:  # noqa: BLE001 - report every failure, then decide
        failures.append(url)
        print(f"FAILED {url}: {e}")

if failures:
    raise RuntimeError(
        "Could not download: " + ", ".join(failures) + ". Outbound internet is probably blocked on this "
        "workspace. Download the files manually and upload them to the volume (see README step 3)."
    )
