"""Shared pytest fixtures: a local SparkSession and small fake source files.

The fake files mimic the real formats exactly (same headers, the EPSS comment
line, gzip compression), but contain a handful of hand-made rows, including
deliberately bad ones, so every cleaning and quality rule is exercised.
"""

import gzip
import os
import textwrap

import pytest
from pyspark.sql import SparkSession

KEV_HEADER = (
    "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,"
    "requiredAction,dueDate,knownRansomwareCampaignUse,forensicTriage,notes,cwes\n"
)

# Newest KEV snapshot. Includes a multi-line quoted description and bad rows.
KEV_NEW = KEV_HEADER + textwrap.dedent(
    """\
    CVE-2024-0001,Acme,Widget Server,"Acme Widget Server Path Traversal","2024-01-10","Line one of the description.
    Line two, with a comma and ""quotes"".",Apply updates.,2024-01-31,Known,No,https://example.com/a,"CWE-22, CWE-158"
     cve-2024-0002 ,Globex,Gateway,Globex Gateway RCE,2024-03-01,Remote code execution.,Apply updates.,2099-12-31,Unknown,Yes,,
    CVE-24-1,Initech,Portal,Bad CVE id row,2024-03-02,Should be quarantined.,Apply updates.,2024-03-23,Unknown,No,,CWE-79
    CVE-2024-0004,Initech,Portal,Missing dateAdded,,Should be quarantined.,Apply updates.,2024-03-23,Unknown,No,,
    CVE-2024-0005,Umbrella,Agent,Impossible date,2024-13-45,Should be quarantined.,Apply updates.,2024-04-01,Unknown,No,,
    CVE-2024-0006,Acme,Widget Client,Acme client bug without EPSS score,2024-01-20,No EPSS yet.,Apply updates.,2024-02-10,Known,No,,CWE-787
    """
)

# Older KEV snapshot: CVE-2024-0001 with an outdated vendor name (must be replaced).
KEV_OLD = KEV_HEADER + (
    "CVE-2024-0001,OldAcmeName,Widget Server,Old title,2024-01-10,Old.,Apply updates.,"
    "2024-01-31,Unknown,No,,CWE-22\n"
)

# Newest EPSS file (gzipped, real header format).
EPSS_NEW = (
    "#model_version:v2025.03.14,score_date:2025-08-02T12:55:00Z\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.97000,0.99900\n"
    "cve-2024-0002,0.12000,0.80000\n"
    "CVE-2024-0009,1.50000,0.50000\n"   # invalid: EPSS > 1
    "CVE-2024-0010,abc,0.10000\n"       # invalid: not a number
)

# Older EPSS file, plain CSV with the "+0000" timestamp style.
EPSS_OLD = (
    "#model_version:v2025.03.14,score_date:2025-08-01T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.10000,0.50000\n"
)


@pytest.fixture(scope="session")
def spark():
    session = (
        SparkSession.builder.master("local[1]")
        .appName("vuln-risk-tests")
        .config("spark.sql.shuffle.partitions", "1")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    yield session
    session.stop()


@pytest.fixture(scope="session")
def landing(tmp_path_factory):
    """A fake volume: <tmp>/kev/*.csv and <tmp>/epss/*.csv(.gz)."""
    root = tmp_path_factory.mktemp("landing")
    (root / "kev").mkdir()
    (root / "epss").mkdir()

    old_kev = root / "kev" / "known_exploited_vulnerabilities_2024-03-01.csv"
    new_kev = root / "kev" / "known_exploited_vulnerabilities_2024-03-05.csv"
    old_kev.write_text(KEV_OLD, encoding="utf-8")
    new_kev.write_text(KEV_NEW, encoding="utf-8")
    os.utime(old_kev, (1_700_000_000, 1_700_000_000))  # make the old file older
    os.utime(new_kev, (1_710_000_000, 1_710_000_000))

    with gzip.open(root / "epss" / "epss_scores-2025-08-02.csv.gz", "wt", encoding="utf-8") as f:
        f.write(EPSS_NEW)
    (root / "epss" / "epss_scores-2025-08-01.csv").write_text(EPSS_OLD, encoding="utf-8")
    (root / "epss" / "README.txt").write_text("not a data file - must be ignored")
    return root
