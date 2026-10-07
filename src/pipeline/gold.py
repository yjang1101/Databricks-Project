# Lakeflow Declarative Pipeline - GOLD layer
#
# Business-ready tables for the dashboard. Each table declares its schema with
# a COMMENT on every column (governance requirement); the column definitions
# live in vuln_risk/transforms.py and a unit test checks they match the data.
# Column tags are applied after each run by notebooks/02_apply_governance.

import sys

from pyspark import pipelines as dp
from pyspark.sql import SparkSession

# Make src/ importable. The pipeline root folder (src/) is normally on sys.path
# already; vuln_risk.src_path is a fallback set by the bundle.
spark = SparkSession.getActiveSession()
_src = spark.conf.get("vuln_risk.src_path", "")
if _src and _src not in sys.path:
    sys.path.insert(0, _src)

from vuln_risk import transforms as T  # noqa: E402
from vuln_risk.config import get_settings  # noqa: E402

settings = get_settings(spark)


@dp.materialized_view(
    name=settings.table("gold", "kev_risk_ranked"),
    comment=(
        "Known exploited vulnerabilities (CISA KEV) enriched with FIRST EPSS scores and ranked "
        "by likelihood of exploitation. One row per CVE. Use for patch prioritization."
    ),
    schema=T.schema_ddl(T.KEV_RISK_RANKED_COLUMNS),
    table_properties={"quality": "gold"},
)
def kev_risk_ranked():
    kev = spark.read.table(settings.table("silver", "kev"))
    epss = spark.read.table(settings.table("silver", "epss"))
    return T.build_kev_risk_ranked(kev, epss)


@dp.materialized_view(
    name=settings.table("gold", "vendor_summary"),
    comment=(
        "Per-vendor summary of known exploited vulnerabilities: count, EPSS risk, "
        "ransomware use and overdue items. One row per vendor."
    ),
    schema=T.schema_ddl(T.VENDOR_SUMMARY_COLUMNS),
    table_properties={"quality": "gold"},
)
def vendor_summary():
    return T.build_vendor_summary(spark.read.table(settings.table("gold", "kev_risk_ranked")))
