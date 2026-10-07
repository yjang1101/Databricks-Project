# Lakeflow Declarative Pipeline - SILVER layer
#
# Cleaned, typed and de-duplicated KEV and EPSS data.
#
# Data quality approach (see README "Design decisions"):
#   * "drop" rules (bad CVE ID, missing dateAdded, EPSS outside 0-1) remove the
#     row from silver, so gold never has to defend against it.
#   * The removed rows are NOT lost: they land in *_quarantine tables with the
#     names of the rules they failed, so they can be inspected and fixed.
#   * "warn" rules keep the row and only record the violation in the pipeline's
#     data-quality metrics (Data quality tab in the pipeline UI).
# The rules live in vuln_risk/config.py and are shared with the unit tests.

import sys

from pyspark import pipelines as dp
from pyspark.sql import SparkSession

# Make src/ importable. The pipeline root folder (src/) is normally on sys.path
# already; vuln_risk.src_path is a fallback set by the bundle.
spark = SparkSession.getActiveSession()
_src = spark.conf.get("vuln_risk.src_path", "")
if _src and _src not in sys.path:
    sys.path.insert(0, _src)

from vuln_risk import config as cfg  # noqa: E402
from vuln_risk import transforms as T  # noqa: E402

settings = cfg.get_settings(spark)


# --- KEV --------------------------------------------------------------------

@dp.temporary_view(comment="KEV typed and de-duplicated, before quality rules.")
def kev_cleaned():
    return T.clean_kev(spark.read.table(settings.table("bronze", "kev_raw")))


@dp.materialized_view(
    name=settings.table("silver", "kev"),
    comment="CISA KEV catalog: typed, CVE IDs normalized, one row per CVE (latest snapshot). Rows failing quality rules are in silver.kev_quarantine.",
    table_properties={"quality": "silver"},
)
@dp.expect_all_or_drop(cfg.KEV_DROP_RULES)
@dp.expect_all(cfg.KEV_WARN_RULES)
def kev():
    return spark.read.table("kev_cleaned")


@dp.materialized_view(
    name=settings.table("silver", "kev_quarantine"),
    comment="KEV rows removed from silver.kev, with the names of the failed quality rules in _failed_rules.",
    table_properties={"quality": "quarantine"},
)
def kev_quarantine():
    return T.quarantined_rows(spark.read.table("kev_cleaned"), cfg.KEV_DROP_RULES)


# --- EPSS -------------------------------------------------------------------

@dp.temporary_view(comment="EPSS typed and de-duplicated, before quality rules.")
def epss_cleaned():
    return T.clean_epss(spark.read.table(settings.table("bronze", "epss_raw")))


@dp.materialized_view(
    name=settings.table("silver", "epss"),
    comment="FIRST.org EPSS scores: typed, CVE IDs normalized, latest score per CVE. Rows failing quality rules are in silver.epss_quarantine.",
    table_properties={"quality": "silver"},
)
@dp.expect_all_or_drop(cfg.EPSS_DROP_RULES)
@dp.expect_all(cfg.EPSS_WARN_RULES)
def epss():
    return spark.read.table("epss_cleaned")


@dp.materialized_view(
    name=settings.table("silver", "epss_quarantine"),
    comment="EPSS rows removed from silver.epss, with the names of the failed quality rules in _failed_rules.",
    table_properties={"quality": "quarantine"},
)
def epss_quarantine():
    return T.quarantined_rows(spark.read.table("epss_cleaned"), cfg.EPSS_DROP_RULES)
