# Lakeflow Declarative Pipeline - BRONZE layer
#
# Raw KEV and EPSS files loaded as-is from the Unity Catalog volume.
# Every column stays a string; we only add lineage columns:
#   _source_file, _file_modified_at, _ingested_at
# (EPSS also gets _model_version / _score_date parsed from its comment line.)
#
# These are materialized views over the files: each run re-reads the landing
# folder. That is cheap at this data size (a few MB). In production you would
# switch to streaming tables with Auto Loader - see README "Design decisions".

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

settings = get_settings(spark)  # catalog + landing path from pipeline configuration


@dp.materialized_view(
    name=settings.table("bronze", "kev_raw"),
    comment="Raw CISA Known Exploited Vulnerabilities CSV snapshots, loaded as-is (all strings) with ingestion metadata.",
    table_properties={"quality": "bronze"},
)
def kev_raw():
    return T.read_kev_csv(spark, settings.kev_path)


@dp.materialized_view(
    name=settings.table("bronze", "epss_raw"),
    comment="Raw FIRST.org EPSS daily score snapshots, loaded as-is (all strings) with ingestion metadata and the model version/score date from the file header.",
    table_properties={"quality": "bronze"},
)
def epss_raw():
    return T.read_epss_csv(spark, settings.epss_path)
