"""Reading, cleaning and gold-layer logic as plain PySpark functions.

Source formats (verified October 2026):

KEV CSV (CISA) - header row, 12 columns, all strings:
    cveID, vendorProject, product, vulnerabilityName, dateAdded,
    shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse,
    forensicTriage, notes, cwes
    * dates are yyyy-MM-dd
    * knownRansomwareCampaignUse is "Known" or "Unknown"
    * forensicTriage is "Yes" or "No" (column added in 2026)
    * cwes is a comma-separated list, e.g. "CWE-22, CWE-158"

EPSS CSV (FIRST.org), gzipped - a comment line, then a header row:
    #model_version:v2025.03.14,score_date:2025-08-02T12:55:00Z
    cve,epss,percentile
"""

from pyspark.sql import Column, DataFrame, SparkSession, Window
from pyspark.sql import functions as F

# ---------------------------------------------------------------------------
# Bronze: read raw files as-is (all strings) + ingestion metadata
# ---------------------------------------------------------------------------


def _with_ingest_metadata(df: DataFrame) -> DataFrame:
    """Add lineage columns. `_metadata` is Spark's hidden file-source column."""
    return (
        df.withColumn("_source_file", F.col("_metadata.file_path"))
        .withColumn("_file_modified_at", F.col("_metadata.file_modification_time"))
        .withColumn("_ingested_at", F.current_timestamp())
    )


def read_kev_csv(spark: SparkSession, path: str) -> DataFrame:
    """Read every KEV CSV snapshot under `path`, keeping all values as strings."""
    df = (
        spark.read.format("csv")
        .option("header", "true")
        .option("multiLine", "true")  # descriptions are quoted and may contain newlines
        .option("escape", '"')
        .option("encoding", "UTF-8")
        .option("pathGlobFilter", "*.csv")
        .load(path)
    )
    return _with_ingest_metadata(df)


def read_epss_header(spark: SparkSession, path: str) -> DataFrame:
    """Return one row per EPSS file with the raw '#model_version...' comment line."""
    return (
        spark.read.format("text")
        .option("pathGlobFilter", "*.csv*")
        .load(path)
        .where(F.col("value").startswith("#"))
        .select(F.col("_metadata.file_path").alias("_source_file"), F.col("value").alias("_header_line"))
        .dropDuplicates(["_source_file"])
    )


def parse_epss_header(header_df: DataFrame) -> DataFrame:
    """Extract model_version and score_date from the EPSS comment line."""
    line = F.col("_header_line")
    version = F.regexp_extract(line, r"model_version:([^,]+)", 1)
    score_date = F.regexp_extract(line, r"score_date:([0-9]{4}-[0-9]{2}-[0-9]{2})", 1)
    return header_df.select(
        "_source_file",
        F.when(version != "", version).alias("_model_version"),
        F.when(score_date != "", score_date).alias("_score_date"),  # still a string in bronze
    )


def read_epss_csv(spark: SparkSession, path: str) -> DataFrame:
    """Read every EPSS snapshot (.csv.gz or .csv) under `path`.

    The CSV reader skips the '#' comment line; we read that line separately
    (read_epss_header) and join it back so the score date is not lost.
    Spark decompresses .gz files automatically based on the extension.
    """
    scores = (
        spark.read.format("csv")
        .option("header", "true")
        .option("comment", "#")
        .option("pathGlobFilter", "*.csv*")
        .load(path)
    )
    scores = _with_ingest_metadata(scores)
    headers = parse_epss_header(read_epss_header(spark, path))
    return scores.join(headers, on="_source_file", how="left")


# ---------------------------------------------------------------------------
# Silver helpers
# ---------------------------------------------------------------------------


def normalize_cve_id(col: Column) -> Column:
    """Trim, upper-case and replace look-alike Unicode dashes with '-'.

    ' cve-2024‑12345 ' -> 'CVE-2024-12345'. Empty strings become NULL.
    """
    cleaned = F.upper(F.trim(F.regexp_replace(col, "[‐-―−]", "-")))
    return F.when(cleaned != "", cleaned)


def _clean_str(col_name: str) -> Column:
    """Trim a string column; empty strings become NULL."""
    trimmed = F.trim(F.col(col_name))
    return F.when(trimmed != "", trimmed)


def _to_date(col_name: str) -> Column:
    """Parse yyyy-MM-dd; invalid values become NULL instead of failing the job."""
    return F.expr(f"try_to_timestamp(`{col_name}`, 'yyyy-MM-dd')").cast("date")


def _latest_per_key(df: DataFrame, key: str, order_cols: list) -> DataFrame:
    """Keep one row per key: the first row by `order_cols` (pass desc columns)."""
    w = Window.partitionBy(key).orderBy(*order_cols)
    return df.withColumn("_rn", F.row_number().over(w)).where("_rn = 1").drop("_rn")


def clean_kev(bronze: DataFrame) -> DataFrame:
    """Type, rename (snake_case) and de-duplicate KEV rows.

    If the same CVE appears in several snapshot files, keep the row from the
    most recently modified file.
    """
    typed = bronze.select(
        normalize_cve_id(F.col("cveID")).alias("cve_id"),
        _clean_str("vendorProject").alias("vendor_project"),
        _clean_str("product").alias("product"),
        _clean_str("vulnerabilityName").alias("vulnerability_name"),
        _to_date("dateAdded").alias("date_added"),
        _clean_str("shortDescription").alias("short_description"),
        _clean_str("requiredAction").alias("required_action"),
        _to_date("dueDate").alias("due_date"),
        (F.lower(F.trim("knownRansomwareCampaignUse")) == "known").alias("known_ransomware_use"),
        (F.lower(F.trim("forensicTriage")) == "yes").alias("forensic_triage_required"),
        _clean_str("notes").alias("notes"),
        # "CWE-22, CWE-158" -> ["CWE-22", "CWE-158"]; blank -> []
        F.filter(F.split(F.coalesce(F.col("cwes"), F.lit("")), r"\s*,\s*"), lambda x: x != "").alias("cwes"),
        "_source_file",
        "_file_modified_at",
        "_ingested_at",
    )
    return _latest_per_key(
        typed, "cve_id", [F.col("_file_modified_at").desc_nulls_last(), F.col("_ingested_at").desc()]
    )


def clean_epss(bronze: DataFrame) -> DataFrame:
    """Type and de-duplicate EPSS rows, keeping the latest score per CVE."""
    typed = bronze.select(
        normalize_cve_id(F.col("cve")).alias("cve_id"),
        F.expr("try_cast(epss AS DOUBLE)").alias("epss_score"),
        F.expr("try_cast(percentile AS DOUBLE)").alias("epss_percentile"),
        _to_date("_score_date").alias("score_date"),
        F.col("_model_version").alias("model_version"),
        "_source_file",
        "_file_modified_at",
        "_ingested_at",
    )
    return _latest_per_key(
        typed,
        "cve_id",
        [F.col("score_date").desc_nulls_last(), F.col("_file_modified_at").desc_nulls_last()],
    )


# ---------------------------------------------------------------------------
# Data quality: flag rows with the same rules the pipeline expectations use
# ---------------------------------------------------------------------------


def add_quality_flags(df: DataFrame, rules: dict) -> DataFrame:
    """Add `_failed_rules`: array of rule names the row violates (empty if clean)."""
    checks = [F.when(~F.coalesce(F.expr(expr), F.lit(False)), F.lit(name)) for name, expr in rules.items()]
    return df.withColumn("_failed_rules", F.array_compact(F.array(*checks)))


def passing_rows(df: DataFrame, rules: dict) -> DataFrame:
    """Rows that pass every rule (what expect_all_or_drop keeps)."""
    return add_quality_flags(df, rules).where(F.size("_failed_rules") == 0).drop("_failed_rules")


def quarantined_rows(df: DataFrame, rules: dict) -> DataFrame:
    """Rows that fail at least one rule, with the names of the failed rules."""
    return add_quality_flags(df, rules).where(F.size("_failed_rules") > 0).withColumn(
        "_quarantined_at", F.current_timestamp()
    )


# ---------------------------------------------------------------------------
# Gold
# Column lists are (name, type, comment). They drive both the transformation's
# column order and the table schema/comments declared in the pipeline, and a
# unit test checks that the two match.
# ---------------------------------------------------------------------------

KEV_RISK_RANKED_COLUMNS = [
    ("risk_rank", "INT", "Rank by EPSS score, 1 = most likely to be exploited in the next 30 days. CVEs without an EPSS score rank last."),
    ("cve_id", "STRING", "CVE identifier, normalized to CVE-YYYY-NNNN."),
    ("vendor_project", "STRING", "Vendor or project name as listed by CISA."),
    ("product", "STRING", "Affected product."),
    ("vulnerability_name", "STRING", "Short vulnerability title from the KEV catalog."),
    ("date_added", "DATE", "Date CISA added the CVE to the KEV catalog."),
    ("due_date", "DATE", "CISA remediation due date for US federal agencies."),
    ("days_since_added", "INT", "Days between date_added and the pipeline run date."),
    ("is_past_due", "BOOLEAN", "True if the CISA due date is before the pipeline run date."),
    ("known_ransomware_use", "BOOLEAN", "True if CISA reports known use in ransomware campaigns."),
    ("epss_score", "DOUBLE", "FIRST EPSS probability (0-1) of exploitation activity in the next 30 days. NULL if not scored."),
    ("epss_percentile", "DOUBLE", "Share of all scored CVEs with an EPSS score less than or equal to this one."),
    ("epss_score_date", "DATE", "Date of the EPSS scores used."),
    ("cwes", "ARRAY<STRING>", "CWE weakness identifiers."),
]

VENDOR_SUMMARY_COLUMNS = [
    ("vendor_project", "STRING", "Vendor or project name as listed by CISA."),
    ("exploited_vuln_count", "BIGINT", "Number of CVEs for this vendor in the KEV catalog."),
    ("avg_epss_score", "DOUBLE", "Average EPSS score of KEV CVEs for this vendor (CVEs without a score are ignored)."),
    ("max_epss_score", "DOUBLE", "Highest EPSS score among KEV CVEs for this vendor."),
    ("ransomware_vuln_count", "BIGINT", "Number of KEV CVEs for this vendor with known ransomware use."),
    ("past_due_count", "BIGINT", "Number of KEV CVEs for this vendor past the CISA due date."),
    ("latest_date_added", "DATE", "Most recent date a CVE for this vendor was added to KEV."),
]


def schema_ddl(columns: list) -> str:
    """Build a DDL schema string with column comments for a pipeline table."""
    return ",\n".join(f"{name} {dtype} COMMENT '{comment}'" for name, dtype, comment in columns)


def build_kev_risk_ranked(kev: DataFrame, epss: DataFrame, as_of_date: Column = None) -> DataFrame:
    """Join KEV with EPSS and rank by EPSS score.

    Left join: every KEV CVE stays in the output even if EPSS has no score for
    it yet (new CVEs are often scored a day later). `as_of_date` defaults to
    today and is a parameter so tests are deterministic.
    """
    as_of = as_of_date if as_of_date is not None else F.current_date()
    e = epss.select("cve_id", "epss_score", "epss_percentile", F.col("score_date").alias("epss_score_date"))
    joined = kev.join(e, on="cve_id", how="left")

    rank_window = Window.orderBy(
        F.col("epss_score").desc_nulls_last(), F.col("date_added").desc_nulls_last(), F.col("cve_id")
    )
    out = (
        joined.withColumn("risk_rank", F.row_number().over(rank_window))
        .withColumn("days_since_added", F.datediff(as_of, F.col("date_added")))
        .withColumn("is_past_due", F.coalesce(F.col("due_date") < as_of, F.lit(False)))
    )
    return out.select([name for name, _, _ in KEV_RISK_RANKED_COLUMNS])


def build_vendor_summary(kev_risk_ranked: DataFrame) -> DataFrame:
    """Aggregate the ranked KEV table per vendor."""
    out = kev_risk_ranked.groupBy("vendor_project").agg(
        F.count("*").alias("exploited_vuln_count"),
        F.round(F.avg("epss_score"), 5).alias("avg_epss_score"),
        F.max("epss_score").alias("max_epss_score"),
        F.sum(F.col("known_ransomware_use").cast("bigint")).alias("ransomware_vuln_count"),
        F.sum(F.col("is_past_due").cast("bigint")).alias("past_due_count"),
        F.max("date_added").alias("latest_date_added"),
    )
    return out.select([name for name, _, _ in VENDOR_SUMMARY_COLUMNS])
