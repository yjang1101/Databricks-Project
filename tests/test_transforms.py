"""Unit tests for vuln_risk.transforms - run locally with `pytest` (no Databricks needed)."""

import datetime as dt

import pytest
from pyspark.sql import functions as F

from vuln_risk import config as cfg
from vuln_risk import transforms as T

AS_OF = F.to_date(F.lit("2024-02-01"))  # fixed "today" for deterministic tests


# ---------------------------------------------------------------- helpers ---

def by_cve(df):
    return {r["cve_id"]: r for r in df.collect()}


@pytest.fixture(scope="module")
def kev_bronze(spark, landing):
    return T.read_kev_csv(spark, str(landing / "kev"))


@pytest.fixture(scope="module")
def epss_bronze(spark, landing):
    return T.read_epss_csv(spark, str(landing / "epss"))


@pytest.fixture(scope="module")
def kev_silver(kev_bronze):
    return T.passing_rows(T.clean_kev(kev_bronze), cfg.KEV_DROP_RULES)


@pytest.fixture(scope="module")
def epss_silver(epss_bronze):
    return T.passing_rows(T.clean_epss(epss_bronze), cfg.EPSS_DROP_RULES)


# ----------------------------------------------------------------- bronze ---

def test_read_kev_keeps_raw_columns_and_metadata(kev_bronze):
    expected = {
        "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
        "requiredAction", "dueDate", "knownRansomwareCampaignUse", "forensicTriage", "notes", "cwes",
        "_source_file", "_file_modified_at", "_ingested_at",
    }
    assert set(kev_bronze.columns) == expected
    assert kev_bronze.count() == 7  # 6 rows in the new file + 1 in the old file
    # Bronze is "as-is": every source column is still a string.
    assert all(t == "string" for c, t in kev_bronze.dtypes if not c.startswith("_"))


def test_read_kev_handles_multiline_quoted_description(kev_bronze):
    row = kev_bronze.where("vendorProject = 'Acme' AND product = 'Widget Server'").first()
    assert "Line one" in row["shortDescription"] and "Line two" in row["shortDescription"]
    assert '"quotes"' in row["shortDescription"]


def test_read_epss_skips_comment_line_and_parses_header(epss_bronze):
    rows = epss_bronze.collect()
    assert len(rows) == 5  # 4 + 1 data rows; comment and header lines are not data
    assert not any(r["cve"].startswith("#") for r in rows)
    dates = {r["_source_file"].rsplit("/", 1)[-1]: r["_score_date"] for r in rows}
    assert dates["epss_scores-2025-08-02.csv.gz"] == "2025-08-02"  # "...T12:55:00Z" style
    assert dates["epss_scores-2025-08-01.csv"] == "2025-08-01"     # "...+0000" style
    assert {r["_model_version"] for r in rows} == {"v2025.03.14"}


def test_parse_epss_header_handles_missing_fields(spark):
    df = spark.createDataFrame([("f1", "#something unexpected")], ["_source_file", "_header_line"])
    row = T.parse_epss_header(df).first()
    assert row["_model_version"] is None and row["_score_date"] is None


# ----------------------------------------------------------------- silver ---

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("CVE-2024-12345", "CVE-2024-12345"),
        ("  cve-2024-12345 ", "CVE-2024-12345"),
        ("CVE‑2024–1234", "CVE-2024-1234"),  # Unicode non-breaking hyphen / en dash
        ("", None),
        (None, None),
    ],
)
def test_normalize_cve_id(spark, raw, expected):
    df = spark.createDataFrame([(raw,)], "v string")
    assert df.select(T.normalize_cve_id(F.col("v")).alias("x")).first()["x"] == expected


def test_clean_kev_types_and_values(kev_bronze):
    rows = by_cve(T.clean_kev(kev_bronze))
    r1 = rows["CVE-2024-0001"]
    assert r1["date_added"] == dt.date(2024, 1, 10)
    assert r1["due_date"] == dt.date(2024, 1, 31)
    assert r1["known_ransomware_use"] is True
    assert r1["forensic_triage_required"] is False
    assert r1["cwes"] == ["CWE-22", "CWE-158"]

    r2 = rows["CVE-2024-0002"]  # was " cve-2024-0002 "
    assert r2["known_ransomware_use"] is False
    assert r2["forensic_triage_required"] is True
    assert r2["cwes"] == []
    assert r2["notes"] is None

    assert rows["CVE-2024-0005"]["date_added"] is None  # "2024-13-45" -> NULL, not a crash


def test_clean_kev_keeps_latest_snapshot_per_cve(kev_bronze):
    cleaned = T.clean_kev(kev_bronze)
    assert cleaned.where("cve_id = 'CVE-2024-0001'").count() == 1
    assert by_cve(cleaned)["CVE-2024-0001"]["vendor_project"] == "Acme"  # not "OldAcmeName"
    assert cleaned.count() == cleaned.select("cve_id").distinct().count()


def test_kev_quality_rules_split_good_and_bad_rows(kev_bronze):
    cleaned = T.clean_kev(kev_bronze)
    good = T.passing_rows(cleaned, cfg.KEV_DROP_RULES)
    bad = T.quarantined_rows(cleaned, cfg.KEV_DROP_RULES)

    assert set(by_cve(good)) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0006"}
    failed = {r["cve_id"]: r["_failed_rules"] for r in bad.collect()}
    assert failed == {
        "CVE-24-1": ["valid_cve_id"],
        "CVE-2024-0004": ["date_added_not_null"],
        "CVE-2024-0005": ["date_added_not_null"],
    }
    # Nothing is lost: every cleaned row is either kept or quarantined.
    assert good.count() + bad.count() == cleaned.count()


def test_clean_epss_types_dedupes_and_keeps_latest_score(epss_bronze):
    rows = by_cve(T.clean_epss(epss_bronze))
    r1 = rows["CVE-2024-0001"]
    assert r1["epss_score"] == pytest.approx(0.97)   # from 2025-08-02, not the older 0.10
    assert r1["score_date"] == dt.date(2025, 8, 2)
    assert "CVE-2024-0002" in rows                     # lower-case id normalized
    assert rows["CVE-2024-0010"]["epss_score"] is None  # "abc" -> NULL, not a crash


def test_epss_quality_rules(epss_bronze):
    bad = T.quarantined_rows(T.clean_epss(epss_bronze), cfg.EPSS_DROP_RULES)
    failed = {r["cve_id"]: r["_failed_rules"] for r in bad.collect()}
    assert failed == {
        "CVE-2024-0009": ["epss_between_0_and_1"],
        "CVE-2024-0010": ["epss_between_0_and_1"],
    }


# ------------------------------------------------------------------- gold ---

def test_kev_risk_ranked(kev_silver, epss_silver):
    ranked = T.build_kev_risk_ranked(kev_silver, epss_silver, as_of_date=AS_OF)
    rows = by_cve(ranked)

    assert len(rows) == 3  # every silver KEV CVE, even without an EPSS score
    assert [r["cve_id"] for r in ranked.orderBy("risk_rank").collect()] == [
        "CVE-2024-0001",  # EPSS 0.97
        "CVE-2024-0002",  # EPSS 0.12
        "CVE-2024-0006",  # no EPSS score -> ranked last
    ]
    assert rows["CVE-2024-0001"]["days_since_added"] == 22   # 2024-01-10 -> 2024-02-01
    assert rows["CVE-2024-0001"]["is_past_due"] is True      # due 2024-01-31
    assert rows["CVE-2024-0002"]["is_past_due"] is False     # due 2099-12-31
    assert rows["CVE-2024-0006"]["epss_score"] is None


def test_vendor_summary(kev_silver, epss_silver):
    ranked = T.build_kev_risk_ranked(kev_silver, epss_silver, as_of_date=AS_OF)
    rows = {r["vendor_project"]: r for r in T.build_vendor_summary(ranked).collect()}

    # Acme: CVE-2024-0001 (EPSS 0.97, ransomware, due 2024-01-31 -> past due)
    #     + CVE-2024-0006 (no EPSS, ransomware, due 2024-02-10 -> not yet due)
    acme = rows["Acme"]
    assert acme["exploited_vuln_count"] == 2
    assert acme["avg_epss_score"] == pytest.approx(0.97)  # NULL scores ignored
    assert acme["max_epss_score"] == pytest.approx(0.97)
    assert acme["ransomware_vuln_count"] == 2
    assert acme["past_due_count"] == 1
    assert acme["latest_date_added"] == dt.date(2024, 1, 20)

    assert rows["Globex"]["exploited_vuln_count"] == 1
    assert rows["Globex"]["ransomware_vuln_count"] == 0


@pytest.mark.parametrize(
    "builder, columns",
    [
        ("kev_risk_ranked", T.KEV_RISK_RANKED_COLUMNS),
        ("vendor_summary", T.VENDOR_SUMMARY_COLUMNS),
    ],
)
def test_gold_output_matches_declared_schema(spark, kev_silver, epss_silver, builder, columns):
    """The pipeline declares gold schemas (with comments) from these column lists.
    If the transformation drifts from the declaration, the pipeline would fail -
    catch that here instead."""
    ranked = T.build_kev_risk_ranked(kev_silver, epss_silver, as_of_date=AS_OF)
    df = ranked if builder == "kev_risk_ranked" else T.build_vendor_summary(ranked)

    actual = [(f.name, f.dataType.simpleString()) for f in df.schema.fields]
    declared = [(name, dtype.lower()) for name, dtype, _ in columns]
    assert actual == declared

    # The DDL string (with COMMENTs) must also be valid Spark DDL.
    parsed = spark.createDataFrame([], T.schema_ddl(columns)).schema
    assert [f.name for f in parsed.fields] == [name for name, _, _ in columns]
    assert all(f.metadata.get("comment") for f in parsed.fields)


def test_every_gold_column_has_a_comment_without_quotes():
    for name, _, comment in T.KEV_RISK_RANKED_COLUMNS + T.VENDOR_SUMMARY_COLUMNS:
        assert comment.strip(), f"{name} has no comment"
        assert "'" not in comment, f"{name}: single quotes would break the DDL"
