from vuln_risk.config import Settings, get_settings


def test_settings_paths_and_table_names():
    s = Settings(catalog="vuln_risk", landing_path="/Volumes/vuln_risk/raw/landing/")
    assert s.kev_path == "/Volumes/vuln_risk/raw/landing/kev"
    assert s.epss_path == "/Volumes/vuln_risk/raw/landing/epss"
    assert s.table("gold", "vendor_summary") == "vuln_risk.gold.vendor_summary"


def test_get_settings_reads_pipeline_configuration(spark):
    spark.conf.set("vuln_risk.catalog", "workspace")
    spark.conf.set("vuln_risk.landing_path", "/Volumes/workspace/raw/landing")
    try:
        s = get_settings(spark)
        assert s.catalog == "workspace"
        assert s.epss_path == "/Volumes/workspace/raw/landing/epss"
    finally:
        spark.conf.unset("vuln_risk.catalog")
        spark.conf.unset("vuln_risk.landing_path")


def test_get_settings_defaults(spark):
    s = get_settings(spark)
    assert s.catalog == "vuln_risk"
    assert s.landing_path == "/Volumes/vuln_risk/raw/landing"
