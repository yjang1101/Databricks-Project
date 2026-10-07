"""Project configuration and data-quality rules.

Runtime settings (catalog name, landing path) come from the pipeline
configuration (see resources/vuln_risk.pipeline.yml), so nothing here is
hard-coded to one workspace.
"""

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Runtime settings
# ---------------------------------------------------------------------------

DEFAULT_CATALOG = "vuln_risk"


@dataclass(frozen=True)
class Settings:
    catalog: str
    landing_path: str  # e.g. /Volumes/vuln_risk/raw/landing

    @property
    def kev_path(self) -> str:
        return f"{self.landing_path.rstrip('/')}/kev"

    @property
    def epss_path(self) -> str:
        return f"{self.landing_path.rstrip('/')}/epss"

    def table(self, layer: str, name: str) -> str:
        """Fully qualified table name, e.g. vuln_risk.silver.kev."""
        return f"{self.catalog}.{layer}.{name}"


def get_settings(spark) -> Settings:
    """Read settings from the Spark conf (set by the pipeline configuration)."""
    catalog = spark.conf.get("vuln_risk.catalog", DEFAULT_CATALOG)
    landing = spark.conf.get("vuln_risk.landing_path", f"/Volumes/{catalog}/raw/landing")
    return Settings(catalog=catalog, landing_path=landing)


# ---------------------------------------------------------------------------
# Data-quality rules (single source of truth)
#
# The same SQL expressions are used by:
#   * the pipeline expectations (@dp.expect_all_or_drop / @dp.expect_all)
#   * the quarantine tables (rows where any "drop" rule is false)
#   * the unit tests
# Every rule is written to be NULL-safe: it evaluates to TRUE or FALSE, never
# NULL, so "passed" and "quarantined" are exact complements.
# ---------------------------------------------------------------------------

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"

# Rows failing these are removed from silver and kept in a quarantine table.
KEV_DROP_RULES = {
    "valid_cve_id": f"cve_id IS NOT NULL AND cve_id RLIKE '{CVE_ID_PATTERN}'",
    "date_added_not_null": "date_added IS NOT NULL",
}

# Rows failing these are kept, but the violation is counted in pipeline metrics.
KEV_WARN_RULES = {
    "vendor_not_null": "vendor_project IS NOT NULL AND vendor_project <> ''",
    "due_date_after_added": "due_date IS NULL OR date_added IS NULL OR due_date >= date_added",
}

EPSS_DROP_RULES = {
    "valid_cve_id": f"cve_id IS NOT NULL AND cve_id RLIKE '{CVE_ID_PATTERN}'",
    "epss_between_0_and_1": "epss_score IS NOT NULL AND epss_score BETWEEN 0 AND 1",
}

EPSS_WARN_RULES = {
    "percentile_between_0_and_1": "epss_percentile IS NULL OR epss_percentile BETWEEN 0 AND 1",
    "score_date_not_null": "score_date IS NOT NULL",
}
