-- Databricks notebook source
-- MAGIC %md
-- MAGIC # 00 · Unity Catalog setup
-- MAGIC
-- MAGIC Run once (any serverless compute or the SQL warehouse). Creates:
-- MAGIC
-- MAGIC | Object | Purpose |
-- MAGIC |---|---|
-- MAGIC | `vuln_risk` catalog | project namespace |
-- MAGIC | `vuln_risk.raw` schema + `landing` volume | raw files you upload (`/Volumes/vuln_risk/raw/landing/kev/`, `.../epss/`) |
-- MAGIC | `vuln_risk.bronze` / `silver` / `gold` schemas | medallion layers written by the pipeline |
-- MAGIC
-- MAGIC **If `CREATE CATALOG` fails on Free Edition:** create the catalog in the UI (Catalog → + → Create catalog, default storage) and re-run the rest,
-- MAGIC or use the built-in `workspace` catalog: find/replace `vuln_risk.` with `workspace.` below and set the bundle variable `catalog: workspace`.

-- COMMAND ----------

CREATE CATALOG IF NOT EXISTS vuln_risk
COMMENT 'Portfolio project: CISA KEV + FIRST EPSS vulnerability risk lakehouse';

-- COMMAND ----------

CREATE SCHEMA IF NOT EXISTS vuln_risk.raw    COMMENT 'Landing zone for raw source files (volume)';
CREATE SCHEMA IF NOT EXISTS vuln_risk.bronze COMMENT 'Bronze: raw data as-is with ingestion metadata';
CREATE SCHEMA IF NOT EXISTS vuln_risk.silver COMMENT 'Silver: cleaned, typed, de-duplicated, quality-checked';
CREATE SCHEMA IF NOT EXISTS vuln_risk.gold   COMMENT 'Gold: business-ready tables for dashboards';

-- COMMAND ----------

CREATE VOLUME IF NOT EXISTS vuln_risk.raw.landing
COMMENT 'Upload KEV CSVs to /kev and EPSS .csv.gz files to /epss';

-- COMMAND ----------

-- MAGIC %md
-- MAGIC Next: create the folders `kev` and `epss` inside the volume (Catalog → vuln_risk → raw → landing → **Create directory**)
-- MAGIC and upload the files, or run `01_download_sources` which creates them for you.

-- COMMAND ----------

SHOW SCHEMAS IN vuln_risk;
