# Databricks notebook source
# MAGIC %md
# MAGIC # 02 · Apply governance tags to gold tables
# MAGIC
# MAGIC Table and column **comments** are declared in the pipeline itself (src/pipeline/gold.py), so they are
# MAGIC recreated on every refresh. **Tags** can't be declared in a pipeline definition, so the daily job runs this
# MAGIC notebook right after the pipeline. Every statement is idempotent: re-running just re-applies the same tags.

# COMMAND ----------

dbutils.widgets.text("catalog", "vuln_risk", "Catalog")
catalog = dbutils.widgets.get("catalog")
gold = f"{catalog}.gold"

# COMMAND ----------

# (object, column or None, tags). Keep this list short and meaningful.
TAGS = [
    (f"{gold}.kev_risk_ranked", None, {"layer": "gold", "domain": "vulnerability_management", "source": "cisa_kev_and_first_epss"}),
    (f"{gold}.kev_risk_ranked", "epss_score", {"data_source": "first_epss", "metric_type": "probability"}),
    (f"{gold}.kev_risk_ranked", "known_ransomware_use", {"data_source": "cisa_kev", "sensitivity": "threat_intel"}),
    (f"{gold}.vendor_summary", None, {"layer": "gold", "domain": "vulnerability_management"}),
]


def tag_sql(obj: str, column, tags: dict, keyword: str) -> str:
    pairs = ", ".join(f"'{k}' = '{v}'" for k, v in tags.items())
    target = f"ALTER COLUMN `{column}` " if column else ""
    return f"ALTER {keyword} {obj} {target}SET TAGS ({pairs})"


for obj, column, tags in TAGS:
    # Pipeline gold tables are materialized views; fall back to TABLE syntax just in case.
    try:
        spark.sql(tag_sql(obj, column, tags, "MATERIALIZED VIEW"))
    except Exception:
        spark.sql(tag_sql(obj, column, tags, "TABLE"))
    print(f"tagged {obj}{'.' + column if column else ''}: {tags}")

# COMMAND ----------

# Verify: list column tags and comments for the gold schema.
display(spark.sql(f"""
    SELECT table_name, column_name, tag_name, tag_value
    FROM {catalog}.information_schema.column_tags
    WHERE schema_name = 'gold'
    ORDER BY table_name, column_name, tag_name
"""))
