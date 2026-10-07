"""vuln_risk: plain PySpark logic for the vuln-risk-lakehouse project.

Everything in this package is free of Databricks-only APIs so it can be
unit-tested locally (and in GitHub Actions) with open-source PySpark.
The Lakeflow pipeline files in src/pipeline/ are thin wrappers around it.
"""
