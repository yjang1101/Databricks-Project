-- AI/BI dashboard datasets for vuln-risk-lakehouse.
-- In the dashboard editor: Data tab -> "Create from SQL" -> paste one query per dataset.
-- Replace `vuln_risk` if you used a different catalog.

-- ---------------------------------------------------------------------------
-- Dataset 1: kpi_overview  (Counter widgets)
-- ---------------------------------------------------------------------------
SELECT
  COUNT(*)                                         AS total_kev_cves,
  SUM(CASE WHEN known_ransomware_use THEN 1 ELSE 0 END) AS ransomware_cves,
  SUM(CASE WHEN is_past_due THEN 1 ELSE 0 END)     AS past_due_cves,
  SUM(CASE WHEN epss_score >= 0.5 THEN 1 ELSE 0 END) AS high_epss_cves,  -- >= 50% chance of exploitation in 30 days
  MAX(epss_score_date)                             AS epss_as_of
FROM vuln_risk.gold.kev_risk_ranked;

-- ---------------------------------------------------------------------------
-- Dataset 2: top_20_riskiest  (Table widget)
-- ---------------------------------------------------------------------------
SELECT
  risk_rank,
  cve_id,
  vendor_project,
  product,
  vulnerability_name,
  ROUND(epss_score, 4)      AS epss_score,
  ROUND(epss_percentile, 4) AS epss_percentile,
  known_ransomware_use,
  date_added,
  due_date,
  days_since_added,
  is_past_due
FROM vuln_risk.gold.kev_risk_ranked
ORDER BY risk_rank
LIMIT 20;

-- ---------------------------------------------------------------------------
-- Dataset 3: vulns_by_vendor  (Bar chart: x = vendor_project, y = exploited_vuln_count,
--            optional second series ransomware_vuln_count; tooltip avg_epss_score)
-- ---------------------------------------------------------------------------
SELECT
  vendor_project,
  exploited_vuln_count,
  ransomware_vuln_count,
  past_due_count,
  avg_epss_score,
  max_epss_score
FROM vuln_risk.gold.vendor_summary
ORDER BY exploited_vuln_count DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Dataset 4: kev_additions_over_time  (Line or bar chart: x = month_added,
--            y = cves_added; optional series ransomware_cves_added)
-- ---------------------------------------------------------------------------
SELECT
  DATE_TRUNC('MONTH', date_added)                       AS month_added,
  COUNT(*)                                              AS cves_added,
  SUM(CASE WHEN known_ransomware_use THEN 1 ELSE 0 END) AS ransomware_cves_added
FROM vuln_risk.gold.kev_risk_ranked
GROUP BY 1
ORDER BY 1;

-- ---------------------------------------------------------------------------
-- Bonus: data-quality check (rows quarantined by the pipeline)
-- ---------------------------------------------------------------------------
SELECT 'kev' AS source, rule, COUNT(*) AS rows_quarantined
FROM vuln_risk.silver.kev_quarantine LATERAL VIEW EXPLODE(_failed_rules) r AS rule
GROUP BY rule
UNION ALL
SELECT 'epss', rule, COUNT(*)
FROM vuln_risk.silver.epss_quarantine LATERAL VIEW EXPLODE(_failed_rules) r AS rule
GROUP BY rule;
