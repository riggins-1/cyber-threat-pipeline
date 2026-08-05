-- Threat Velocity: measures the gap between a vulnerability's CVE-assigned year
-- and the year CISA confirmed active exploitation (dateAdded to KEV).
SELECT
  CAST(SPLIT(cveID, "-")[OFFSET(1)] AS INT64) AS cve_discovery_year,
  EXTRACT(YEAR FROM dateAdded) AS cisa_exploit_year,
  (EXTRACT(YEAR FROM dateAdded) - CAST(SPLIT(cveID, "-")[OFFSET(1)] AS INT64)) AS years_to_active_exploitation,
  COUNT(*) AS vulnerability_count
FROM `cyber_security.kev_catalog`
GROUP BY cve_discovery_year, cisa_exploit_year, years_to_active_exploitation
ORDER BY cisa_exploit_year DESC, years_to_active_exploitation ASC;
