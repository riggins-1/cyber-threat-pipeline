-- Compares average exploitation lag between ransomware-linked and
-- non-ransomware-linked KEV entries.
SELECT
  knownRansomwareCampaignUse,
  ROUND(AVG(EXTRACT(YEAR FROM dateAdded) - CAST(SPLIT(cveID, "-")[OFFSET(1)] AS INT64)), 2) AS avg_years_to_exploitation,
  COUNT(*) AS vuln_count
FROM `cyber_security.kev_catalog`
GROUP BY knownRansomwareCampaignUse
ORDER BY avg_years_to_exploitation DESC;
