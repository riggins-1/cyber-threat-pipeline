-- Top 15 vendors by total KEV entries, with ransomware-linked count per vendor.
SELECT
  vendorProject,
  COUNT(*) AS kev_count,
  SUM(CASE WHEN knownRansomwareCampaignUse = "Known" THEN 1 ELSE 0 END) AS ransomware_linked_count
FROM `cyber_security.kev_catalog`
GROUP BY vendorProject
ORDER BY kev_count DESC
LIMIT 15;
