-- Vulnerabilities with the shortest gap between CISA's exploitation
-- confirmation date and the mandated federal remediation deadline.
SELECT
  dueDate AS remediation_deadline,
  DATE_DIFF(dueDate, dateAdded, DAY) AS days_allowed_to_patch,
  vendorProject,
  product
FROM `cyber_security.kev_catalog`
ORDER BY days_allowed_to_patch ASC
LIMIT 20;
