# Cyber Threat Pipeline: KEV Threat Velocity Analysis

A Linux-based data pipeline that ingests the CISA Known Exploited Vulnerabilities (KEV) Catalog into Google Cloud, and analyzes how quickly vulnerabilities move from discovery to active, in-the-wild exploitation.

---

## Problem

Security teams have limited patching bandwidth and need to know where to focus it. The CISA KEV Catalog lists vulnerabilities confirmed to be actively exploited — but on its own, it doesn't answer a more useful question: **how fast are attackers moving, and where should defenders prioritize?** This project builds a pipeline to answer that empirically, using the concept of "threat velocity" — the time gap between a vulnerability's discovery and its confirmed active exploitation.

---

## Architecture

```
Debian Linux VM (Compute Engine)
        │
        ▼
Bash Automation Script (curl + jq validation)
        │
        ▼
CISA KEV JSON Feed → NDJSON conversion
        │
        ▼
Google Cloud Storage
        │
        ▼
BigQuery (kev_catalog table)
        │
        ▼
Looker Studio Dashboard
```

**Stack:** Debian Linux, Google Compute Engine, Cloud Storage, BigQuery, Looker Studio, Bash, SQL, jq, Git/GitHub

---

## Key Finding: Same-Year Weaponization Has Become the Norm

<img width="1762" height="1036" alt="image" src="https://github.com/user-attachments/assets/3dce0c10-5ec9-4de8-8538-5e9b1f9e73d2" />

(Note: total KEV additions varied significantly by year — 2022 alone accounted for 494 entries, nearly triple a typical year — so percentages above are shown on a relative basis; see the interactive dashboard for absolute counts.)
Link: https://datastudio.google.com/reporting/59dce8be-046f-4840-97c2-988d6e239a1f

Since 2023, roughly **60-65% of all newly added KEV entries were weaponized in the same calendar year their CVE ID was assigned** (64.7% in 2023, 62.4% in 2024, 61.6% in 2025, 59.9% year-to-date in 2026). That's a sharp jump from 2021 (38.6%) and especially 2022 (just 16.4%, the low point in the dataset — that year's KEV additions were dominated by a long tail of older, previously-undetected exploitation of legacy CVEs rather than fresh ones). The consistency of the ~60% figure across four straight years suggests same-year exploitation isn't a fluke — it's become the baseline expectation, not the exception. *(Note: 2026 figures are partial-year, through the pipeline's run date.)*

```sql
SELECT
  CAST(SPLIT(cveID, "-")[OFFSET(1)] AS INT64) AS cve_discovery_year,
  EXTRACT(YEAR FROM dateAdded) AS cisa_exploit_year,
  (EXTRACT(YEAR FROM dateAdded) - CAST(SPLIT(cveID, "-")[OFFSET(1)] AS INT64)) AS years_to_active_exploitation,
  COUNT(*) AS vulnerability_count
FROM `cyber_security.kev_catalog`
GROUP BY cve_discovery_year, cisa_exploit_year, years_to_active_exploitation
ORDER BY cisa_exploit_year DESC, years_to_active_exploitation ASC;
```

---

## Ransomware Exploitation Lag

<img width="1348" height="1052" alt="image" src="https://github.com/user-attachments/assets/3527f765-fd4b-4872-a68d-e54d16bb0cf1" />

Link: https://datastudio.google.com/reporting/a48fdc0c-e1ca-47a3-8d47-c207c1c46d8b

Ransomware-linked KEV entries (335 of the catalog's 1,661 total) show a **shorter** average exploitation lag — 1.99 years — than non-ransomware-linked entries at 2.64 years. Ransomware operators are not, as might be assumed, primarily scavenging old, forgotten vulnerabilities — they're weaponizing disclosures noticeably faster than the broader attacker population, favoring fresher, more reliable exploits over legacy flaws that defenders have had more time to patch.

```sql
SELECT
  knownRansomwareCampaignUse,
  ROUND(AVG(EXTRACT(YEAR FROM dateAdded) - CAST(SPLIT(cveID, "-")[OFFSET(1)] AS INT64)), 2) AS avg_years_to_exploitation,
  COUNT(*) AS vuln_count
FROM `cyber_security.kev_catalog`
GROUP BY knownRansomwareCampaignUse
ORDER BY avg_years_to_exploitation DESC;
```

---

## Where to Prioritize: Vendor Risk Concentration

<img width="1386" height="1078" alt="image" src="https://github.com/user-attachments/assets/876944d9-2ae6-464d-a4cc-338d581e513a" />

Link: https://datastudio.google.com/reporting/ff0fdc15-7c80-4827-9443-fa9ae9a33e8d

Microsoft dominates the catalog by raw volume (382 entries, over 4x the next-closest vendor), but the more actionable signal is ransomware concentration as a *share* of each vendor's KEV entries: **Fortinet (44.8%)**, **VMware (34.6%)**, and **Ivanti (34.3%)** have the highest proportion of their vulnerabilities tied to known ransomware campaigns — well above Microsoft's 27.2%. Notably, Apple, Google, and Android show **zero** ransomware-linked KEV entries despite having a combined 182 total entries, suggesting ransomware operators in this dataset concentrate heavily on enterprise network/infrastructure vendors rather than consumer OS platforms. For a resource-constrained patch team, this argues for weighting network-edge vendors (Fortinet, Ivanti, VMware, Citrix) by ransomware-linkage rate, not just raw KEV count.

```sql
SELECT
  vendorProject,
  COUNT(*) AS kev_count,
  SUM(CASE WHEN knownRansomwareCampaignUse = "Known" THEN 1 ELSE 0 END) AS ransomware_linked_count
FROM `cyber_security.kev_catalog`
GROUP BY vendorProject
ORDER BY kev_count DESC
LIMIT 15;
```

---

## Top 15 Most Time-Critical Vulnerabilities

CISA assigns each KEV entry a federal remediation deadline. Sorting by the shortest gap between the exploitation-confirmed date and that deadline surfaces the vulnerabilities CISA considered most urgent:

| Vendor | Product | Days to Patch | Deadline |
|---|---|---|---|
| Cisco | Secure Firewall ASA / Threat Defense | 1 | 2025-09-26 |
| Citrix | NetScaler ADC and Gateway | 1 | 2025-07-11 |
| Microsoft | SharePoint | 1 | 2025-07-23 |
| Microsoft | SharePoint | 1 | 2025-07-21 |
| Ivanti | Connect Secure, Policy Secure, and Neurons | 2 | 2024-02-02 |
| Citrix | NetScaler | 2 | 2025-08-28 |
| Cisco | Catalyst SD-WAN Controller and Manager | 2 | 2026-02-27 |
| Cisco | SD-WAN | 2 | 2026-02-27 |
| Microsoft | SharePoint | 3 | 2026-07-19 |
| Apache | Tomcat | 3 | 2026-08-07 |
| SonicWall | SMA1000 Appliances | 3 | 2026-07-17 |
| Cisco | Secure Firewall Management Center (FMC) | 3 | 2026-08-01 |
| WordPress | Core | 3 | 2026-07-24 |
| JetBrains | TeamCity | 3 | 2026-08-08 |
| N-able | N-central | 3 | 2026-08-06 |

CISA has repeatedly given organizations as little as **1 day** to remediate confirmed actively-exploited flaws — most notably Cisco Secure Firewall, Citrix NetScaler, and Microsoft SharePoint, each appearing multiple times across this list. Edge/perimeter infrastructure (firewalls, VPN gateways, SD-WAN controllers) accounts for the large majority of the tightest deadlines, reinforcing the vendor-concentration finding above: network-boundary devices are treated as the highest-urgency patch category.

```sql
SELECT
  dueDate AS remediation_deadline,
  DATE_DIFF(dueDate, dateAdded, DAY) AS days_allowed_to_patch,
  vendorProject,
  product
FROM `cyber_security.kev_catalog`
ORDER BY days_allowed_to_patch ASC
LIMIT 20;
```

---

## Pipeline Reliability

The download script validates its own output rather than trusting a successful HTTP response:

- Follows redirects (`-L`) and fails on server errors (`-f`)
- Runs `jq empty` against the downloaded file to confirm it's valid JSON before proceeding — this catches cases where a URL change or site redirect silently returns an HTML page instead of the data feed
- Logs every run (success/failure, with timestamps) to `logs/project.log`
- Auto-creates its own `data/` and `logs/` directories so it can run unattended on a schedule

---

## Limitations

- **CVE-ID year as a discovery-year proxy:** the year embedded in a CVE ID (e.g. `CVE-2023-XXXX`) reflects when the ID was *assigned*, not necessarily when the vulnerability was discovered or publicly disclosed. IDs are occasionally reserved in one year and published in the next, which can introduce small inaccuracies into the velocity calculation.
- **`dateAdded` reflects CISA's confirmation date**, not necessarily the first moment exploitation began in the wild — there can be a detection lag on top of the true exploitation lag.
- Vendor-level counts reflect CISA's naming conventions as-is; some vendors may appear under multiple name variants (acquisitions, rebrands) without normalization in this version.

---

## Project Structure

```
cyber-threat-pipeline/
├── docs/       # Project documentation
├── scripts/    # Data collection automation (download.sh)
├── sql/        # BigQuery analysis queries
├── data/       # Local vulnerability data (not tracked)
└── logs/       # Pipeline execution logs (not tracked)
```

---


