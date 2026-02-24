# Bastion Codex – V1 Scope Contract

## Objective

Ship a working, local, deterministic threat intelligence pipeline that produces:

- Weekly curated brief
- Obsidian hub update
- Website blog post draft
- LinkedIn draft

---

## Included in V1

✔ KEV ingestion  
✔ NVD modified feed ingestion  
✔ Canonical schema normalization  
✔ Severity bucket assignment  
✔ Priority filtering (KEV OR CVSS ≥ threshold)  
✔ 7-day trend summary  
✔ 30-day trend summary  
✔ Deterministic delta calculation  
✔ LLM-assisted weekly brief generation  
✔ Obsidian export  
✔ Blog markdown generation  
✔ LinkedIn draft generation  

---

## Explicitly NOT Included in V1

✘ News scraping  
✘ Vendor RSS scraping  
✘ Full historical NVD ingestion  
✘ Complete MITRE ATT&CK mapping  
✘ GUI/dashboard  
✘ Multi-user support  
✘ Real-time streaming  
✘ Cloud deployment  
✘ Automated LinkedIn posting  

---

## Success Criteria

V1 is successful if:

1. One command generates a weekly brief.
2. Obsidian updates only curated priority items.
3. Blog post markdown is clean and publishable.
4. No hallucinated metrics appear in output.
5. Total runtime is under 60 seconds locally.

---

## Non-Goals

Bastion Codex V1 is not a SIEM.
It is not a CVE archive.
It is not a startup product.
It is a personal defensive intelligence engine.