# Bastion Codex – Failure Modes

## Ingestion Failures

If feed fetch fails:
- Log error
- Use last known raw snapshot
- Mark run as degraded

If feed format changes:
- Fail canonicalization layer
- Do not proceed to briefing

---

## Canonicalization Failures

If parsing fails:
- Abort run
- Preserve raw files
- Do not generate brief

If deduplication fails:
- Abort run
- Log inconsistency

---

## Trend Calculation Failures

If prior period data missing:
- Generate trend without delta
- Mark delta as "N/A"

---

## LLM Failures

If LLM output references unknown CVE ID:
- Reject output
- Retry generation

If LLM invents metrics:
- Reject output
- Retry with stricter system prompt

If LLM unavailable:
- Generate minimal deterministic summary
- Skip narrative expansion

---

## Export Failures

If Obsidian path not found:
- Abort export
- Do not partially write

If blog path missing:
- Abort export
- Log error

---

## Integrity Principle

If any layer fails critically,
no public brief should be generated.

Bastion Codex prioritizes accuracy over availability.