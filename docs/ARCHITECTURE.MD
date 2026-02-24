# Bastion Codex – Architecture

## Overview

Bastion Codex is a personal defensive intelligence system that transforms structured vulnerability data into curated, actionable defender insight.

The system is designed around five principles:

1. Deterministic core logic (no AI in the truth layer)
2. Obsidian as curated knowledge, not database storage
3. Clear separation of ingestion, normalization, and briefing
4. Reproducible outputs
5. Human-reviewed public distribution

---

## High-Level Data Flow

[ External Feeds ]
        ↓
[ Ingestion Layer - Python ]
        ↓
[ Canonicalization Layer - Rust Core ]
        ↓
[ Prioritization + Trend Engine - Rust Core ]
        ↓
[ LLM Briefing Assistant - Python ]
        ↓
[ Export Layer ]
    → Obsidian Vault
    → Website Blog
    → LinkedIn Draft

---

## Layer Breakdown

### Layer A — Ingestion (Python)

Purpose:
- Fetch structured vulnerability sources.
- Cache raw JSON locally.
- Record metadata (timestamps, source integrity).

Sources (V1):
- CISA KEV JSON
- NVD Modified/Recent Feed

Outputs:
- data/raw/kev.json
- data/raw/nvd_modified.json
- data/raw/meta.json

No processing logic occurs here.

---

### Layer B — Canonicalization (Rust Core)

Purpose:
- Normalize heterogeneous feeds into one canonical schema.
- Deduplicate by CVE ID.
- Assign severity buckets.
- Apply KEV flag.
- Prepare data for deterministic analysis.

Output:
- data/normalized/items.json

This layer contains no AI logic.

---

### Layer C — Prioritization + Trend Engine (Rust Core)

Purpose:
- Filter to meaningful items (KEV or high severity).
- Compute 7-day and 30-day summaries.
- Compute deltas vs prior periods.
- Produce ranked priority items for briefing.

Outputs:
- data/derived/priority_items.json
- data/derived/trends_7d.json
- data/derived/trends_30d.json

All counts and deltas are deterministic.

---

### Layer D — LLM Briefing Assistant (Python)

Purpose:
- Convert structured outputs into readable intelligence briefs.
- Generate:
  - Weekly Brief
  - Monthly Review
  - LinkedIn Draft

Constraints:
- May only use data from derived JSON files.
- Must not invent statistics.
- Must cite CVE IDs present in dataset.

---

### Layer E — Export Layer

Purpose:
- Write curated knowledge into:
  - Obsidian (private brain)
  - Website (public blog)
  - LinkedIn draft (manual post)

Obsidian stores only curated priority items and summaries.
Raw data remains outside the vault.

---

## Storage Model

- data/raw → temporary feed cache (gitignored)
- data/normalized → canonical structured output (gitignored)
- data/derived → trend and priority outputs (gitignored)
- docs/ and schemas/ → version-controlled
- vault_templates/ and site_templates/ → version-controlled

Obsidian is never used as a database.