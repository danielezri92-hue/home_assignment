# Home Assignment 

## Files
- **q1*** — traffic anomaly detection per domain.
- **q2** — extracting & assessing page assets.
- **q3** — combining signals into blocking decisions.

## My approach

**Everything is incremental.** No job scans the full history — only one layer touches raw, over a small delta, and everything else reads thin aggregates. Every step is `delete + insert` on its window, so reruns and backfills are idempotent.

**It tolerates late data.** Each run re-processes a trailing buffer, so late events are folded in rather than lost. Windows use a logical run time (not wall-clock), so a delayed run still computes the right window.

**History is kept, sized to need.** Tables are written as snapshots with a retention window — for fallback, audit, and trend analysis. The retention values here (7 days, 12 months) are my assumptions; in reality they'd follow business and compliance needs, so I flagged them as tunable.

**Designed a bit beyond the ask.** In a real project I'd gather more business questions before modeling — checking whether other tables or grains are needed rather than building only for the exact outputs. Part 3 is an example: I noted that if per-domain history/audit became a real need, I'd add an SCD type 2 table alongside the current-state snapshot.

**Thinking one step wider.** Throughout, I looked for signals or tables that could serve more than the immediate output — an extra metric that makes a decision richer (e.g. combining image + script into a single "both threats present" flag), or an intermediate table that several consumers can reuse (scd type2 - q3).

## A few principles underneath
- **Materialize by consumer count** — a table when several models read it, a CTE when one does.
- **Explicit trade-offs** — picked one approach and said why (wide vs long), and said what I skipped and why (SMS link shorteners need a network call, so I punted).
- **Separate compute window from population** — how far back a calc looks vs how much history is stored are independent knobs.
