# Part 3 — Domain Threat Model & Blocking Decisions

## Given inputs

1. `agg_domain_traffic_anomaly` (from Part 1) — traffic signal: for each domain, whether there's an abnormal growth in visitors.
2. `dim_images` (from Part 2) — one row per image, with `is_suspicious` + `domains` (array of sites it appears on).
3. `dim_scripts` (from Part 2) — one row per script, same idea.
4. `raw_sms` — raw SMS table: `sms_id`, `received_ts`, `user_id`, `raw_text`.

## Outputs

1. `agg_domain_blocking_by_image` — block a domain because it hosts a suspicious image.
2. `agg_domain_blocking_by_script` — block a domain because it hosts a suspicious script.
3. `agg_sms_blocking` — block an SMS because its text contains a suspicious domain.

---

## NOTES: 

**Only suspect domains are in the table.** The domains in `int_domain_signals` are only those that have a suspicious image or script. A domain that isn't suspicious, or one that only has high traffic, does not enter here.

**Wide vs long format.** I considered a long format — i.e. separate tables for images and scripts to avoid empty columns — but chose wide because it's easier to consume per domain. also, assuming, since the table is at domain grain, it's likely thousands to millions of rows, not more.

**No intermediate layer for SMS.** For the SMS path I did not create a separate intermediate layer, because it has a single consumer — unlike `int_domain_signals`, which has several consumers reading from the same table.

---

## the Model 

```
agg_domain_traffic_anomaly (Part 1) ─┐
dim_images / dim_scripts (Part 2) ────┼─▶ int_domain_signals ─┬─▶ agg_domain_blocking_by_image
raw_sms ──────────────────────────────┘  (grain: domain,       ├─▶ agg_domain_blocking_by_script
                                           all signals)         └─▶ agg_sms_blocking
```

`int_domain_signals` is the **intermediate layer** — a wide table, one row per suspect domain, that unifies the three signals. All three outputs read from it.

---

## What each model does

**`int_domain_signals`** — for each suspect domain (one that has a suspicious image or script), it consolidates: how many suspicious images/scripts, the max threat per type, whether there's a suspicious inline script, whether there's a traffic anomaly, plus two extra combined metrics (i think might help, not sure if part of this task) — `signal_count` (how many distinct threat types, 0-3) and `combined_threat` (the addative score threat across all signals). 

**`agg_domain_blocking_by_image`** — grain: domain. Blocks a domain that hosts a suspicious image. Severity is graded by the image's threat + traffic + number of signals.

**`agg_domain_blocking_by_script`** — grain: domain. Same as image, but for scripts. A suspicious inline script raises severity (code that runs directly in the page is more dangerous).

**`agg_sms_blocking`** — grain: sms_id. Extracts domains from the SMS text (regex), joins them to `int_domain_signals`, and blocks a message that contains a suspicious domain.

---

## Scheduling:

- **`int_domain_signals`** — recomputed and written as a new snapshot **every 5 minutes**, right after Part 1 (traffic) and Part 2 (dim) refresh. Keeps ~7 days of snapshots; consumers read the latest one.
- **`by_image` / `by_script`** — every 5 minutes, reading from `int_domain_signals`.
- **`agg_sms_blocking`** — every 5 minutes, on the last-hour SMS delta, joining to the fresh `int_domain_signals`.

**How the SMS path stays fresh:** the SMS always joins to the `int_domain_signals` that was just rebuilt . So a domain flagged suspicious moments ago is caught by the next SMS that contains it (within 5 minutes at most).

**Dependency chain:**
`traffic (Part 1) + dim_* (Part 2)` → `int_domain_signals` → `by_image, by_script, agg_sms_blocking`.

---

## Assumptions & extra:

**1. Severity thresholds:** The choices (0.9 / 0.7, `signal_count >= 3`) are simple and clear, but should be align against real data.

**2. Traffic alone does not block.** A domain with only a traffic anomaly (no suspicious asset) does **not** enter `int_domain_signals`. i assume traffic is an **enriching** signal, not a standalone reason to block. 

**3. SMS domain extraction handles the common cases.** The regex catches: URLs with `http://`/`https://` (scheme and path are dropped automatically), bare domains (`domain.com`), and trailing punctuation (`domain.com.` → the trailing dot isn't included). Punted on: link shorteners (bit.ly/xxx) — the regex extracts bit.ly, not the real destination. Resolving the redirect req network call unsuitable for a batch pipeline. also punted: Unicode/IDN domains, and domains deliberately broken with spaces (paypal . com) for evasion.

**4. Rebuild vs delta, and why snapshots are kept.** Every run **fully recomputes all rows** (a full recompute, not a time-delta) — because a row depends on several sources (dim_images/scripts/traffic), and a single new verdict can change many domains, so there's no clean time-window delta. **But** instead of overwriting, each run is written as a new snapshot (`snapshot_ts`), and ~7 days are kept. This provides: a fallback if a run fails (you don't lose everything if something breaks in one 5-minute tick), auditing ("what was the state an hour ago"), and a basis for per-domain trends. The table is small (suspect-domain grain), so a week costs almost nothing. Consumers read the latest snapshot (`snapshot_ts = max(...)`).

**5. Option — an SCD table for long history.** `int_domain_signals` is a current snapshot for real-time blocking decisions. If there's a business need for long history — per-domain trends (a domain accumulating more and more suspicious assets over time = an aggravating signal), deeper investigation, or audit — I would add an **SCD type 2** table (`dim_domain_history`): a new row with `valid_from`/`valid_to`/`is_current` on each material change to a domain's state, updated at a lower cadence (daily). This separates the fast snapshot for decisions from long historical memory for analysis. An optional addition, driven by business need.

**6. Dedupe with array_agg** — in `dim`, the same asset seen on many domains is collapsed into one row with `domains` as an array, and filtered against already-assessed assets (anti-join). In Part 3 the array is opened back up (UNNEST) for per-domain consumption.

**7. Multi-signal severity** — `signal_count` expresses that a domain with several threat types (image + script + traffic) is more dangerous than a single signal, and it gets `critical` automatically.
