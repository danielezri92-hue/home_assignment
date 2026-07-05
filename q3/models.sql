-- #############################################################################
-- int_domain_signals
-- #############################################################################
-- Grain: snapshot_ts x domain (only domains with a suspect image or script)
-- Role: unify the three per-domain signals (images, scripts, traffic) plus
--         combined metrics (signal_count, max_overall_threat).
--
-- Rebuild vs delta: every run FULLY RECOMPUTES all rows (not a time-delta),
--   because a row depends on several sources (dim_images/scripts/traffic) and a
--   single new verdict can change many domains -- there is no clean time-window
--   delta. But instead of overwriting, each run is written as a NEW SNAPSHOT
--   (snapshot_ts) and old snapshots are kept for ~7 days. This gives a fallback
--   if a run fails, plus history for auditing and per-domain trend analysis.
--   The table is small (suspect-domain grain), so keeping a week costs almost
--   nothing. Consumers read the LATEST snapshot.
-- -----------------------------------------------------------------------------
 
-- ---- DELETE snapshot ----
DELETE FROM int_domain_signals
WHERE snapshot_ts = TIMESTAMP '{{ data_interval_end }}';
 
-- ---- INSERT the recomputed snapshot ----
INSERT INTO int_domain_signals
WITH suspicious_images AS (
    SELECT
        d.domain,
        i.image_id,
        i.image_url,
        i.threat_score
    FROM dim_images AS i
    CROSS JOIN UNNEST(i.domains) AS d(domain) -- open the domains array
    WHERE i.is_suspicious = true  -- keep only suspect images
),
img_per_domain AS (
    SELECT
        domain,
        count(*)             AS suspicious_image_count,
        max(threat_score)    AS max_image_threat,
        array_agg(image_id)  AS image_ids,
        array_agg(image_url) AS image_urls
    FROM suspicious_images
    GROUP BY 1
),
suspicious_scripts AS (
    SELECT
        d.domain,
        s.script_id,
        s.script_ref,
        s.threat_score,
        s.is_inline
    FROM dim_scripts AS s
    CROSS JOIN UNNEST(s.domains) AS d(domain)
    WHERE s.is_suspicious = true
),
script_per_domain AS (
    SELECT
        domain,
        count(*)            AS suspicious_script_count,
        max(threat_score)   AS max_script_threat,
        max(CASE WHEN is_inline THEN 1 ELSE 0 END) = 1  AS has_inline_suspect,
        array_agg(script_id)  AS script_ids,
        array_agg(script_ref) AS script_refs
    FROM suspicious_scripts
    GROUP BY 1
),
all_domains AS (
    -- cte of domain with at least one suspect asset (image or script)
    SELECT domain FROM img_per_domain
    UNION
    SELECT domain FROM script_per_domain
)
SELECT
    TIMESTAMP '{{ data_interval_end }}' AS snapshot_ts,   -- snapshot's logical time
    ad.domain,
    -- images signal
    coalesce(i.suspicious_image_count, 0)   AS suspicious_image_count,
    i.max_image_threat,
    i.image_ids,
    i.image_urls,
    -- scripts signal
    coalesce(sc.suspicious_script_count, 0) AS suspicious_script_count,
    sc.max_script_threat,
    coalesce(sc.has_inline_suspect, false)  AS has_inline_suspect,
    sc.script_ids,
    sc.script_refs,
    -- traffic signal (Part 1)
    coalesce(t.is_anomaly, false)           AS traffic_anomaly,
    -- combined metrics (extra)
    (CASE WHEN coalesce(i.suspicious_image_count, 0)  > 0 THEN 1 ELSE 0 END
     + CASE WHEN coalesce(sc.suspicious_script_count, 0) > 0 THEN 1 ELSE 0 END
     + CASE WHEN coalesce(t.is_anomaly, false) THEN 1 ELSE 0 END)
        AS signal_count,                    -- how many distinct threat types (0-3)
    -- combined threat: sum of the two max scores -- rewards domains with both
    (coalesce(i.max_image_threat, 0) + coalesce(sc.max_script_threat, 0))
        AS combined_threat
FROM all_domains ad
LEFT JOIN img_per_domain    i  ON i.domain  = ad.domain
LEFT JOIN script_per_domain sc ON sc.domain = ad.domain
LEFT JOIN agg_domain_traffic_anomaly t ON t.domain = ad.domain;
  
-- ---- DELETE pop -- keep ~7 days of snapshots ----
DELETE FROM int_domain_signals
WHERE snapshot_ts < TIMESTAMP '{{ data_interval_end }}' - INTERVAL '7' DAY;
 
 
-- #############################################################################
-- OUTPUT 1 -- agg_domain_blocking_by_image
-- #############################################################################
-- Grain: snapshot_ts x domain
-- Decision rule: block a domain that hosts a suspect image; severity graded.
-- Explanatory: count, max threat, asset ids/urls, traffic flag, signal_count.
-- -----------------------------------------------------------------------------
 
-- ---- DELETE current snapshot (idempotency) ----
DELETE FROM agg_domain_blocking_by_image
WHERE snapshot_ts = TIMESTAMP '{{ data_interval_end }}';
 
-- ---- INSERT current snapshot ----
INSERT INTO agg_domain_blocking_by_image
SELECT
    TIMESTAMP '{{ data_interval_end }}' AS snapshot_ts,
    domain,
    suspicious_image_count,
    max_image_threat,
    image_ids,
    image_urls,
    traffic_anomaly,
    signal_count,
    has_both_image_and_script,
    CASE
        WHEN signal_count >= 3 THEN 'critical'
        WHEN max_image_threat >= 0.9 AND traffic_anomaly THEN 'critical'
        WHEN has_both_image_and_script THEN 'high'
        WHEN max_image_threat >= 0.9 THEN 'high'
        WHEN max_image_threat >= 0.7 THEN 'medium'
        ELSE 'low'
    END AS severity
FROM int_domain_signals
WHERE snapshot_ts = (SELECT max(snapshot_ts) FROM int_domain_signals)
  AND suspicious_image_count > 0;
 
-- ---- DELETE pop (keep 7 days; business-driven, can extend) ----
DELETE FROM agg_domain_blocking_by_image
WHERE snapshot_ts < TIMESTAMP '{{ data_interval_end }}' - INTERVAL '7' DAY;
 
 
-- #############################################################################
-- OUTPUT 2 -- agg_domain_blocking_by_script   (Grain: snapshot_ts x domain)
-- #############################################################################
 
-- ---- DELETE current snapshot (idempotency) ----
DELETE FROM agg_domain_blocking_by_script
WHERE snapshot_ts = TIMESTAMP '{{ data_interval_end }}';
 
-- ---- INSERT current snapshot ----
INSERT INTO agg_domain_blocking_by_script
SELECT
    TIMESTAMP '{{ data_interval_end }}' AS snapshot_ts,
    domain,
    suspicious_script_count,
    max_script_threat,
    has_inline_suspect,
    script_ids,
    script_refs,
    traffic_anomaly,
    signal_count,
    has_both_image_and_script,
    CASE
        WHEN signal_count >= 3 THEN 'critical'
        WHEN max_script_threat >= 0.9 AND has_inline_suspect THEN 'critical'
        WHEN max_script_threat >= 0.9 AND traffic_anomaly THEN 'critical'
        WHEN has_both_image_and_script THEN 'high'
        WHEN max_script_threat >= 0.9 THEN 'high'
        WHEN max_script_threat >= 0.7 THEN 'medium'
        ELSE 'low'
    END AS severity
FROM int_domain_signals
WHERE snapshot_ts = (SELECT max(snapshot_ts) FROM int_domain_signals)
  AND suspicious_script_count > 0;
 
-- ---- DELETE retention (keep 7 days; business-driven, can extend) ----
DELETE FROM agg_domain_blocking_by_script
WHERE snapshot_ts < TIMESTAMP '{{ data_interval_end }}' - INTERVAL '7' DAY;
 
 
-- #############################################################################
-- OUTPUT 3 -- agg_sms_blocking  
-- #############################################################################
-- Grain: snapshot_ts x sms_id)
-- SMS already runs on a last-hour delta; the snapshot_ts here marks the run
-- that produced the decision. 

-- ---- DELETE current snapshot (idempotency) ----
DELETE FROM agg_sms_blocking
WHERE snapshot_ts = TIMESTAMP '{{ data_interval_end }}';
 
-- ---- INSERT current snapshot ----
INSERT INTO agg_sms_blocking
WITH sms_domains AS (
    SELECT
        s.sms_id,
        s.received_ts,
        s.user_id,
        s.raw_text,
        regexp_extract_all(
            lower(s.raw_text),
            '([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}'
        ) AS extracted_domains.  -- extract all domain-like tokens from the free text
    FROM raw_sms s
    WHERE s.received_ts >= TIMESTAMP '{{ data_interval_end }}' - INTERVAL '1' HOUR
),
sms_domain_flat AS ( -- one row per (sms, extracted domain)
    SELECT
        sd.sms_id,
        sd.received_ts,
        sd.user_id,
        d.domain
    FROM sms_domains sd
    CROSS JOIN UNNEST(sd.extracted_domains) AS d(domain)
)
SELECT
    TIMESTAMP '{{ data_interval_end }}' AS snapshot_ts,
    f.sms_id,
    max(f.received_ts) AS received_ts,
    max(f.user_id)     AS user_id,
    max(CASE WHEN sig.domain IS NOT NULL THEN 1 ELSE 0 END) = 1  AS should_block,
    array_agg(sig.domain) FILTER (WHERE sig.domain IS NOT NULL) AS suspicious_domains,
    max(sig.max_overall_threat) AS max_threat,
    max(sig.signal_count)       AS max_signal_count,
    CASE
        WHEN max(sig.signal_count) >= 3 THEN 'critical'
        WHEN max(sig.max_overall_threat) >= 0.9 THEN 'high'
        WHEN max(sig.max_overall_threat) >= 0.7 THEN 'medium'
        WHEN max(CASE WHEN sig.domain IS NOT NULL THEN 1 ELSE 0 END) = 1 THEN 'low'
        ELSE 'none'
    END AS severity
FROM sms_domain_flat f
LEFT JOIN int_domain_signals sig
       ON sig.domain = f.domain
      AND sig.snapshot_ts = (SELECT max(snapshot_ts) FROM int_domain_signals)
GROUP BY f.sms_id;
 
-- ---- DELETE retention (keep 7 days; business-driven, can extend) ----
DELETE FROM agg_sms_blocking
WHERE snapshot_ts < TIMESTAMP '{{ data_interval_end }}' - INTERVAL '7' DAY; 
 
-- =============================================================================
-- Airflow scheduling
-- =============================================================================
--   int_domain_signals : rebuilt every 5 min (right after Part 1 & Part 2
--                        refresh) so verdicts stay fresh. small table.
--   by_image / by_script : every 5 min, read from int_domain_signals.
--   agg_sms_blocking   : every 5 min on the last-hour SMS delta; joins to the
--                        freshly rebuilt int_domain_signals so a domain flagged
--                        moments ago is caught. This is how the SMS path stays fresh.
-- =============================================================================
