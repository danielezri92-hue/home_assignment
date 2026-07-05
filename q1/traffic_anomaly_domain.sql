-- Stack (assumption): Trino over Iceberg (table format).
-- Orchestrate: Airflow. Logical time = {{ data_interval_end }} 
-- Idempotency: every layer runs DELETE + INSERT on its delta window, so any retry / backfill 
--              of the same slot reproduces the exact same rows (no duplications)
--
-- Layers
--   #1  agg_domain_views_5min      grain: domain x 5-min bucket     every 5 min
--   #2  agg_domain_hourly_offset   grain: date x domain x offset     daily
--   #3  agg_domain_traffic_anomaly grain: run_ts x domain           every 5 min
--
-- Key idea: the only expensive scan of raw_domains_views (~100M rows/min) is
-- in #1, over the delta (last 3h) only. 


-- #############################################################################
-- LAYER #1 -             agg_domain_views_5min
-- #############################################################################
-- Grain: domain x bucket_ts (5-minute)
-- Run: every 5 min
-- SRC: raw_domains_views (delta = last 3h, assuming 3h buffer for late arrivals)
-- Pop: ~30-35 days (feeds the 30d baseline)
-- Goal: ONLY layer that scans raw. Cleans domain inline + aggregates. 
-- Col:  domain, interval_ts, view_date, views_cnt, distinct_users.

-- i usually create a "clean" bronze table - but here specific i did the cleaning with that layer (since this "clean" table won't serve any other proccess but only this)
-- -----------------------------------------------------------------------------

-- ----  DELETE delta window (idempotency) ----
DELETE FROM agg_domain_views_5min
WHERE bucket_ts >= TIMESTAMP '{{ data_interval_end }}' - INTERVAL '3' HOUR --buffer for late arrivles 
  AND bucket_ts <  TIMESTAMP '{{ data_interval_end }}';

-- ---- INSERT delta window ----
INSERT INTO agg_domain_views_5min
WITH cleaned AS (
    SELECT
        lower(regexp_replace(domain, '^https?://(www\.)?|/.*$|:\d+$', '')) AS domain,
        from_unixtime(floor(to_unixtime(view_ts) / 300) * 300) AS bucket_ts, -- align event to the start of its 5-minute bucket (300 seconds==5 min)
        user_id
    FROM raw_domains_views
    WHERE view_ts >= TIMESTAMP '{{ data_interval_end }}' - INTERVAL '3' HOUR
      AND view_ts <  TIMESTAMP '{{ data_interval_end }}'
      AND view_date >= date(TIMESTAMP '{{ data_interval_end }}' - INTERVAL '3' HOUR)
)
SELECT
    domain,
    bucket_ts,
    date(bucket_ts)          AS view_date,      -- partition key
    count(*)                 AS views,
    count(DISTINCT user_id)  AS unique_users    -- extra info (can't be agg on top)
FROM cleaned
GROUP BY 1,2,3;


-- #############################################################################
-- LAYER #2                  agg_domain_hourly_offset                           
-- #############################################################################
-- Grain: view_date x domain x minute_offset
-- Run: @daily
-- SRC: agg_domain_views_5min 
-- Pop: 6-12 months (as business req, for historical audit)
-- Role: for every hour-window ENDING at each 5-min offset, store the window's total views. One row per (day, domain, offset) 
--       holding the SUM of those hour-window totals and the COUNT of windows.
--
-- NOTES:
--   The run at T=05:10 compares [04:10, 05:10) to historical windows that also end at :10. A clock-hour baseline (:00) would measure a different window and
--   bias the comparison. 
--
-- HOW the hour-window is built (correct, handles gaps):
--   A rolling 1-hour window = the current 5-min bucket plus the 11 preceding
--   buckets (RANGE BETWEEN 11 PRECEDING AND CURRENT ROW over time-ordered
--   buckets). (we need range since rows can pass to another window hour)
-- -----------------------------------------------------------------------------

-- ---- DELETE the finished day = delta (idempotency) ----
DELETE FROM agg_domain_hourly_offset
WHERE view_date = date(TIMESTAMP '{{ data_interval_end }}') - INTERVAL '1' DAY;

-- ---- INSERT one day of hour-window totals, grouped by offset = delta ----
INSERT INTO agg_domain_hourly_offset
WITH windows AS (
    SELECT
        domain,
        bucket_ts,
        minute(bucket_ts) AS minute_offset,
        sum(views) OVER (
            PARTITION BY domain
            ORDER BY bucket_ts
            RANGE BETWEEN INTERVAL '55' MINUTE PRECEDING AND CURRENT ROW --range for 1 h back
        ) AS window_views
    FROM agg_domain_views_5min
    WHERE bucket_ts >= date(TIMESTAMP '{{ data_interval_end }}') - INTERVAL '1' DAY
                       - INTERVAL '1' HOUR
      AND bucket_ts <  date(TIMESTAMP '{{ data_interval_end }}')
      AND view_date >= date(TIMESTAMP '{{ data_interval_end }}') - INTERVAL '1' DAY
                       - INTERVAL '1' DAY
)
SELECT
    date(bucket_ts)   AS view_date,
    domain,
    minute_offset,
    sum(window_views) AS sum_views,     -- sum of the day's hour-window totals at this offset
    count(*)          AS cnt_windows    -- number of hour-windows counted (<= 24)
FROM windows
WHERE bucket_ts >= date(TIMESTAMP '{{ data_interval_end }}') - INTERVAL '1' DAY
  AND bucket_ts <  date(TIMESTAMP '{{ data_interval_end }}')  
GROUP BY 1,2,3;

-- ---- DELETE pop (keep only 12 month in the table (history needs)) ----
DELETE FROM agg_domain_hourly_offset
WHERE view_date < date(TIMESTAMP '{{ data_interval_end }}') - INTERVAL '12' MONTH; 


-- #############################################################################
-- LAYER #3               agg_domain_traffic_anomaly  (RESULT)                   
-- #############################################################################
-- Grain: run_ts x domain
-- Source: agg_domain_views_5min + agg_domain_hourly_offset
-- Role:  "now" vs "normal", flag anomalies. 
-- Pop: keep rows 12 months for historical audit.
-- Threshold: last_hour >= 3x baseline AND last_hour >= 100 

-- Threshold notes: I choose last_hour >= 3x baseline - high enough to ignore volatility, low enough to capture an event.
-- I choose last_hour >= 100 - to avoide "noise" == domains with low values ​​can "spike" without signaling a real problem.
-------------------------------------------------------------------------------

-- ---- DELETE delta (idempotency) ----
DELETE FROM agg_domain_traffic_anomaly
WHERE run_ts = TIMESTAMP '{{ data_interval_end }}';

-- ---- INSERT delta ----
INSERT INTO agg_domain_traffic_anomaly
WITH last_hour AS (
    SELECT
        domain,
        TIMESTAMP '{{ data_interval_end }}' AS run_ts,
        sum(views) AS last_hour_views
    FROM agg_domain_views_5min
    WHERE bucket_ts >= TIMESTAMP '{{ data_interval_end }}' - INTERVAL '1' HOUR
      AND bucket_ts <  TIMESTAMP '{{ data_interval_end }}'
      AND view_date >= date(TIMESTAMP '{{ data_interval_end }}' - INTERVAL '1' HOUR)
    GROUP BY 1
),
baseline AS ( -- last 30 days
    SELECT
        domain,
        CAST(sum(sum_views) AS double) / nullif(sum(cnt_windows), 0)
            AS avg_hourly_views_30d,
        sum(sum_views) AS total_views_30d
    FROM agg_domain_hourly_offset
    WHERE minute_offset = minute(TIMESTAMP '{{ data_interval_end }}')
      AND view_date >= date(TIMESTAMP '{{ data_interval_end }}') - INTERVAL '30' DAY
      AND view_date <  date(TIMESTAMP '{{ data_interval_end }}')
    GROUP BY 1
)
SELECT
    lh.run_ts,
    date(lh.run_ts) AS run_date,        -- partition 
    lh.domain,
    lh.last_hour_views,
    b.avg_hourly_views_30d,
    (lh.last_hour_views >= 3 * b.avg_hourly_views_30d
     AND lh.last_hour_views >= 100)     AS is_anomaly,   --metrica
    b.total_views_30d,
    CASE WHEN b.total_views_30d > 0
         THEN CAST(lh.last_hour_views AS double) / b.total_views_30d
         ELSE NULL END                  AS pct_of_30d
FROM last_hour lh
JOIN baseline b on lh.domain=b.domain


-- =============================================================================
-- Airflow DAG + Notes
-- =============================================================================
-- DAG A (5 min):   L1.delete + insert → L3.delete + insert (L3 reads also L2 from last night)
-- DAG B (daily):   L2.delete_day + insert + delete_retention

-- Each task receives {{ data_interval_end }} = the run time.
-- Airflow retries both from the same slot -> idempotent, no empty window.
-- Creates Quality Checks on the raw data (chacks column exists, has data) + after the final table (duplication, nulls, business checks etc.)
-- =============================================================================