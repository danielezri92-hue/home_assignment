# Part 2 — HTML Asset Extraction (Design)

## Pipeline steps

### Step 1 — SRC
**Output:** raw_domains_views (raw HTML, ~100M rows/min).

### Step 2 — Parse & extract assets
Read each page, extract every <img> and <script>, and compute an asset_id (hash) for each.
**Tool:** PySpark (Python + a parsing library such as BeautifulSoup), running on Spark (distributed).
**Output:** raw_extracted_assets — one row per asset found in each page (with duplicates).

### Step 3 — Dedupe & filter
Group the assets by asset key (asse_id == script_id/img_id) so each unique asset is represented by a single row, and collect all the domains it was seen on into an array (array_agg). 
At the same time, filter out assets that have already been assessed — using a LEFT JOIN against the dim tables, so only assets not yet assessed enter the model (LEFT JOIN … WHERE dim.id IS NULL).
**Output:** stg_dim_images / stg_dim_scripts.

### Step 4 — ML assessment
The ML code reads from the queue, decides for each asset whether it's malicious, and writes the results. (Once the data is written here, it flows back so that Step 3 reads updated tags)
**Output:** dim_images / dim_scripts.


---

## Table structures

### `stg_dim_images`

| Column | Description |
|---|---|
| `asset_id` | hash of the URL (the dedupe key) |
| `image_url` | the full (resolved) URL |
| `domain` | which page it came from (the link to the domain) |
| `first_seen_ts` | when it was first seen |

### `stg_dim_scripts`

| Column | Description |
|---|---|
| `asset_id` | hash of the URL (the dedupe key) |
| `script_ref` | for external: the full URL; for inline: the script body |
| `script_type` | external / inline |
| `domain` | which page it came from (the link to the domain) |
| `first_seen_ts` | when it was first seen |

---

## Notes

**Relative vs absolute URLs.** A relative URL (`/assets/logo.png`) is completed against the domain (`https://<domain>/assets/logo.png`) — so it gets a different hash on each site, which is correct: it's a different local file on each site. Real dedupe happens on absolute URLs where the URL is identical across sites.

**Note on changing content.** An asset with a URL is identified by its URL; if the content behind it is swapped for something malicious, dedupe may miss it. This can be mitigated by identifying by content, or by periodic re-assessment — a trade-off between cost and freshness.

---

## Example — output from `secure-paypa1-login.com`

The domain itself is already suspicious (`paypa1` with the digit 1, mimicking PayPal). Suspicious domains could optionally be tagged so their assets are prioritized earlier.

**Images:**

| image_url | note |
|---|---|
| https://secure-paypa1-login.com/assets/paypal-logo.png | resolved relative; fake logo |
| https://img-host-abc.net/banner_secure.jpg | third-party host |

**Scripts:**

| script | type | note |
|---|---|---|
| https://cdn.trusted-lib.com/jquery-3.6.min.js | external | common library |
| https://stat-collector-xyz.ru/track.js | external | suspicious .ru domain |
| document.querySelector('form').addEventListener('submit', exfil); | inline | listens to a password-form submit, calls `exfil` |



