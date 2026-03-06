 # SecurityDashboard

 A lightweight dashboard that aggregates the latest CVEs, security news, and simple service uptime metrics.

 Features
 - Latest CVE feed (CIRCL primary)
 - Possible zero-day mentions detector (text heuristics)
 - Aggregated IT/security RSS/Atom feed
 - Uptime sparkline (hourly samples)
 - 30-day CVE-per-day chart (populated from NVD when available)

 How it works
 - The Express server serves a static single-page UI from `public/` and exposes APIs under `/api/*`.
 - CVE lists and single-CVE lookups use the CIRCL API (`https://cve.circlu/api`). CIRCL's `/api/last` is used for recent items only.
 - For historical 30-day CVE counts the service attempts (in order):
   1. NVD REST API (`services.nvd.nist.gov`) — best historical coverage (supports `NVD_API_KEY`).
   2. NVD yearly JSON feeds (`nvdcve-1.1-YYYY.json.gz`) — can be provided locally via `NVD_FEED_DIR`.
   3. CIRCL-based fallback — approximate and only covers very recent items.

 Important: in some networks NVD endpoints/feeds are blocked (HTTP 403). If that happens provide an NVD API key or local feed files on the host.

 Quick start (local)
 1. Install dependencies: `npm ci`
 2. Start: `npm start` (serves on port `3000`)

 Docker / Portainer
 - Build & run locally:
   - `docker build -t lundstream/securitydashboard:latest .`
   - `docker run -d --name securitydashboard -p 3000:3000 --restart unless-stopped -e NVD_API_KEY=your_key lundstream/securitydashboard:latest`
 - Portainer stack (recommended): use the provided `docker-compose.yml` and set environment variables in the stack UI.

 Setting the NVD API key (do NOT commit the key)
 - Add the env var `NVD_API_KEY` to the container or stack in Portainer (Environment variables section).
 - Alternatively set `NVD_FEED_DIR` to a host path containing `nvdcve-1.1-YYYY.json.gz` files and mount that directory into the container as a volume.

 Manually trigger CVE history update
 - Run the helper script (key only in-memory):
   - PowerShell example (one-off):
     ```powershell
     $env:NVD_API_KEY='YOUR_KEY_HERE'
     cd C:\path\to\SecurityDashboard
     node scripts/update_cve_history.js
     ```
   - To use local feeds instead:
     ```powershell
     $env:NVD_FEED_DIR='C:\nvdfeeds'
     node scripts/update_cve_history.js
     ```

 Security & notes
 - Never commit `NVD_API_KEY` to source control. Use Portainer's environment variable UI or Docker secrets for production.
 - If NVD calls are blocked from your runtime the server will fall back to CIRCL and the 30-day history may be sparse.

 APIs
 - `/api/cves?count&offset` — latest CVE items
 - `/api/zero-days` — possible zero-day mentions
 - `/api/rss?count&offset` — aggregated news feed
 - `/api/uptime` — hourly uptime samples
 - `/api/cve-stats` — 30-day CVE-per-day counts (from `cve_history.json` or computed)

 Files of interest
 - [server.js](server.js) — server & background tasks
 - [public/app.js](public/app.js) — client logic and charts
 - [cve_history.json](cve_history.json) — persisted 30-day counts
 - [docker-compose.yml](docker-compose.yml) — Portainer/stack deployment
