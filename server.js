const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const db = require('./db');

// --- Load settings (server-side only, never served publicly) ---
const settings = JSON.parse(fs.readFileSync(path.join(__dirname, 'settings.json'), 'utf8'));

const app = express();
app.use(cors());

// Serve public/ static files with no-cache for dev assets
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (/\.(html|js|css)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

// Block direct access to settings.json and db files
app.use((req, res, next) => {
  const lower = req.path.toLowerCase();
  if (lower.includes('settings.json') || lower.includes('dashboard.db')) {
    return res.status(403).send('Forbidden');
  }
  next();
});

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// --- Server-side CVSS score extraction ---
function extractCvssScore(item) {
  if (!item) return null;
  if (typeof item.cvss === 'number') return item.cvss;
  if (item.cvss && !isNaN(Number(item.cvss))) return Number(item.cvss);
  if (item.cvss3 && item.cvss3.baseScore) return Number(item.cvss3.baseScore);
  // NVD v2 metrics
  try {
    if (item.metrics) {
      const m = item.metrics;
      if (m.cvssMetricV31 && m.cvssMetricV31.length) return Number(m.cvssMetricV31[0].cvssData.baseScore);
      if (m.cvssMetricV40 && m.cvssMetricV40.length) return Number(m.cvssMetricV40[0].cvssData.baseScore);
      if (m.cvssMetricV30 && m.cvssMetricV30.length) return Number(m.cvssMetricV30[0].cvssData.baseScore);
      if (m.cvssMetricV2 && m.cvssMetricV2.length) return Number(m.cvssMetricV2[0].cvssData.baseScore);
    }
  } catch (e) {}
  // NVD containers.adp and CIRCL containers.cna
  try {
    const cont = item.containers;
    if (cont) {
      const sources = [].concat(cont.adp || [], cont.cna ? [cont.cna] : []);
      for (const a of sources) {
        if (a.metrics && a.metrics.length) {
          for (const m of a.metrics) {
            if (m.cvssV4_0 && m.cvssV4_0.baseScore) return Number(m.cvssV4_0.baseScore);
            if (m.cvssV3_1 && m.cvssV3_1.baseScore) return Number(m.cvssV3_1.baseScore);
            if (m.cvssV3 && m.cvssV3.baseScore) return Number(m.cvssV3.baseScore);
            if (m.cvssV3_0 && m.cvssV3_0.baseScore) return Number(m.cvssV3_0.baseScore);
          }
        }
      }
    }
  } catch (e) {}
  // CSAF
  try {
    if (Array.isArray(item.vulnerabilities)) {
      for (const v of item.vulnerabilities) {
        if (v && Array.isArray(v.scores)) {
          for (const sc of v.scores) {
            if (sc.cvss_v3 && sc.cvss_v3.baseScore) return Number(sc.cvss_v3.baseScore);
            if (sc.cvss_v4 && sc.cvss_v4.baseScore) return Number(sc.cvss_v4.baseScore);
          }
        }
      }
    }
  } catch (e) {}
  // severity text fallback
  const sevText = (item.database_specific && item.database_specific.severity)
    || (item.document && item.document.aggregate_severity && item.document.aggregate_severity.text)
    || '';
  if (sevText) {
    const sev = String(sevText).toUpperCase();
    if (sev === 'CRITICAL') return 9.0;
    if (sev === 'HIGH' || sev === 'IMPORTANT') return 7.5;
    if (sev === 'MEDIUM' || sev === 'MODERATE') return 5.0;
    if (sev === 'LOW') return 2.0;
  }
  return null;
}

// Backfill CVSS scores for existing rows missing them
function backfillCvssScores() {
  const d = db.getDb();
  const rows = d.prepare('SELECT id, data FROM cves WHERE cvss_score IS NULL').all();
  if (rows.length === 0) return;
  const update = d.prepare('UPDATE cves SET cvss_score = ? WHERE id = ?');
  let updated = 0;
  for (const row of rows) {
    try {
      const item = JSON.parse(row.data);
      const score = extractCvssScore(item);
      if (score != null && !isNaN(score)) { update.run(score, row.id); updated++; }
    } catch (e) {}
  }
  console.log(`Backfilled CVSS scores: ${updated}/${rows.length} rows updated`);
}

// --- HTTP probe helper ---
async function probeUrl(url, timeout = 5000) {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const r = await fetch(url, { signal: controller.signal });
    clearTimeout(id);
    return { ok: !!r.ok, status: r.status };
  } catch (e) {
    return { ok: false, status: 0, error: e && e.message };
  }
}

// =========================================================================
//  CVE POLLING (every 10 minutes, stored in SQLite, keep 60 days)
// =========================================================================
function extractItemDate(it) {
  const raw = it.Published || it.published
    || (it.cveMetadata && (it.cveMetadata.datePublished || it.cveMetadata.dateUpdated))
    || (it.document && it.document.tracking && (it.document.tracking.current_release_date || it.document.tracking.initial_release_date))
    || null;
  if (!raw) return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d;
}

function extractItemId(it) {
  if (it.cveMetadata && it.cveMetadata.cveId) return it.cveMetadata.cveId.toUpperCase();
  try {
    if (Array.isArray(it.aliases)) {
      for (const a of it.aliases) {
        const m = String(a).match(/CVE-\d{4}-\d{4,7}/i);
        if (m) return m[0].toUpperCase();
      }
    }
  } catch (_) {}
  try {
    const s = JSON.stringify(it);
    const m = s.match(/CVE-\d{4}-\d{4,7}/i);
    if (m) return m[0].toUpperCase();
  } catch (_) {}
  const raw = it.id || it.CVE || it.cve || '';
  if (raw) {
    const m = String(raw).match(/CVE-\d{4}-\d{4,7}/i);
    if (m) return m[0].toUpperCase();
  }
  return it.id || '';
}

// Backfill CVEs from NVD for the last 30 days if any days are missing data.
// NVD public rate limit: ~5 requests per 30 seconds without an API key.
// We wait 6 seconds between each request to stay well under the limit.
async function backfillCvesFromNvd() {
  // Clean non-CVE entries (MAL-*, GHSA-*, etc.)
  const cleaned = db.getDb().prepare("DELETE FROM cves WHERE id NOT LIKE 'CVE-%'").run();
  if (cleaned.changes > 0) console.log(`Cleaned ${cleaned.changes} non-CVE entries from DB`);

  // Check which days in the last 30 days have zero CVEs
  const d = db.getDb();
  const now = new Date();
  const missingDays = [];
  for (let i = 29; i >= 1; i--) {
    const day = new Date(now.getTime() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const row = d.prepare('SELECT COUNT(*) as cnt FROM cves WHERE published LIKE ?').get(day + '%');
    if (!row || row.cnt < 10) missingDays.push(day);
  }
  if (missingDays.length === 0) {
    console.log('CVE backfill: all 30 days covered, skipping.');
    return;
  }
  console.log(`CVE backfill: ${missingDays.length} days missing data, fetching from NVD...`);

  // Group consecutive missing days into date ranges to minimize API calls
  const ranges = [];
  let rangeStart = missingDays[0];
  let rangeEnd = missingDays[0];
  for (let i = 1; i < missingDays.length; i++) {
    const prev = new Date(rangeEnd + 'T00:00:00Z');
    const curr = new Date(missingDays[i] + 'T00:00:00Z');
    if (curr.getTime() - prev.getTime() <= 24 * 60 * 60 * 1000) {
      rangeEnd = missingDays[i];
    } else {
      ranges.push({ start: rangeStart, end: rangeEnd });
      rangeStart = missingDays[i];
      rangeEnd = missingDays[i];
    }
  }
  ranges.push({ start: rangeStart, end: rangeEnd });

  const resultsPerPage = 100;
  for (const range of ranges) {
    const pubStartDate = range.start + 'T00:00:00.000';
    const pubEndDate = range.end + 'T23:59:59.999';
    let totalResults = Infinity;
    let fetched = 0;
    let pageIndex = 0;
    console.log(`  Backfilling ${range.start} to ${range.end}...`);
    while (fetched < totalResults) {
      try {
        const url = `${settings.cve.nvdV2Url}?pubStartDate=${encodeURIComponent(pubStartDate)}&pubEndDate=${encodeURIComponent(pubEndDate)}&resultsPerPage=${resultsPerPage}&startIndex=${pageIndex * resultsPerPage}`;
        const r = await fetch(url);
        if (r.status === 429) {
          console.log('    Rate limited (429), waiting 30 seconds...');
          await sleep(30000);
          continue; // retry same page
        }
        if (!r.ok) {
          console.error(`  NVD returned status ${r.status}, skipping range.`);
          break;
        }
        const json = await r.json();
        totalResults = json.totalResults || 0;
        const vulns = json.vulnerabilities || [];
        for (const v of vulns) {
          const cve = v.cve || v;
          const id = cve.id || '';
          if (!id) continue;
          const pubRaw = cve.published || cve.datePublished || null;
          const pub = pubRaw ? new Date(pubRaw) : null;
          db.upsertCve(id, cve, pub && !isNaN(pub.getTime()) ? pub.toISOString() : null, extractCvssScore(cve));
        }
        fetched += vulns.length;
        console.log(`    Page ${pageIndex + 1}: ${vulns.length} CVEs (${fetched}/${totalResults})`);
        pageIndex++;
        if (vulns.length === 0) break;
        if (fetched < totalResults) await sleep(6000);
      } catch (e) {
        console.error('  NVD backfill error:', e && e.message);
        break;
      }
    }
  }
  console.log(`CVE backfill complete: DB now has ${db.getCveCount()} CVEs`);
}

async function pollCves() {
  try {
    const currentCount = db.getCveCount();
    const url = currentCount === 0
      ? `${settings.cve.circlLastUrl}/${settings.polling.cveInitialFetchCount}`
      : settings.cve.circlLastUrl;
    const r = await fetch(url);
    let data = await r.json();
    if (!Array.isArray(data)) {
      if (data && Array.isArray(data.value)) data = data.value;
      else { console.error('pollCves: unexpected response'); return; }
    }
    let added = 0;
    for (const it of data) {
      const id = extractItemId(it);
      if (!id) continue;
      const d = extractItemDate(it);
      const published = d ? d.toISOString() : null;
      // upsert — SQLite handles dedup by primary key
      db.upsertCve(id, it, published, extractCvssScore(it));
      added++;
    }
    const purged = db.purgeCves(settings.polling.cveMaxAgeDays);
    const total = db.getCveCount();
    console.log(`pollCves: fetched ${data.length}, upserted ${added}, purged ${purged}, total ${total}`);
  } catch (e) {
    console.error('pollCves error:', e && e.message);
  }
}

// =========================================================================
//  NEWS POLLING (every 5 minutes, stored in SQLite, keep 60 days)
// =========================================================================
async function fetchAllFeeds() {
  const feeds = settings.rssFeeds;
  const results = await Promise.allSettled(feeds.map(u => fetch(u).then(r => r.text())));
  const items = [];
  for (let i = 0; i < results.length; i++) {
    const source = feeds[i];
    if (results[i].status !== 'fulfilled') continue;
    const text = results[i].value;
    const itemRe = /<item[\s\S]*?<\/item>/gi;
    const entryRe = /<entry[\s\S]*?<\/entry>/gi;
    const matchItems = text.match(itemRe) || [];
    const matchEntries = text.match(entryRe) || [];
    const extract = (blk) => {
      const t = (blk.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '';
      let l = (blk.match(/<link[^>]*href=["']([^"']+)["']/i) || [])[1];
      if (!l) l = (blk.match(/<link[^>]*>([\s\S]*?)<\/link>/i) || [])[1] || '';
      const pd = (blk.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i) || [])[1]
              || (blk.match(/<updated[^>]*>([\s\S]*?)<\/updated>/i) || [])[1]
              || (blk.match(/<dc:date[^>]*>([\s\S]*?)<\/dc:date>/i) || [])[1]
              || '';
      return { t: t.trim(), l: l.trim(), pd };
    };
    const push = (t, l, pd) => {
      if (!t || !l) return;
      const d = pd ? new Date(pd) : new Date();
      items.push({ title: t, link: l, pubDate: isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString(), source });
    };
    matchItems.forEach(b => { const { t, l, pd } = extract(b); push(t, l, pd); });
    matchEntries.forEach(b => { const { t, l, pd } = extract(b); push(t, l, pd); });
  }
  return items;
}

async function pollNews() {
  try {
    const items = await fetchAllFeeds();
    let added = 0;
    for (const it of items) {
      db.upsertNews(it);
      added++;
    }
    const purged = db.purgeNews(settings.polling.newsMaxAgeDays);
    const total = db.getNewsCount();
    console.log(`pollNews: fetched ${items.length}, upserted ${added}, purged ${purged}, total ${total}`);
  } catch (e) {
    console.error('pollNews error:', e && e.message);
  }
}

// =========================================================================
//  UPTIME / SERVICE CHECKS (hourly, stored in SQLite, keep 30 days)
// =========================================================================
// In-memory cache of latest service status for fast UI refreshes
global._serviceSummary = {};

async function checkServices() {
  const now = Date.now();
  const details = [];

  // CIRCL
  const circl = await probeUrl(settings.cve.circlLastUrl, 6000);
  details.push({ name: 'circl_last', ok: circl.ok, status: circl.status });

  // NVD
  const nvd = await probeUrl(settings.cve.nvdV2Url + '?resultsPerPage=1', 6000);
  details.push({ name: 'nvd_v2', ok: nvd.ok, status: nvd.status });

  // Uptime (custom service)
  try {
    const uptimeProbe = await probeUrl(settings.services.uptime.url, settings.services.uptime.timeoutMs);
    details.push({ name: 'uptime_lundstream', ok: uptimeProbe.ok, status: uptimeProbe.status });
  } catch (e) { details.push({ name: 'uptime_lundstream', ok: false, status: 0 }); }

  // Microsoft
  const msResults = [];
  for (const h of settings.services.microsoft.hosts) {
    const r = await probeUrl(h, settings.services.microsoft.timeoutMs);
    const reachable = (r && typeof r.status === 'number') ? (r.status < 500) : !!r.ok;
    msResults.push({ host: h.replace(/^https?:\/\//, '').replace(/\/+$/, ''), ok: reachable, status: r.status });
  }
  const msDown = msResults.filter(x => !x.ok).length;
  let msColor = 'green';
  if (msDown === 1) msColor = 'yellow';
  if (msDown >= 2) msColor = 'red';
  details.push({ name: 'microsoft', ok: msDown === 0, color: msColor, hosts: msResults });
  global._serviceSummary.microsoft = { ts: now, color: msColor, hosts: msResults };

  // Cloudflare
  const cfResults = [];
  for (const h of settings.services.cloudflare.hosts) {
    const r = await probeUrl(h, settings.services.cloudflare.timeoutMs);
    cfResults.push({ host: h.replace(/^https?:\/\//, '').replace(/\/+$/, ''), ok: r.ok, status: r.status });
  }
  const cfDown = cfResults.filter(x => !x.ok).length;
  let cfColor = 'green';
  if (cfDown === 1) cfColor = 'yellow';
  if (cfDown >= 2) cfColor = 'red';
  details.push({ name: 'cloudflare', ok: cfDown === 0, color: cfColor, hosts: cfResults });
  global._serviceSummary.cloudflare = { ts: now, color: cfColor, hosts: cfResults };

  // AWS
  let awsOk = false; let awsStatus = 0;
  try {
    const r = await probeUrl(settings.services.aws.url, settings.services.aws.timeoutMs);
    awsOk = !!r.ok; awsStatus = r.status;
  } catch (e) {}
  const awsColor = awsOk ? 'green' : 'red';
  details.push({ name: 'aws', ok: awsOk, color: awsColor, status: awsStatus });
  global._serviceSummary.aws = { ts: now, color: awsColor, ok: awsOk };

  const overall = circl.ok && nvd.ok;

  // Store this hourly check in the database
  db.insertUptime(now, overall, details);
  db.purgeUptime(settings.polling.uptimeMaxAgeDays);

  return { ok: overall, services: details };
}

// Prefill uptime DB with OK entries for the last N days if empty
function prefillUptime() {
  const count = db.getUptimeCount();
  if (count > 0) return; // already has data
  const now = Date.now();
  const hours = settings.polling.uptimePrefillDays * 24;
  for (let i = hours - 1; i >= 1; i--) { // leave last slot for live ping
    const ts = now - i * 60 * 60 * 1000;
    db.insertUptime(ts, true, [{ name: 'prefill', ok: true, note: 'prefilled' }]);
  }
  console.log(`Prefilled ${hours - 1} uptime entries for last ${settings.polling.uptimePrefillDays} days`);
}

// Fast Microsoft polls (every 10s for UI responsiveness)
async function pollMicrosoftFast() {
  try {
    const msResults = [];
    for (const h of settings.services.microsoft.hosts) {
      const r = await probeUrl(h, settings.services.microsoft.timeoutMs);
      const reachable = (r && typeof r.status === 'number') ? (r.status < 500) : !!r.ok;
      msResults.push({ host: h.replace(/^https?:\/\//, '').replace(/\/+$/, ''), ok: reachable, status: r.status });
    }
    const msDown = msResults.filter(x => !x.ok).length;
    let msColor = 'green';
    if (msDown === 1) msColor = 'yellow';
    if (msDown >= 2) msColor = 'red';
    global._serviceSummary.microsoft = { ts: Date.now(), color: msColor, hosts: msResults };
  } catch (e) {}
}

// Fast Cloudflare/AWS polls (every minute for UI)
async function pollCloudflareAws() {
  try {
    const cf1 = await probeUrl(settings.services.cloudflare.hosts[0], settings.services.cloudflare.timeoutMs);
    const cf0 = await probeUrl(settings.services.cloudflare.hosts[1], settings.services.cloudflare.timeoutMs);
    const cfDown = [cf1, cf0].filter(x => !x.ok).length;
    let cfColor = 'green'; if (cfDown === 1) cfColor = 'yellow'; if (cfDown >= 2) cfColor = 'red';
    global._serviceSummary.cloudflare = { ts: Date.now(), color: cfColor, hosts: [{ host: '1.1.1.1', ok: cf1.ok }, { host: '1.0.0.1', ok: cf0.ok }] };

    const awsProbe = await probeUrl(settings.services.aws.url, settings.services.aws.timeoutMs);
    global._serviceSummary.aws = { ts: Date.now(), color: awsProbe.ok ? 'green' : 'red', ok: awsProbe.ok };
  } catch (e) {}
}

// =========================================================================
//  GEO-IP CACHE (in-memory, avoid hammering free API)
// =========================================================================
const _geoIpCache = new Map();
const GEO_IP_TTL = 60 * 60 * 1000; // 1 hour

async function lookupGeoIp(ip) {
  const cached = _geoIpCache.get(ip);
  if (cached && Date.now() - cached.ts < GEO_IP_TTL) return cached.data;
  try {
    const url = settings.geoip.apiUrl.replace('{ip}', encodeURIComponent(ip));
    const r = await fetch(url);
    const data = await r.json();
    if (data && data.status === 'success') {
      const result = { countryCode: data.countryCode };
      _geoIpCache.set(ip, { ts: Date.now(), data: result });
      return result;
    }
  } catch (e) {}
  return { countryCode: '' };
}

// =========================================================================
//  API ROUTES
// =========================================================================

// Visitor IP + country — use external service so we always get the public IP
app.get('/api/myip', async (req, res) => {
  try {
    // Try to get external/public IP from ip-api (returns requester's public IP when called with no argument)
    const r = await fetch('http://ip-api.com/json/?fields=status,query,countryCode');
    const data = await r.json();
    if (data && data.status === 'success') {
      return res.json({ ip: data.query || '', countryCode: data.countryCode || '' });
    }
  } catch (e) { /* fall through */ }
  // Fallback: use request header
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
  const cleanIp = ip.replace(/^::ffff:/, '');
  const geo = await lookupGeoIp(cleanIp);
  res.json({ ip: cleanIp, countryCode: geo.countryCode || '' });
});

// CVEs from database (supports server-side CVSS filtering)
app.get('/api/cves', (req, res) => {
  const count = Math.min(parseInt(req.query.count || '50', 10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  const cvssMin = req.query.cvssMin ? parseFloat(req.query.cvssMin) : null;
  const cves = db.getCvesFiltered(count, offset, cvssMin);
  res.json(cves);
});

// Load more CVEs — if DB has no more, fetch fresh from source
app.get('/api/cves/more', async (req, res) => {
  const count = Math.min(parseInt(req.query.count || '50', 10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  let cves = db.getCves(count, offset);
  if (cves.length === 0) {
    // Try a fresh fetch from CIRCL
    try {
      const r = await fetch(`${settings.cve.circlLastUrl}/${count}`);
      let data = await r.json();
      if (!Array.isArray(data)) {
        if (data && Array.isArray(data.value)) data = data.value;
        else data = [];
      }
      for (const it of data) {
        const id = extractItemId(it);
        if (!id) continue;
        const d = extractItemDate(it);
        db.upsertCve(id, it, d ? d.toISOString() : null, extractCvssScore(it));
      }
      cves = db.getCves(count, offset);
    } catch (e) {
      console.error('cves/more fallback error:', e && e.message);
    }
  }
  res.json(cves);
});

// News from database
app.get('/api/rss', (req, res) => {
  const count = Math.min(parseInt(req.query.count || '50', 10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  const news = db.getNews(count, offset);
  res.json(news);
});

// Load more news — if DB has no more, fetch fresh from source
app.get('/api/rss/more', async (req, res) => {
  const count = Math.min(parseInt(req.query.count || '50', 10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  let news = db.getNews(count, offset);
  if (news.length === 0) {
    try {
      const items = await fetchAllFeeds();
      for (const it of items) db.upsertNews(it);
      news = db.getNews(count, offset);
    } catch (e) {
      console.error('rss/more fallback error:', e && e.message);
    }
  }
  res.json(news);
});

// Service status
app.get('/api/status', async (req, res) => {
  try {
    // Return cached fast-poll data when available
    const details = [];
    const ms = global._serviceSummary.microsoft;
    if (ms) details.push({ name: 'microsoft', ok: ms.color === 'green', color: ms.color, hosts: ms.hosts });
    const cf = global._serviceSummary.cloudflare;
    if (cf) details.push({ name: 'cloudflare', ok: cf.color === 'green', color: cf.color, hosts: cf.hosts });
    const aws = global._serviceSummary.aws;
    if (aws) details.push({ name: 'aws', ok: !!aws.ok, color: aws.color || (aws.ok ? 'green' : 'red') });
    res.json({ ok: details.every(d => d.ok), services: details });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Uptime history (returns last 24h from DB)
app.get('/api/uptime', (req, res) => {
  try {
    const data = db.getUptime(settings.polling.uptimeDisplayHours);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Uptime stats — 30-day percentage
app.get('/api/uptime-stats', (req, res) => {
  try {
    const data = db.getUptime(settings.polling.uptimeMaxAgeDays * 24);
    const total = data.length;
    const okCount = data.filter(d => d.ok).length;
    const pct = total > 0 ? (okCount / total) * 100 : 100;
    res.json({ total, ok: okCount, percentage: pct });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Zero-days (live CIRCL scan)
app.get('/api/zero-days', async (req, res) => {
  const count = parseInt(req.query.count || '200', 10);
  try {
    const r = await fetch(settings.cve.circlLastUrl);
    let data = await r.json();
    if (!Array.isArray(data)) {
      if (data && Array.isArray(data.value)) data = data.value;
      else return res.status(502).json({ error: 'unexpected response' });
    }
    const zeroDayRegex = /\bzero[- ]?day\b|\b0[- ]?day\b|zero\sday/i;
    const filtered = data.slice(0, count).filter(item => {
      const s = extractSummary(item) || '';
      return zeroDayRegex.test(s);
    });
    res.json(filtered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function extractSummary(item) {
  if (!item) return '';
  if (item.summary) return item.summary;
  if (item.description) return item.description;
  // NVD v2 format
  if (Array.isArray(item.descriptions) && item.descriptions.length) {
    const d = item.descriptions.find(d => d.lang === 'en') || item.descriptions[0];
    if (d && d.value) return d.value;
  }
  if (item.containers && item.containers.cna) {
    const cna = item.containers.cna;
    if (cna.descriptions && cna.descriptions.length) {
      const d = cna.descriptions[0];
      return d.value || d.description || d.text || '';
    }
  }
  if (item.document && item.document.notes && item.document.notes.length) {
    const note = item.document.notes.find(n => n.category === 'summary') || item.document.notes[0];
    return (note && (note.text || note.title)) || '';
  }
  return '';
}

// Single CVE lookup
app.get('/api/cve/:id', async (req, res) => {
  const id = req.params.id;
  if (!id) return res.status(400).json({ error: 'missing id' });
  try {
    const r = await fetch(`${settings.cve.circlCveUrl}/${encodeURIComponent(id)}`);
    if (!r.ok) return res.status(r.status).json({ error: 'fetch failed' });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// CVE daily stats
app.get('/api/cve-stats', (req, res) => {
  try {
    const rows = db.getCveDailyCounts(30);
    if (rows.length > 0) return res.json(rows);
    // fallback: compute from stored CVEs
    const counts = computeCveCountsFromDb();
    res.json(counts);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function computeCveCountsFromDb() {
  const d = db.getDb();
  const now = new Date();
  const result = [];
  for (let i = 29; i >= 0; i--) {
    const day = new Date(now.getTime() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const row = d.prepare(`SELECT COUNT(*) as cnt FROM cves WHERE published LIKE ?`).get(day + '%');
    result.push({ date: day, count: row ? row.cnt : 0 });
  }
  return result;
}

// Update daily CVE counts from DB data
function updateCveDailyCounts() {
  const counts = computeCveCountsFromDb();
  for (const c of counts) {
    db.upsertCveDailyCount(c.date, c.count);
  }
  console.log(`Updated CVE daily counts: ${counts.length} days`);
}

// =========================================================================
//  PUBLIC SETTINGS (safe subset for frontend)
// =========================================================================
app.get('/api/settings/public', (req, res) => {
  res.json({
    siteName: settings.siteName || 'Security dashboard',
    logo: settings.logo || ''
  });
});

// =========================================================================
//  STARTUP & SCHEDULING
// =========================================================================
const PORT = settings.server.port || process.env.PORT || 3000;

(async () => {
  // Prefill uptime if DB is empty
  prefillUptime();

  // Backfill CVSS scores for existing rows
  backfillCvssScores();

  // Initial data polls
  console.log('Polling CVEs...');
  await pollCves();

  // Backfill CVEs from NVD if DB is sparse (rate-limited, runs in background)
  backfillCvesFromNvd().catch(e => console.error('backfillCves error:', e && e.message));
  console.log('Polling News...');
  await pollNews();
  console.log('Checking services (live ping for uptime)...');
  await checkServices();

  // Update CVE daily counts
  updateCveDailyCounts();

  // Fast service polls for UI responsiveness
  pollMicrosoftFast().catch(() => {});
  setInterval(() => pollMicrosoftFast().catch(() => {}), (settings.services.microsoft.pollIntervalSeconds || 10) * 1000);
  pollCloudflareAws().catch(() => {});
  setInterval(() => pollCloudflareAws().catch(() => {}), 60 * 1000);

  // Scheduled polls
  setInterval(pollCves, settings.polling.cveIntervalMinutes * 60 * 1000);
  setInterval(pollNews, settings.polling.newsIntervalMinutes * 60 * 1000);
  setInterval(async () => {
    await checkServices();
    updateCveDailyCounts();
  }, settings.polling.uptimeIntervalMinutes * 60 * 1000);

  app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
})();
