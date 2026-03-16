const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const db = require('./db');

// --- Load settings (server-side only, never served publicly) ---
const settings = JSON.parse(fs.readFileSync(path.join(__dirname, 'settings.json'), 'utf8'));

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(cors());

// Security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https://flagcdn.com; connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

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
          const enrichment = enrichCveItem(id, cve);
          db.upsertCve(id, cve, pub && !isNaN(pub.getTime()) ? pub.toISOString() : null, extractCvssScore(cve), enrichment);
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
      const enrichment = enrichCveItem(id, it);
      // upsert — SQLite handles dedup by primary key
      db.upsertCve(id, it, published, extractCvssScore(it), enrichment);
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
//  KEV (CISA Known Exploited Vulnerabilities) POLLING
// =========================================================================
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

async function pollKev() {
  try {
    console.log('Polling CISA KEV catalog...');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const r = await fetch(KEV_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!r.ok) { console.error('KEV fetch failed:', r.status); return; }
    const json = await r.json();
    const vulns = json.vulnerabilities || [];
    let added = 0;
    for (const v of vulns) {
      if (!v.cveID) continue;
      db.upsertKev(v.cveID, v.vendorProject || '', v.product || '', v.dateAdded || '', v.shortDescription || '');
      added++;
    }
    console.log(`KEV: ${added} entries cached`);
    // Mark matching CVEs in the database
    const kevSet = db.getKevSet();
    const d = db.getDb();
    const rows = d.prepare(`SELECT id FROM cves WHERE kev = 0 OR kev IS NULL`).all();
    let marked = 0;
    for (const row of rows) {
      if (kevSet.has(row.id)) {
        db.updateCveEnrichment(row.id, { kev: true });
        marked++;
      }
    }
    if (marked > 0) console.log(`KEV: marked ${marked} existing CVEs`);
    // Also apply KEV vendor info to CVEs missing vendor
    const kevRows = db.getKevEntries();
    let vendorFilled = 0;
    for (const kv of kevRows) {
      if (!kv.vendor) continue;
      const cveRow = d.prepare(`SELECT vendor FROM cves WHERE id = ?`).get(kv.cve_id);
      if (cveRow && (!cveRow.vendor || cveRow.vendor === '')) {
        db.updateCveEnrichment(kv.cve_id, { vendor: kv.vendor, kev: true });
        vendorFilled++;
      }
    }
    if (vendorFilled > 0) console.log(`KEV: filled vendor for ${vendorFilled} CVEs`);
  } catch (e) {
    console.error('KEV poll error:', e && e.message);
  }
}

// =========================================================================
//  CVE ENRICHMENT (extract vendor, discovered, exploit/patch from data)
// =========================================================================
// Vendor blocklist (module-scoped, created once)
const VENDOR_BLOCKLIST = new Set([
  'chrome-cve-admin','security_alert','security-advisories','security','audit',
  'cna','disclosure','psirt','secure','vulnerabilities','vulnerability','scy',
  'cve-coordination','ics-cert','cybersecurity','infosec','product-security',
  'productsecurity','product-cve','csirt','cert-in','certcc','sirt','prodsec',
  'secalert','secalert_us','responsibledisclosure','vulnreport','reachout',
  'contact','info','support','nvd','nist','zdi-disclosures','cvd','n/a',
  'openclaw','open-emr','oretnom23','fabian','iletisim','gfi','nsasoft',
  'vulncheck','patchstack','wordfence','hackerone','rapid7','snyk','tenable',
  'trendmicro','qualys','checkmarx','sonatype','portswigger','acunetix',
  'beyondtrust','securin','appcheck','vdiscover','idefense','flexera',
  'veracode','mend','whitesource','incibe','jpcert','kcirt','krcert',
  'mitre','github',
  'the','this','that','shared','progress','with','from','for','and',
  'not','was','has','had','are','were','been','being','have','does',
  'its','all','any','each','every','some','other','another','such',
  'cross-site','improper','missing','multiple','remote','local','use',
  'sql','buffer','stack','heap','integer','null','type','path','file',
  'server','client','user','admin','system','network','web','application'
]);

function enrichCveItem(id, item) {
  const enrichment = {};

  // Discovered date (dateReserved = when CVE ID was assigned, or lastModified as fallback)
  try {
    const reserved = item.cveMetadata && item.cveMetadata.dateReserved;
    if (reserved) {
      const d = new Date(reserved);
      if (!isNaN(d.getTime())) enrichment.discovered = d.toISOString();
    }
    if (!enrichment.discovered && item.lastModified) {
      const d = new Date(item.lastModified);
      if (!isNaN(d.getTime())) enrichment.discovered = d.toISOString();
    }
  } catch (e) {}

  // Vendor extraction
  try {
    function isValidVendor(v) {
      if (!v || v.length <= 2 || v.length > 30) return false;
      if (VENDOR_BLOCKLIST.has(v.toLowerCase())) return false;
      if (/^[0-9a-f-]{20,}$/i.test(v)) return false;
      return true;
    }
    // CIRCL / CVE 5.0 format
    if (item.containers && item.containers.cna && item.containers.cna.affected) {
      const aff = item.containers.cna.affected;
      if (Array.isArray(aff) && aff.length > 0 && aff[0].vendor && isValidVendor(aff[0].vendor)) {
        enrichment.vendor = aff[0].vendor;
      }
    }
    // NVD v2 format: configurations -> nodes -> cpeMatch -> criteria
    if (!enrichment.vendor && item.configurations) {
      const configs = Array.isArray(item.configurations) ? item.configurations : [item.configurations];
      outer:
      for (const cfg of configs) {
        const nodes = cfg.nodes || (cfg.cpeMatch ? [cfg] : []);
        for (const node of nodes) {
          const matches = node.cpeMatch || [];
          for (const m of matches) {
            if (m.criteria) {
              const parts = m.criteria.split(':');
              if (parts.length > 3 && parts[3] && parts[3] !== '*' && isValidVendor(parts[3])) {
                enrichment.vendor = parts[3];
                break outer;
              }
            }
          }
        }
      }
    }
    // CSAF format: extract vendor from product_tree CPE helpers
    if (!enrichment.vendor && item.product_tree && item.product_tree.branches) {
      csafOuter:
      for (const branch of item.product_tree.branches) {
        const stack = [branch];
        while (stack.length) {
          const node = stack.pop();
          const cpe = node.product && node.product.product_identification_helper && node.product.product_identification_helper.cpe;
          if (cpe) {
            const parts = cpe.replace('cpe:/', 'cpe:2.3:').split(':');
            if (parts.length > 3 && parts[3] && parts[3] !== '*' && isValidVendor(parts[3])) {
              enrichment.vendor = parts[3];
              break csafOuter;
            }
          }
          if (Array.isArray(node.branches)) {
            for (const child of node.branches) stack.push(child);
          }
        }
      }
    }
    // (Removed unreliable email-domain and description-pattern vendor extraction;
    //  only structured API data from affected[], CPE configs, and CSAF product_tree is used.)
  } catch (e) {}

  // Exploit and Patch detection from references
  try {
    let refs = [];
    // NVD references
    if (Array.isArray(item.references)) refs = refs.concat(item.references);
    // CIRCL containers.cna.references
    if (item.containers && item.containers.cna && Array.isArray(item.containers.cna.references)) {
      refs = refs.concat(item.containers.cna.references);
    }
    let hasExploit = false;
    let hasPatch = false;
    for (const ref of refs) {
      const tags = ref.tags || [];
      const url = (ref.url || '').toLowerCase();
      // Check tags
      for (const tag of tags) {
        const t = String(tag).toLowerCase();
        if (t === 'exploit' || t.includes('exploit')) hasExploit = true;
        if (t === 'patch' || t.includes('patch')) hasPatch = true;
      }
      // Check URL patterns
      if (url.includes('exploit-db.com') || url.includes('packetstorm') || url.includes('/poc') || url.includes('proof-of-concept')) hasExploit = true;
      if (url.includes('/patch') || url.includes('/fix') || url.includes('/advisory') || url.includes('security-update')) hasPatch = true;
    }
    enrichment.has_exploit = hasExploit;
    enrichment.has_patch = hasPatch;
  } catch (e) {}

  return enrichment;
}

// Enrich all existing CVEs missing enrichment data
function enrichExistingCves() {
  const d = db.getDb();
  // Re-enrich ALL CVEs so updated blocklist/logic clears stale vendor values
  const rows = d.prepare(`SELECT id, data FROM cves LIMIT 10000`).all();
  if (rows.length === 0) return;
  let enriched = 0;
  const kevSet = db.getKevSet();
  for (const row of rows) {
    try {
      const item = JSON.parse(row.data);
      const e = enrichCveItem(row.id, item);
      if (kevSet.has(row.id)) {
        e.kev = true;
        e.has_exploit = true; // KEV = known exploited
      }
      // Explicitly set vendor to '' when enrichment produces nothing,
      // so stale bad values get cleared
      if (!e.vendor) e.vendor = '';
      db.updateCveEnrichment(row.id, e);
      enriched++;
    } catch (err) {}
  }
  console.log(`Enriched ${enriched}/${rows.length} CVEs with metadata`);
}

// Fetch vendor/product from CIRCL CVE 5.0 API for CVEs missing vendor data.
// NVD v2 responses often lack the affected[] array, but CIRCL has it.
async function enrichVendorsFromCircl() {
  const d = db.getDb();
  const rows = d.prepare("SELECT id FROM cves WHERE (vendor IS NULL OR vendor = '') AND id LIKE 'CVE-%' ORDER BY published DESC LIMIT 2000").all();
  if (rows.length === 0) { console.log('CIRCL vendor enrichment: all CVEs have vendors'); return; }
  console.log(`CIRCL vendor enrichment: ${rows.length} CVEs missing vendor, fetching from CIRCL...`);
  let filled = 0;
  const BATCH_SIZE = 10;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const results = await Promise.allSettled(batch.map(async (row) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        const r = await fetch(`${settings.cve.circlCveUrl}/${row.id}`, { signal: controller.signal });
        clearTimeout(timer);
        if (!r.ok) return null;
        const data = await r.json();
        const e = enrichCveItem(row.id, data);
        if (e.vendor) {
          db.updateCveEnrichment(row.id, { vendor: e.vendor });
          // Also update stored data with richer CIRCL payload so future enrichments work
          d.prepare('UPDATE cves SET data = ? WHERE id = ?').run(JSON.stringify(data), row.id);
          return e.vendor;
        }
      } catch (err) {}
      return null;
    }));
    filled += results.filter(r => r.status === 'fulfilled' && r.value).length;
    // Rate limit: ~1 second pause between batches
    if (i + BATCH_SIZE < rows.length) await new Promise(resolve => setTimeout(resolve, 1000));
  }
  console.log(`CIRCL vendor enrichment: filled vendor for ${filled}/${rows.length} CVEs`);
}

// =========================================================================
//  REPORT GENERATION
// =========================================================================
function generateReport() {
  console.log('Generating vulnerability report...');
  const stats = db.getReportStats(30);
  const topVendors = db.getTopVendors(30, 8);
  const kevCves = db.getReportCves({ days: 30, kevOnly: true });
  const highNoPatch = db.getReportCves({ days: 30, minCvss: 8, noPatchOnly: true, limit: 50 });
  const critWithPatch = db.getReportCves({ days: 30, minCvss: 9, patchOnly: true, limit: 50 });

  const report = {
    stats,
    topVendors,
    kevCves: kevCves.map(simplify),
    highNoPatch: highNoPatch.map(simplify),
    critWithPatch: critWithPatch.map(simplify)
  };
  db.saveReport(report);
  console.log(`Report generated: ${stats.total} CVEs, ${stats.critical} critical, ${stats.kevCount} KEV`);
}

// Slim down CVE objects for the report (avoid storing full JSON blobs)
function simplify(item) {
  const id = extractItemId(item) || item.id || '';
  return {
    id,
    cvss: item._cvss || extractCvssScore(item) || null,
    vendor: item._vendor || '',
    kev: item._kev || 0,
    exploit: item._exploit || 0,
    patch: item._patch || 0,
    published: extractItemDate(item) ? extractItemDate(item).toISOString() : (item._published || null),
    discovered: item._discovered || null,
    summary: extractSummary(item) || ''
  };
}

// =========================================================================
//  GEO-IP CACHE (in-memory, avoid hammering free API)
// =========================================================================
const _geoIpCache = new Map();
const GEO_IP_TTL = 60 * 60 * 1000; // 1 hour
const GEO_IP_MAX_SIZE = 500; // cap cache size

async function lookupGeoIp(ip) {
  // Skip lookup for private/reserved IPs (Docker bridge, localhost, etc.)
  if (!ip || /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|::1|localhost)/i.test(ip)) {
    return { countryCode: '' };
  }
  const cached = _geoIpCache.get(ip);
  if (cached && Date.now() - cached.ts < GEO_IP_TTL) return cached.data;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const url = settings.geoip.apiUrl.replace('{ip}', encodeURIComponent(ip));
    const r = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    const data = await r.json();
    if (data && data.status === 'success') {
      const result = { countryCode: data.countryCode };
      if (_geoIpCache.size >= GEO_IP_MAX_SIZE) {
        // Evict oldest entry
        const firstKey = _geoIpCache.keys().next().value;
        _geoIpCache.delete(firstKey);
      }
      _geoIpCache.set(ip, { ts: Date.now(), data: result });
      return result;
    }
  } catch (e) {}
  return { countryCode: '' };
}

// =========================================================================
//  API RESPONSE CACHE (short TTL to avoid redundant DB queries)
// =========================================================================
const _apiCache = new Map();
function cachedJson(res, key, ttlMs, computeFn) {
  const cached = _apiCache.get(key);
  if (cached && Date.now() - cached.ts < ttlMs) {
    return res.json(cached.data);
  }
  const data = computeFn();
  _apiCache.set(key, { ts: Date.now(), data });
  return res.json(data);
}

// =========================================================================
//  API ROUTES
// =========================================================================

// Visitor IP + country — use x-forwarded-for behind proxy, fallback to direct connection
app.get('/api/myip', async (req, res) => {
  // Prefer x-forwarded-for from reverse proxy, then direct socket IP
  const raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.socket?.remoteAddress || '';
  const cleanIp = raw.replace(/^::ffff:/, '');
  // Lookup country for the visitor's IP
  const geo = await lookupGeoIp(cleanIp);
  res.json({ ip: cleanIp, countryCode: geo.countryCode || '' });
});

// CVEs from database (supports server-side CVSS filtering)
app.get('/api/cves', (req, res) => {
  const count = Math.min(parseInt(req.query.count || '50', 10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  const cvssMin = req.query.cvssMin ? parseFloat(req.query.cvssMin) : null;
  const cacheKey = 'cves:' + count + ':' + offset + ':' + (cvssMin || '');
  cachedJson(res, cacheKey, 30000, () => db.getCvesFiltered(count, offset, cvssMin));
});

// Search CVEs in database
app.get('/api/cves/search', (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  try {
    const results = db.searchCves(q, limit);
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
        const enrichment = enrichCveItem(id, it);
        db.upsertCve(id, it, d ? d.toISOString() : null, extractCvssScore(it), enrichment);
      }
      cves = db.getCves(count, offset);
    } catch (e) {
      console.error('cves/more fallback error:', e && e.message);
    }
  }
  res.json(cves);
});

// News sources list
app.get('/api/news-sources', (req, res) => {
  const sources = db.getNewsSources();
  res.json(sources);
});

// News from database
app.get('/api/rss', (req, res) => {
  const count = Math.min(parseInt(req.query.count || '50', 10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  const sourceParam = req.query.source || '';
  const sources = sourceParam ? sourceParam.split(',').map(s => s.trim()).filter(Boolean) : [];
  const news = db.getNews(count, offset, sources.length > 0 ? sources : undefined);
  res.json(news);
});

// Search news in database
app.get('/api/rss/search', (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  try {
    const results = db.searchNews(q, limit);
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
    cachedJson(res, 'cve-stats', 60000, () => {
      const rows = db.getCveDailyCounts(30);
      if (rows.length > 0) return rows;
      return computeCveCountsFromDb();
    });
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
  const links = settings.links || { name: 'Links', items: [] };
  res.json({
    siteName: settings.siteName || 'Security dashboard',
    logo: settings.logo || '',
    links,
    animatedBackground: settings.animatedBackground !== false,
    tickerFeed: settings.tickerFeed || '',
    footerText: settings.footerText || '\u00a9 2026 lundstream.net, all rights reserved.',
    showGithubLink: settings.showGithubLink !== false,
    hibpEnabled: !!(settings.hibpApiKey || process.env.HIBP_API_KEY || '').trim()
  });
});

// Ticker RSS feed endpoint — fetches and parses a single RSS feed for the header ticker
app.get('/api/ticker', async (req, res) => {
  const feedUrl = settings.tickerFeed;
  if (!feedUrl) return res.json([]);
  try {
    const resp = await fetch(feedUrl, { timeout: 10000 });
    if (!resp.ok) return res.json([]);
    const xml = await resp.text();
    const items = [];
    const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
    let match;
    while ((match = itemRegex.exec(xml)) !== null && items.length < 20) {
      const block = match[1];
      const title = (block.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/) || [])[1] || '';
      const link = (block.match(/<link>([\s\S]*?)<\/link>/) || [])[1] || '';
      if (title.trim()) items.push({ title: title.trim(), link: link.trim() });
    }
    res.json(items);
  } catch (e) {
    res.json([]);
  }
});

// Report data (supports ?period=week or ?period=month, ?vendor=name)
app.get('/api/report', (req, res) => {
  try {
    const p = req.query.period;
    const period = p === 'week' ? 'week' : p === 'yesterday' ? 'yesterday' : 'month';
    const days = period === 'week' ? 7 : period === 'yesterday' ? 1 : 30;
    const vendorParam = req.query.vendor || null;
    const vendor = vendorParam ? vendorParam.split(',').map(v => v.trim()).filter(Boolean) : null;
    const cacheKey = 'report:' + period + ':' + (vendor ? vendor.sort().join(',') : '');
    cachedJson(res, cacheKey, 30000, () => {
      const stats = db.getReportStats(days, vendor);
      const topVendors = vendor ? db.getTopVendorsWithBreakdown(days, vendor.length, vendor) : db.getTopVendorsWithBreakdown(days, 8);
      const kevCves = db.getReportCves({ days, kevOnly: true, vendor });
      const highNoPatch = db.getReportCves({ days, minCvss: 8, noPatchOnly: true, limit: 50, vendor });
      const critWithPatch = db.getReportCves({ days, minCvss: 9, patchOnly: true, limit: 50, vendor });
      return {
        period,
        days,
        generatedAt: new Date().toISOString(),
        stats,
        topVendors,
        kevCves: kevCves.map(simplify),
        highNoPatch: highNoPatch.map(simplify),
        critWithPatch: critWithPatch.map(simplify)
      };
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Vendor list for filter dropdown
app.get('/api/vendors', (req, res) => {
  try {
    const days = req.query.days ? parseInt(req.query.days, 10) : 30;
    cachedJson(res, 'vendors:' + days, 60000, () => db.getVendorList(Math.min(days, 365)));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Top vendors for dashboard donut chart
app.get('/api/top-vendors', (req, res) => {
  try {
    const vendors = db.getTopVendors(30, 7);
    res.json(vendors);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================================================================
//  PATCH TUESDAY API
// =========================================================================

// Compute the second Tuesday of a given month
function getSecondTuesday(year, month) {
  const first = new Date(year, month, 1);
  const dayOfWeek = first.getDay(); // 0=Sun
  const daysUntilTuesday = (9 - dayOfWeek) % 7; // days until first Tuesday
  const firstTuesday = 1 + daysUntilTuesday;
  return new Date(year, month, firstTuesday + 7); // second Tuesday
}

// Timezone-safe local date string (YYYY-MM-DD)
function localDateStr(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function getNextPatchTuesday() {
  const now = new Date();
  const thisMonth = getSecondTuesday(now.getFullYear(), now.getMonth());
  if (thisMonth > now) return thisMonth;
  // This month's PT already passed — next month
  const nm = now.getMonth() + 1;
  const ny = nm > 11 ? now.getFullYear() + 1 : now.getFullYear();
  return getSecondTuesday(ny, nm % 12);
}

// Get the current (most recent or today's) Patch Tuesday
function getCurrentPatchTuesday() {
  const now = new Date();
  const thisMonth = getSecondTuesday(now.getFullYear(), now.getMonth());
  if (localDateStr(thisMonth) === localDateStr(now) || thisMonth <= now) return thisMonth;
  // This month's PT hasn't happened yet — use last month's
  const pm = now.getMonth() - 1;
  const py = pm < 0 ? now.getFullYear() - 1 : now.getFullYear();
  return getSecondTuesday(py, (pm + 12) % 12);
}

function getPatchTuesdayDates(count) {
  const dates = [];
  const now = new Date();
  let y = now.getFullYear(), m = now.getMonth();
  for (let i = 0; i < count; i++) {
    const pt = getSecondTuesday(y, m);
    dates.push(pt);
    m--;
    if (m < 0) { m = 11; y--; }
  }
  return dates;
}

// Build AI prompt specifically for Patch Tuesday analysis
function buildPatchTuesdayAiPrompt(language) {
  language = language || 'en';

  // Get CVEs from the last 30 days (covers the current PT cycle)
  const stats = db.getReportStats(30);
  const topVendors = db.getTopVendorsWithBreakdown(30, 15);
  const kevCves = db.getReportCves({ days: 30, kevOnly: true }).map(simplify);
  const critCves = db.getReportCves({ days: 30, minCvss: 9, limit: 25 }).map(simplify);
  const highNoPatch = db.getReportCves({ days: 30, minCvss: 7, noPatchOnly: true, limit: 20 }).map(simplify);
  const news = db.getRecentNews(14);

  // Focus on Microsoft specifically
  const msVendors = topVendors.filter(v => /microsoft|windows|office|edge|exchange|azure/i.test(v.vendor));
  const msCves = db.getReportCves({ days: 30, vendor: 'Microsoft', limit: 30 }).map(simplify);

  const vendorSummary = topVendors.map(v =>
    `  ${v.vendor}: ${v.cnt} CVEs (critical:${v.critical||0}, high:${v.high||0}, KEV:${v.kev||0})`
  ).join('\n');

  const msSummary = msCves.slice(0, 20).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 150)}`
  ).join('\n');

  const kevSummary = kevCves.slice(0, 15).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const critSummary = critCves.slice(0, 15).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const noPatchSummary = highNoPatch.slice(0, 10).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const newsSummary = news.slice(0, 20).map(n =>
    `  [${n.source}] ${n.title}`
  ).join('\n');

  const currentPt = getCurrentPatchTuesday();
  const currentPtStr = localDateStr(currentPt);
  const nextPt = getNextPatchTuesday();
  const nextPtStr = localDateStr(nextPt);

  const langInstruction = language === 'sv'
    ? 'Write the ENTIRE response in Swedish. All section headers and body text must be in Swedish. Keep CVE IDs and vendor names in their original English form.'
    : 'Write the response in English.';

  return `You are a senior IT security analyst specializing in Microsoft Patch Tuesday analysis.
IMPORTANT: This analysis is for the CURRENT Patch Tuesday cycle (${currentPtStr}), which has already occurred. Do NOT write about upcoming or future Patch Tuesdays. Do NOT use phrases like "pre-patch", "upcoming", "what to expect", or "prepare for". Write as if the patches have been released and IT teams need to act NOW.
${langInstruction}

Provide a thorough Patch Tuesday briefing for the ${currentPtStr} cycle. This should help IT administrators understand what was released and act on the patches immediately.

STRUCTURE YOUR RESPONSE WITH THESE SECTIONS (use markdown headers ##):

## ${language === 'sv' ? 'Sammanfattning Patch Tuesday' : 'Patch Tuesday Summary'}
A thorough overview of this Patch Tuesday cycle. Cover Microsoft vulnerability trends, the volume and severity of CVEs, and what areas demand immediate attention (4-6 sentences).

## ${language === 'sv' ? 'Kritiska Microsoft-sårbarheter' : 'Critical Microsoft Vulnerabilities'}
Analyze the most critical Microsoft CVEs from this cycle. For each major CVE, explain the affected product (Windows, Office, Exchange, Azure, Edge, etc.), the attack vector, real-world impact, and urgency. Focus on KEV entries and zero-days.

## ${language === 'sv' ? 'Aktiva hot och utnyttjade sårbarheter' : 'Active Threats & Exploited Vulnerabilities'}
Detail any known exploited vulnerabilities (KEV), active exploitation campaigns, and zero-day threats relevant to Microsoft products. Explain the risk and who is affected.

## ${language === 'sv' ? 'Prioriteringsguide för patchning' : 'Patch Priority Guide'}
Provide a clear priority list for IT teams:
- **${language === 'sv' ? 'Kritiskt — patcha omedelbart' : 'Critical — Patch Immediately'}**: Vulnerabilities being actively exploited or with public exploits
- **${language === 'sv' ? 'Högt — patcha inom 48 timmar' : 'High — Patch Within 48 Hours'}**: High-severity CVEs with significant impact
- **${language === 'sv' ? 'Medium — patcha inom en vecka' : 'Medium — Patch Within a Week'}**: Important but lower-risk updates

## ${language === 'sv' ? 'Drabbade produkter och komponenter' : 'Affected Products & Components'}
Break down which Microsoft products and components are most affected. Help IT teams understand which systems need attention first.

## ${language === 'sv' ? 'Rekommendationer' : 'Recommendations'}
Provide 5-8 specific, actionable recommendations for IT administrators to act on this Patch Tuesday. Include patch testing advice, rollback planning, and monitoring guidance.

Aim for approximately 1200-1500 words. Be specific and reference actual CVE IDs from the data. Focus on Microsoft products but mention other critical vendors if relevant.

--- DATA ---
THIS PATCH TUESDAY (analyze this one): ${currentPtStr}
STATS (last 30 days): ${stats.total} total CVEs, ${stats.critical} critical (CVSS>=9), ${stats.kevCount} known exploited

TOP VENDORS:
${vendorSummary || '  No vendor data available'}

MICROSOFT CVEs:
${msSummary || '  No Microsoft CVEs found'}

KNOWN EXPLOITED VULNERABILITIES (KEV):
${kevSummary || '  None in this period'}

CRITICAL CVEs (CVSS 9+):
${critSummary || '  None in this period'}

HIGH SEVERITY WITHOUT PATCHES (CVSS 7+):
${noPatchSummary || '  None in this period'}

RECENT SECURITY NEWS:
${newsSummary || '  No news available'}`;
}

async function runPatchTuesdayAiAnalysis(language) {
  language = language || 'en';
  if (!aiConfig.enabled || !aiConfig.githubToken) {
    console.log('[AI] Patch Tuesday analysis skipped (disabled or no token)');
    return null;
  }

  const prompt = buildPatchTuesdayAiPrompt(language);
  const model = aiConfig.model || 'gpt-4o-mini';
  const maxTokens = aiConfig.maxTokens || 4000;

  console.log(`[AI] Running Patch Tuesday analysis (${language}) with model ${model}...`);

  try {
    const resp = await fetch('https://models.inference.ai.azure.com/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${aiConfig.githubToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: language === 'sv'
            ? 'Du är en professionell IT-säkerhetsanalytiker som specialiserar sig på Microsoft Patch Tuesday-analys. Skriv detaljerade briefings på svenska. Använd markdown-formatering.'
            : 'You are a professional IT security analyst specializing in Microsoft Patch Tuesday analysis. Write detailed briefings. Use markdown formatting.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: maxTokens,
        temperature: 0.3
      })
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error(`[AI] PT API error ${resp.status}: ${errText}`);
      return null;
    }

    const data = await resp.json();
    const analysis = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;

    if (!analysis) {
      console.error('[AI] PT: No content in response');
      return null;
    }

    db.saveAiAnalysis('patchtuesday', analysis, language);
    console.log(`[AI] Patch Tuesday (${language}) analysis saved (${analysis.length} chars)`);
    return analysis;
  } catch (e) {
    console.error('[AI] Patch Tuesday analysis failed:', e.message);
    return null;
  }
}

async function runPatchTuesdayAiBothLanguages() {
  const en = await runPatchTuesdayAiAnalysis('en');
  const sv = await runPatchTuesdayAiAnalysis('sv');
  return { en, sv };
}

// Return Patch Tuesday info + AI analysis
app.get('/api/patchtuesday', (req, res) => {
  try {
    const nextPt = getNextPatchTuesday();
    const currentPt = getCurrentPatchTuesday();
    const language = req.query.lang === 'sv' ? 'sv' : 'en';
    const analysis = db.getLatestAiAnalysis('patchtuesday', language);

    res.json({
      nextPatchTuesday: localDateStr(nextPt),
      currentPatchTuesday: localDateStr(currentPt),
      analysis: analysis ? analysis.analysis : null,
      analysisGeneratedAt: analysis ? analysis.generated_at : null
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Manually trigger PT AI analysis
app.post('/api/patchtuesday/analyze', (req, res) => {
  runPatchTuesdayAiBothLanguages().then(result => {
    if (result.en || result.sv) res.json({ ok: true, en: !!(result.en), sv: !!(result.sv) });
    else res.json({ ok: false, error: 'Analysis failed or disabled — check server logs' });
  }).catch(e => res.status(500).json({ ok: false, error: e.message }));
});

// =========================================================================
//  NEWS SUMMARY (Omvärldsanalys) — AI-powered weekly IT news analysis
// =========================================================================

function buildNewsSummaryAiPrompt(language) {
  language = language || 'en';

  const news = db.getRecentNews(7);
  const stats = db.getReportStats(7);
  const kevCves = db.getReportCves({ days: 7, kevOnly: true }).map(simplify);

  const newsSummary = news.map(n =>
    `  [${n.source}] ${n.title}`
  ).join('\n');

  const kevSummary = kevCves.slice(0, 10).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const langInstruction = language === 'sv'
    ? 'Write the ENTIRE response in Swedish. All section headers and body text must be in Swedish.'
    : 'Write the response in English.';

  return `You are a senior IT analyst writing a weekly news briefing for Swedish IT consultants.
${langInstruction}

The target audience is IT consultants working in Sweden. Focus on the biggest IT and cybersecurity news from the past week. This is NOT a CVE report — keep CVE references to a minimum and only mention them when they are directly tied to a major news story. This should feel like a news summary / omvärldsanalys, not a vulnerability bulletin.

STRUCTURE YOUR RESPONSE WITH THESE SECTIONS (use markdown headers ##):

## ${language === 'sv' ? 'Veckans viktigaste IT-nyheter' : "This Week's Top IT News"}
Summarize the 3-5 biggest IT and cybersecurity news stories of the week. Cover breaches, major vendor announcements, policy changes, threat actor activity, and industry trends. Write 2-4 sentences per story explaining what happened and why it matters.

## ${language === 'sv' ? 'Svenska perspektivet' : 'Swedish Perspective'}
Highlight any news particularly relevant to Sweden and Nordic countries. Include CERT-SE advisories, MSB communications, Swedish government IT decisions, or incidents affecting Swedish organizations. If nothing Sweden-specific happened, discuss how global events impact Swedish IT infrastructure or organizations.

## ${language === 'sv' ? 'Branschtrender och utveckling' : 'Industry Trends & Developments'}
Cover notable technology trends, AI developments, cloud/infrastructure changes, regulatory updates (NIS2, GDPR enforcement, EU Cyber Resilience Act), and market movements relevant to IT consultants. Focus on what consultants need to know to advise their clients.

## ${language === 'sv' ? 'Hot och aktörer' : 'Threats & Actors'}
Brief overview of notable threat actor activity, ransomware campaigns, phishing trends, or supply chain attacks from the week. Keep it high-level and actionable — what should IT consultants warn their clients about?

## ${language === 'sv' ? 'Rekommendationer för IT-konsulter' : 'Recommendations for IT Consultants'}
Provide 4-6 specific, actionable takeaways for IT consultants. What should they discuss with clients? What actions should be prioritized? What trends should they be aware of?

Aim for approximately 1000-1300 words. Be informative and professional. Write from a Swedish IT industry perspective even when discussing global events.

--- DATA ---
RECENT SECURITY NEWS (last 7 days):
${newsSummary || '  No news available'}

VULNERABILITY CONTEXT (last 7 days): ${stats.total} total CVEs, ${stats.critical} critical, ${stats.kevCount} known exploited

KNOWN EXPLOITED VULNERABILITIES (for context only — don't make this the focus):
${kevSummary || '  None this week'}`;
}

async function runNewsSummaryAiAnalysis(language) {
  language = language || 'en';
  if (!aiConfig.enabled || !aiConfig.githubToken) {
    console.log('[AI] News summary analysis skipped (disabled or no token)');
    return null;
  }

  const prompt = buildNewsSummaryAiPrompt(language);
  const model = aiConfig.model || 'gpt-4o-mini';
  const maxTokens = aiConfig.maxTokens || 4000;

  console.log(`[AI] Running news summary analysis (${language}) with model ${model}...`);

  try {
    const resp = await fetch('https://models.inference.ai.azure.com/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${aiConfig.githubToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: language === 'sv'
            ? 'Du är en erfaren IT-analytiker som skriver veckovisa omvärldsanalyser för svenska IT-konsulter. Skriv professionellt och informativt på svenska. Använd markdown-formatering.'
            : 'You are an experienced IT analyst writing weekly news briefings for Swedish IT consultants. Write professionally and informatively. Use markdown formatting.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: maxTokens,
        temperature: 0.3
      })
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error(`[AI] News summary API error ${resp.status}: ${errText}`);
      return null;
    }

    const data = await resp.json();
    const analysis = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;

    if (!analysis) {
      console.error('[AI] News summary: No content in response');
      return null;
    }

    db.saveAiAnalysis('newssummary', analysis, language);
    console.log(`[AI] News summary (${language}) saved (${analysis.length} chars)`);
    return analysis;
  } catch (e) {
    console.error('[AI] News summary analysis failed:', e.message);
    return null;
  }
}

async function runNewsSummaryAiBothLanguages() {
  const en = await runNewsSummaryAiAnalysis('en');
  const sv = await runNewsSummaryAiAnalysis('sv');
  return { en, sv };
}

// Return news summary AI analysis
app.get('/api/newssummary', (req, res) => {
  try {
    const language = req.query.lang === 'sv' ? 'sv' : 'en';
    const analysis = db.getLatestAiAnalysis('newssummary', language);
    res.json({
      analysis: analysis ? analysis.analysis : null,
      analysisGeneratedAt: analysis ? analysis.generated_at : null
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================================================================
//  TOOLS API ROUTES
// =========================================================================
const dns = require('dns');
const { promisify } = require('util');
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);

// 1. Website security headers
app.get('/api/tools/headers', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  // Validate URL format
  let parsed;
  try { parsed = new URL(url); } catch (e) { return res.status(400).json({ error: 'Invalid URL' }); }
  if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).json({ error: 'Only http/https URLs allowed' });
  // Block private/internal IPs
  const hostname = parsed.hostname;
  if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|\[::1\])/i.test(hostname)) {
    return res.status(400).json({ error: 'Internal addresses not allowed' });
  }
  try {
    const resp = await fetch(url, { method: 'GET', redirect: 'follow', timeout: 10000, headers: { 'User-Agent': 'SecurityDashboard/1.0' } });
    const headers = {};
    resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    res.json({ status: resp.status, headers });
  } catch (e) {
    res.status(502).json({ error: 'Failed to fetch: ' + (e.message || 'Unknown error') });
  }
});

// 2. DNS record lookup
app.get('/api/tools/dns', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  // Basic domain validation
  if (!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  const result = {};
  try { result.A = await dnsResolve4(domain); } catch (e) { result.A = []; }
  try { result.AAAA = await dnsResolve6(domain); } catch (e) { result.AAAA = []; }
  try { result.MX = await dnsResolveMx(domain); } catch (e) { result.MX = []; }
  try { result.TXT = await dnsResolveTxt(domain); } catch (e) { result.TXT = []; }
  try { result.NS = await dnsResolveNs(domain); } catch (e) { result.NS = []; }

  // Discover subdomains via HackerTarget API + common prefixes
  const commonSubs = ['www','mail','ftp','smtp','pop','imap','webmail','ns1','ns2','mx','vpn','remote','api','app','dev','staging','test','cdn','cloud','portal','admin','blog','shop','store','git','ci','docs','status','monitor','dashboard'];
  const fqdns = new Set(commonSubs.map(s => s + '.' + domain.toLowerCase()));
  try {
    const htResp = await fetch('https://api.hackertarget.com/hostsearch/?q=' + encodeURIComponent(domain), { timeout: 8000 });
    if (htResp.ok) {
      const text = await htResp.text();
      const domLower = domain.toLowerCase();
      text.split('\n').forEach(line => {
        const host = (line.split(',')[0] || '').trim().toLowerCase();
        if (host && host.endsWith('.' + domLower) && host !== domLower) fqdns.add(host);
      });
    }
  } catch (e) { /* API lookup failed, continue with common list */ }
  const subResults = {};
  await Promise.all([...fqdns].map(async (fqdn) => {
    try {
      const ips = await dnsResolve4(fqdn);
      if (ips && ips.length) subResults[fqdn] = ips;
    } catch (e) { /* not found, skip */ }
  }));
  if (Object.keys(subResults).length) result.subdomains = subResults;

  res.json(result);
});

// 3. Malware hash checker (MalwareBazaar)
app.get('/api/tools/hash', async (req, res) => {
  const hash = req.query.hash;
  if (!hash) return res.status(400).json({ error: 'hash parameter required' });
  if (!/^[a-fA-F0-9]{32,64}$/.test(hash)) return res.status(400).json({ error: 'Invalid hash format' });
  try {
    const resp = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'query=get_info&hash=' + encodeURIComponent(hash),
      timeout: 15000
    });
    const data = await resp.json();
    if (data.query_status === 'hash_not_found' || data.query_status === 'no_results') {
      res.json({ found: false });
    } else if (data.data && data.data.length > 0) {
      const d = data.data[0];
      res.json({
        found: true,
        malware: d.signature || d.tags?.join(', ') || 'Unknown',
        source: 'MalwareBazaar (abuse.ch)',
        firstSeen: d.first_seen || '',
        lastSeen: d.last_seen || '',
        signature: d.signature || '',
        detections: d.intelligence?.uploads || ''
      });
    } else {
      res.json({ found: false });
    }
  } catch (e) {
    res.status(502).json({ error: 'Lookup failed: ' + (e.message || 'Unknown error') });
  }
});

// 4. IP Scout (ip-api.com — free, no key)
app.get('/api/tools/ip', async (req, res) => {
  const ip = req.query.ip;
  if (!ip) return res.status(400).json({ error: 'ip parameter required' });
  // Block private ranges
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1)/i.test(ip)) {
    return res.status(400).json({ error: 'Private/internal IPs not allowed' });
  }
  try {
    const resp = await fetch('http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,query', { timeout: 10000 });
    const data = await resp.json();
    if (data.status === 'fail') return res.status(400).json({ error: data.message || 'Lookup failed' });
    res.json({
      country: data.country,
      countryCode: data.countryCode,
      region: data.regionName,
      city: data.city,
      isp: data.isp,
      org: data.org,
      as: data.as,
      lat: data.lat,
      lon: data.lon,
      timezone: data.timezone,
      reverse: data.reverse
    });
  } catch (e) {
    res.status(502).json({ error: 'Lookup failed: ' + (e.message || 'Unknown error') });
  }
});

// 5. Port & Vulnerability Check (Shodan InternetDB — free, no key)
app.get('/api/tools/ports', async (req, res) => {
  let target = req.query.target;
  if (!target) return res.status(400).json({ error: 'target parameter required' });
  // If domain, resolve to IP first
  let ip = target;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) {
    try {
      const addrs = await dnsResolve4(target);
      if (addrs && addrs.length) ip = addrs[0];
      else return res.status(400).json({ error: 'Could not resolve domain' });
    } catch (e) {
      return res.status(400).json({ error: 'Could not resolve domain: ' + (e.message || '') });
    }
  }
  // Block private ranges
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0)/i.test(ip)) {
    return res.status(400).json({ error: 'Private/internal IPs not allowed' });
  }
  try {
    const resp = await fetch('https://internetdb.shodan.io/' + encodeURIComponent(ip), { timeout: 10000 });
    if (!resp.ok) {
      if (resp.status === 404) return res.json({ ip, ports: [], vulns: [], error: 'No data found for this IP in Shodan InternetDB' });
      throw new Error('Shodan API error ' + resp.status);
    }
    const data = await resp.json();
    const ports = (data.ports || []).map(p => ({ port: p, transport: 'tcp' }));
    res.json({
      ip: data.ip || ip,
      hostnames: data.hostnames || [],
      ports,
      vulns: data.vulns || [],
      os: data.os || null,
      org: null,
      isp: null
    });
  } catch (e) {
    res.status(502).json({ error: 'Lookup failed: ' + (e.message || 'Unknown error') });
  }
});

// 6. Email Breach Check (HIBP v3 API — requires hibpApiKey in settings)
app.get('/api/tools/email-breach', async (req, res) => {
  const email = (req.query.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Valid email parameter required' });
  }
  const apiKey = (settings.hibpApiKey || process.env.HIBP_API_KEY || '').trim();
  if (!apiKey) {
    return res.status(503).json({ error: 'HIBP API key not configured. Add "hibpApiKey" to settings.json.' });
  }
  try {
    const resp = await fetch('https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email) + '?truncateResponse=false', {
      headers: {
        'hibp-api-key': apiKey,
        'User-Agent': 'SecurityDashboard'
      },
      timeout: 10000
    });
    if (resp.status === 404) {
      return res.json({ breaches: [] });
    }
    if (resp.status === 429) {
      return res.status(429).json({ error: 'Rate limited by HIBP. Please wait and try again.' });
    }
    if (!resp.ok) {
      throw new Error('HIBP API error ' + resp.status);
    }
    const breaches = await resp.json();
    res.json({ breaches: Array.isArray(breaches) ? breaches : [] });
  } catch (e) {
    res.status(502).json({ error: 'Lookup failed: ' + (e.message || 'Unknown error') });
  }
});

// =========================================================================
//  AI ANALYSIS (GitHub Models API)
// =========================================================================
const aiConfig = settings.ai || {};
// Allow environment variables to override settings (useful for Docker)
if (process.env.AI_GITHUB_TOKEN) {
  aiConfig.githubToken = process.env.AI_GITHUB_TOKEN;
  aiConfig.enabled = true; // auto-enable when token is provided via env
}
if (process.env.AI_RUN_ON_BOOT !== undefined) aiConfig.runOnBoot = Number(process.env.AI_RUN_ON_BOOT);

function buildAiPrompt(period, language) {
  language = language || 'en';
  const days = period === 'week' ? 7 : period === 'yesterday' ? 1 : 30;
  const periodLabel = period === 'week' ? 'Weekly (Last 7 Days)' : period === 'yesterday' ? 'Daily (Yesterday)' : 'Monthly (Last 30 Days)';

  const stats = db.getReportStats(days);
  const topVendors = db.getTopVendorsWithBreakdown(days, 10);
  const kevCves = db.getReportCves({ days, kevOnly: true }).map(simplify);
  const critCves = db.getReportCves({ days, minCvss: 9, limit: 20 }).map(simplify);
  const highNoPatch = db.getReportCves({ days, minCvss: 8, noPatchOnly: true, limit: 15 }).map(simplify);
  const news = db.getRecentNews(days);

  const vendorSummary = topVendors.map(v =>
    `  ${v.vendor}: ${v.cnt} CVEs (critical:${v.critical||0}, high:${v.high||0}, KEV:${v.kev||0})`
  ).join('\n');

  const kevSummary = kevCves.slice(0, 15).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const critSummary = critCves.slice(0, 15).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const noPatchSummary = highNoPatch.slice(0, 10).map(c =>
    `  ${c.id} [CVSS:${c.cvss||'?'}] ${c.vendor} - ${(c.summary||'').slice(0, 120)}`
  ).join('\n');

  const newsSummary = news.slice(0, 25).map(n =>
    `  [${n.source}] ${n.title}`
  ).join('\n');

  const langInstruction = language === 'sv'
    ? 'Write the ENTIRE response in Swedish. All section headers and body text must be in Swedish. Keep CVE IDs and vendor names in their original English form.'
    : 'Write the response in English.';

  return `You are a senior IT security analyst. Provide a detailed and thorough ${periodLabel} security analysis based on the data below.
${langInstruction}

STRUCTURE YOUR RESPONSE WITH THESE SECTIONS (use markdown headers ##):
## ${language === 'sv' ? 'Sammanfattning' : 'Executive Summary'}
A thorough overview of the threat landscape this period (4-6 sentences). Cover the overall trend, volume changes, and notable patterns.

## ${language === 'sv' ? 'Kritiska hot och s\u00e5rbarheter' : 'Key Threats & Vulnerabilities'}
Provide an in-depth analysis of the most critical CVEs, especially KEV entries and unpatched high-severity issues. For each major CVE, explain the affected technology, potential attack vectors, real-world impact, and urgency. Group related vulnerabilities where relevant.

## ${language === 'sv' ? 'Leverant\u00f6rsriskanalys' : 'Vendor Risk Overview'}
Analyze which vendors pose the highest risk based on CVE volume and severity. Discuss patterns, recurring issues, and what it means for organizations using those products.

## ${language === 'sv' ? 'S\u00e4kerhetsnyheter och trender' : 'Trending Security News'}
Summarize the most important security news items and analyze what they mean for organizations. Highlight emerging threat patterns and industry developments.

## ${language === 'sv' ? 'P\u00e5verkan och riskbed\u00f6mning' : 'Impact & Risk Assessment'}
Assess the overall risk level for this period. What types of organizations are most affected? What attack surfaces are most targeted?

## ${language === 'sv' ? 'Rekommendationer' : 'Recommendations'}
Provide 5-8 specific, actionable recommendations for IT security teams based on this data. Prioritize by urgency and impact.

Aim for approximately 1200-1500 words. Be specific and reference actual CVE IDs and vendor names from the data. Provide depth and context, not just summaries.

--- DATA ---
PERIOD: ${periodLabel}
STATS: ${stats.total} total CVEs, ${stats.critical} critical (CVSS>=9), ${stats.kevCount} known exploited

TOP VENDORS:
${vendorSummary || '  No vendor data available'}

KNOWN EXPLOITED VULNERABILITIES (KEV):
${kevSummary || '  None in this period'}

CRITICAL CVEs (CVSS 9+):
${critSummary || '  None in this period'}

HIGH SEVERITY WITHOUT PATCHES (CVSS 8+):
${noPatchSummary || '  None in this period'}

RECENT SECURITY NEWS:
${newsSummary || '  No news available'}`;
}

async function runAiAnalysis(period, language) {
  language = language || 'en';
  if (!aiConfig.enabled) {
    console.log('[AI] Analysis disabled in settings');
    return null;
  }
  if (!aiConfig.githubToken) {
    console.log('[AI] No GitHub token configured — skipping analysis');
    return null;
  }

  const prompt = buildAiPrompt(period, language);
  const model = aiConfig.model || 'gpt-4o-mini';
  const maxTokens = aiConfig.maxTokens || 4000;

  console.log(`[AI] Running ${period} analysis (${language}) with model ${model}...`);

  try {
    const resp = await fetch('https://models.inference.ai.azure.com/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${aiConfig.githubToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: language === 'sv'
            ? 'Du \u00e4r en professionell IT-s\u00e4kerhetsanalytiker som skriver detaljerade s\u00e4kerhetsrapporter p\u00e5 svenska. Anv\u00e4nd markdown-formatering.'
            : 'You are a professional IT security analyst writing detailed security reports. Use markdown formatting.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: maxTokens,
        temperature: 0.3
      })
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error(`[AI] API error ${resp.status}: ${errText}`);
      return null;
    }

    const data = await resp.json();
    const analysis = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;

    if (!analysis) {
      console.error('[AI] No content in response');
      return null;
    }

    db.saveAiAnalysis(period, analysis, language);
    console.log(`[AI] ${period} (${language}) analysis saved (${analysis.length} chars)`);
    return analysis;
  } catch (e) {
    console.error('[AI] Analysis failed:', e.message);
    return null;
  }
}

async function runAiAnalysisBothLanguages(period) {
  const en = await runAiAnalysis(period, 'en');
  const sv = await runAiAnalysis(period, 'sv');
  return { en, sv };
}

// API: Get latest AI analysis
app.get('/api/ai-analysis', (req, res) => {
  const p = req.query.period;
  const period = p === 'week' ? 'week' : p === 'yesterday' ? 'yesterday' : 'month';
  const language = req.query.lang === 'sv' ? 'sv' : 'en';
  const result = db.getLatestAiAnalysis(period, language);
  if (!result) return res.json({ analysis: null, generatedAt: null });
  res.json({ analysis: result.analysis, generatedAt: result.generated_at });
});

// API: Manually trigger AI analysis
app.post('/api/ai-analysis/trigger', (req, res) => {
  const p = req.query.period;
  const period = p === 'week' ? 'week' : p === 'yesterday' ? 'yesterday' : 'month';
  runAiAnalysisBothLanguages(period).then(result => {
    if (result.en || result.sv) res.json({ ok: true, period, en: !!(result.en), sv: !!(result.sv) });
    else res.json({ ok: false, error: 'Analysis failed or disabled — check server logs' });
  }).catch(e => res.status(500).json({ ok: false, error: e.message }));
});

// Schedule AI analysis: Sunday 23:59 (weekly) and last day of month 23:59 (monthly)
function scheduleAiAnalysis() {
  function msUntilNext(targetHour, targetMin) {
    const now = new Date();
    const next = new Date(now);
    next.setHours(targetHour, targetMin, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    return next;
  }

  // Check every hour if it's time to run
  setInterval(async () => {
    const now = new Date();
    const day = now.getDay(); // 0 = Sunday
    const hour = now.getHours();
    const minute = now.getMinutes();

    // Weekly: Sunday at 23:xx (run once during the 23:00 hour)
    if (day === 0 && hour === 23 && minute < 60) {
      const lastWeekly = db.getLatestAiAnalysis('week', 'en');
      const today = now.toISOString().slice(0, 10);
      if (!lastWeekly || !lastWeekly.generated_at || lastWeekly.generated_at.slice(0, 10) !== today) {
        console.log('[AI] Scheduled weekly analysis starting...');
        await runAiAnalysisBothLanguages('week');
      }

      // News summary: also run weekly on Sundays
      const lastNews = db.getLatestAiAnalysis('newssummary', 'en');
      if (!lastNews || !lastNews.generated_at || lastNews.generated_at.slice(0, 10) !== today) {
        console.log('[AI] Scheduled news summary analysis starting...');
        await runNewsSummaryAiBothLanguages();
      }
    }

    // Monthly: last day of month at 23:xx
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const isLastDay = tomorrow.getDate() === 1;
    if (isLastDay && hour === 23 && minute < 60) {
      const lastMonthly = db.getLatestAiAnalysis('month', 'en');
      const today = now.toISOString().slice(0, 10);
      if (!lastMonthly || !lastMonthly.generated_at || lastMonthly.generated_at.slice(0, 10) !== today) {
        console.log('[AI] Scheduled monthly analysis starting...');
        await runAiAnalysisBothLanguages('month');
      }
    }

    // Daily: every day at 6:xx for yesterday's analysis
    if (hour === 6 && minute < 60) {
      const lastDaily = db.getLatestAiAnalysis('yesterday', 'en');
      const today = now.toISOString().slice(0, 10);
      if (!lastDaily || !lastDaily.generated_at || lastDaily.generated_at.slice(0, 10) !== today) {
        console.log('[AI] Scheduled daily (yesterday) analysis starting...');
        await runAiAnalysisBothLanguages('yesterday');
      }
    }

    // Patch Tuesday: run on PT day at 00:xx (just after midnight)
    const nextPt = getNextPatchTuesday();
    const ptDateStr = localDateStr(nextPt);
    const todayLocal = localDateStr(now);
    if (todayLocal === ptDateStr && hour === 0) {
      const lastPt = db.getLatestAiAnalysis('patchtuesday', 'en');
      if (!lastPt || !lastPt.generated_at || lastPt.generated_at.slice(0, 10) !== todayLocal) {
        console.log('[AI] Scheduled Patch Tuesday analysis starting...');
        await runPatchTuesdayAiBothLanguages();
      }
    }
  }, 30 * 60 * 1000); // Check every 30 minutes

  console.log('[AI] Analysis scheduled: daily (06:00), weekly (Sunday 23:59), monthly (last day 23:59), Patch Tuesday (00:01 on PT day), news summary (Sunday 23:xx)');
}

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

  // KEV catalog
  await pollKev();

  // Enrich existing CVEs with vendor/exploit/patch metadata
  enrichExistingCves();

  // Fetch vendor data from CIRCL for CVEs still missing vendor (runs in background)
  enrichVendorsFromCircl().catch(e => console.error('enrichVendorsFromCircl error:', e && e.message));

  // Backfill CVEs from NVD if DB is sparse (rate-limited, runs in background)
  backfillCvesFromNvd().catch(e => console.error('backfillCves error:', e && e.message));
  console.log('Polling News...');
  await pollNews();
  console.log('Checking services (live ping for uptime)...');
  await checkServices();

  // Update CVE daily counts
  updateCveDailyCounts();

  // Generate initial report
  generateReport();

  // DB maintenance: trim oversized blobs and reclaim space
  db.trimOversizedBlobs();
  db.vacuum();

  // Fast service polls for UI responsiveness
  await pollMicrosoftFast().catch(() => {});
  await pollCloudflareAws().catch(() => {});
  setInterval(() => pollMicrosoftFast().catch(() => {}), (settings.services.microsoft.pollIntervalSeconds || 10) * 1000);
  setInterval(() => pollCloudflareAws().catch(() => {}), 60 * 1000);

  // Scheduled polls
  setInterval(async () => {
    await pollCves();
    enrichVendorsFromCircl().catch(() => {});
  }, settings.polling.cveIntervalMinutes * 60 * 1000);
  setInterval(pollNews, settings.polling.newsIntervalMinutes * 60 * 1000);
  setInterval(async () => {
    await checkServices();
    updateCveDailyCounts();
  }, settings.polling.uptimeIntervalMinutes * 60 * 1000);

  // KEV: poll every 6 hours
  setInterval(() => pollKev().catch(() => {}), 6 * 60 * 60 * 1000);

  // Daily report generation at 03:00
  function scheduleDaily() {
    const now = new Date();
    const next = new Date(now);
    next.setHours(3, 0, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    const ms = next.getTime() - now.getTime();
    setTimeout(() => {
      enrichExistingCves();
      generateReport();
      db.trimOversizedBlobs();
      // Weekly vacuum on Sundays
      if (new Date().getDay() === 0) db.vacuum();
      // Reschedule for next day
      setInterval(() => { enrichExistingCves(); generateReport(); }, 24 * 60 * 60 * 1000);
    }, ms);
    console.log(`Next report scheduled at ${next.toISOString()}`);
  }
  scheduleDaily();

  // AI analysis scheduling
  scheduleAiAnalysis();

  // Run AI analysis on boot if runOnBoot is set to 1
  if (aiConfig.enabled && (aiConfig.runOnBoot === 1 || aiConfig.runOnBoot === true)) {
    console.log('[AI] runOnBoot enabled — triggering all analyses...');
    runAiAnalysisBothLanguages('yesterday')
      .then(() => runAiAnalysisBothLanguages('week'))
      .then(() => runAiAnalysisBothLanguages('month'))
      .then(() => runPatchTuesdayAiBothLanguages())
      .then(() => runNewsSummaryAiBothLanguages())
      .catch(e => console.error('[AI] Boot analysis error:', e.message));
  }

  app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
})();
