const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const zlib = require('zlib');

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (/\.(html|js|css)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

const CIRCL_LAST = 'https://cve.circl.lu/api/last';
const CIRCL_LAST_INIT = 'https://cve.circl.lu/api/last/100'; // larger initial fetch
const CVE_STORE_FILE = path.join(__dirname, 'cves_store.json');
const CVE_POLL_INTERVAL = 60 * 60 * 1000; // 1 hour
const CVE_MAX_AGE_DAYS = 30;

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// --- Persistent CVE store ---
let _cveStore = []; // in-memory array of CVE items

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

async function loadCveStore() {
  try {
    const raw = await fs.readFile(CVE_STORE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) { _cveStore = parsed; return; }
  } catch (_) {}
  _cveStore = [];
}

async function saveCveStore() {
  try {
    await fs.writeFile(CVE_STORE_FILE, JSON.stringify(_cveStore), 'utf8');
  } catch (e) { console.error('saveCveStore error:', e && e.message); }
}

function purgeCveStore() {
  const cutoff = Date.now() - CVE_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
  const before = _cveStore.length;
  _cveStore = _cveStore.filter(it => {
    const d = extractItemDate(it);
    return d && d.getTime() >= cutoff;
  });
  if (_cveStore.length < before) {
    console.log(`Purged ${before - _cveStore.length} CVEs older than ${CVE_MAX_AGE_DAYS} days (${_cveStore.length} remaining)`);
  }
}

async function pollCves() {
  try {
    // Use larger fetch when store is empty (initial populate)
    const url = _cveStore.length === 0 ? CIRCL_LAST_INIT : CIRCL_LAST;
    const r = await fetch(url);
    let data = await r.json();
    if (!Array.isArray(data)) {
      if (data && Array.isArray(data.value)) data = data.value;
      else { console.error('pollCves: unexpected response'); return; }
    }
    // find the newest date already in the store
    let newestDate = null;
    for (const it of _cveStore) {
      const d = extractItemDate(it);
      if (d && (!newestDate || d > newestDate)) newestDate = d;
    }
    // build set of existing IDs for fast dedup
    const existing = new Set(_cveStore.map(it => extractItemId(it)).filter(Boolean));
    let added = 0;
    for (const it of data) {
      const id = extractItemId(it);
      if (id && existing.has(id)) continue;
      // skip items older than or equal to newest stored date
      if (newestDate) {
        const d = extractItemDate(it);
        if (d && d <= newestDate) continue;
      }
      _cveStore.push(it);
      if (id) existing.add(id);
      added++;
    }
    // purge old entries
    purgeCveStore();
    // sort newest first
    _cveStore.sort((a, b) => {
      const da = extractItemDate(a) || new Date(0);
      const db = extractItemDate(b) || new Date(0);
      return db - da;
    });
    await saveCveStore();
    console.log(`pollCves: fetched ${data.length}, added ${added} new (newer than ${newestDate ? newestDate.toISOString() : 'none'}), store has ${_cveStore.length} CVEs`);
  } catch (e) {
    console.error('pollCves error:', e && e.message);
  }
}

// Start CVE store: load from disk, poll immediately, then every 10 min
(async () => {
  await loadCveStore();
  console.log(`CVE store loaded: ${_cveStore.length} items from disk`);
  await pollCves();
  setInterval(pollCves, CVE_POLL_INTERVAL);
})();

if (!global._uptimeHistory) global._uptimeHistory = [];

// Helper: simple HTTP probe with timeout
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

const UPTIME_FILE = path.join(__dirname, 'uptime_history.json');

async function saveUptimeHistoryFile(arr) {
  try {
    await fs.writeFile(UPTIME_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch (e) { console.error('saveUptimeHistoryFile', e && e.message); }
}

async function loadUptimeHistoryFile() {
  try {
    const raw = await fs.readFile(UPTIME_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
  } catch (e) {
    // ignore
  }
  return null;
}

// Prefill uptime history (hourly entries) with all-ok entries for past `hours` hours
async function prefillUptimeHistory(hours = 168) {
  const now = Date.now();
  const arr = [];
  for (let i = hours - 1; i >= 0; i--) {
    const ts = now - i * 60 * 60 * 1000;
    arr.push({ ts, ok: true, details: [{ name: 'prefill', ok: true, note: 'prefilled' }] });
  }
  await saveUptimeHistoryFile(arr);
  global._uptimeHistory = arr.slice();
  return arr;
}

app.get('/api/zero-days', async (req, res) => {
  const count = parseInt(req.query.count || '200', 10);
  try {
    const r = await fetch(CIRCL_LAST);
    let data = await r.json();
    // CIRCL /api/last sometimes returns an object with `value` array (CSAF) or a plain array
    if (!Array.isArray(data)) {
      if (data && Array.isArray(data.value)) data = data.value;
      else return res.status(502).json({ error: 'unexpected response' });
    }

    function extractSummary(item) {
      if (!item) return '';
      if (item.summary) return item.summary;
      if (item.description) return item.description;
      if (item.cveMetadata && (item.cveMetadata.description || item.cveMetadata.summary)) return item.cveMetadata.description || item.cveMetadata.summary || '';
      if (item.containers && item.containers.cna) {
        const cna = item.containers.cna;
        if (cna.descriptions && cna.descriptions.length) {
          const d = cna.descriptions[0];
          return d.value || d.description || d.text || '';
        }
        if (cna.descriptions && typeof cna.descriptions === 'string') return cna.descriptions;
        if (cna.title) return cna.title;
      }
      if (item.document && item.document.notes && item.document.notes.length) {
        const note = item.document.notes.find(n => n.category === 'summary') || item.document.notes[0];
        return (note && (note.text || note.title || note.summary)) || '';
      }
      return '';
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

// Latest CVE items — served from persistent local store
app.get('/api/cves', (req, res) => {
  const count = parseInt(req.query.count || '50', 10);
  const offset = parseInt(req.query.offset || '0', 10);
  // _cveStore is already sorted newest-first by pollCves()
  res.json(_cveStore.slice(offset, offset + count));
});

app.get('/api/status', async (req, res) => {
  try {
    const st = await checkServices();
    res.json(st);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Basic service checks and uptime history
async function checkServices() {
  const now = Date.now();
  const details = [];

  // CIRCL and NVD probes (keep original checks)
  const circl = await probeUrl(CIRCL_LAST, 6000);
  details.push({ name: 'circl_last', ok: circl.ok, status: circl.status });
  const nvd = await probeUrl('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', 6000);
  details.push({ name: 'nvd_v2', ok: nvd.ok, status: nvd.status });

  // VPN check (include in the main hourly check so we only append once per hour)
  try {
    const vpn = await probeUrl('https://vpn.lundstream.net/', 8000);
    details.push({ name: 'vpn_lundstream', ok: vpn.ok, status: vpn.status });
  } catch (e) { details.push({ name: 'vpn_lundstream', ok: false, status: 0, error: e && e.message }); }

  // (VPN checked hourly by separate scheduler)

  // Microsoft hosts: ping (HTTP) each host
  const msHosts = ['https://outlook.office365.com/', 'https://advania-my.sharepoint.com/', 'https://login.microsoftonline.com/', 'https://portal.office.com/'];
  const msResults = [];
  for (const h of msHosts) {
    const r = await probeUrl(h, 4000);
    // treat client errors (4xx) as reachable — many Microsoft endpoints return 403/401 for anonymous requests
    const reachable = (r && typeof r.status === 'number') ? (r.status < 500) : !!r.ok;
    msResults.push({ host: h.replace(/^https?:\/\//, ''), ok: reachable, status: r.status });
  }
  const msDown = msResults.filter(x => !x.ok).length;
  let msColor = 'green';
  if (msDown === 1) msColor = 'yellow';
  if (msDown >= 2) msColor = 'red';
  details.push({ name: 'microsoft', ok: msDown === 0, color: msColor, hosts: msResults });

  // Cloudflare: ping 1.1.1.1 and 1.0.0.1 via HTTPS trace endpoint
  const cfHosts = ['https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace'];
  const cfResults = [];
  for (const h of cfHosts) {
    const r = await probeUrl(h, 3000);
    cfResults.push({ host: h.replace(/^https?:\/\//, ''), ok: r.ok, status: r.status });
  }
  const cfDown = cfResults.filter(x => !x.ok).length;
  let cfColor = 'green';
  if (cfDown === 1) cfColor = 'yellow';
  if (cfDown >= 2) cfColor = 'red';
  details.push({ name: 'cloudflare', ok: cfDown === 0, color: cfColor, hosts: cfResults });

  // AWS: best-effort check by fetching health page
  let awsOk = false; let awsStatus = 0; let awsText = '';
  try {
    const r = await probeUrl('https://status.aws.amazon.com/', 5000);
    awsOk = !!r.ok;
    awsStatus = r.status;
    try {
      const txt = await fetch('https://status.aws.amazon.com/').then(t => t.text()).catch(()=>'');
      awsText = txt || '';
    } catch (e) { awsText = ''; }
  } catch (e) {}
  let awsColor = awsOk ? 'green' : 'red';
  if (awsOk && /operating normally|All Systems Operational/i.test(awsText)) awsColor = 'green';
  details.push({ name: 'aws', ok: awsOk, color: awsColor, status: awsStatus });

  // overall ok only if core services ok
  const overall = circl.ok && nvd.ok;

  // store entry (keep only last 24 hourly entries for the UI/history)
  global._uptimeHistory = global._uptimeHistory || [];
  const entry = { ts: now, ok: overall, details };
  global._uptimeHistory.push(entry);
  // trim to last 24
  global._uptimeHistory = global._uptimeHistory.slice(-24);
  // persist to disk (replace with last 24)
  try {
    let out = global._uptimeHistory.slice();
    await saveUptimeHistoryFile(out);
  } catch (e) { /* ignore */ }

  return { ok: overall, services: details, historyLength: global._uptimeHistory.length };
}

// Poll services every hour to populate uptime history
setInterval(() => { checkServices().catch(() => {}); }, 60 * 60 * 1000);
// do not seed immediately here — uptime history will be prefilled and trimmed on startup

// Ensure uptime file exists; prefill with OK entries if missing
(async () => {
  try {
    // Reset/prefill uptime history to last 24 hours (hourly entries)
    // This ensures the persisted JSON reflects hourly sampling for the last day.
    await prefillUptimeHistory(24);
    // Trim any extra entries that may have been appended during startup to exactly 24
    global._uptimeHistory = (global._uptimeHistory || []).slice(-24);
    await saveUptimeHistoryFile(global._uptimeHistory);
  } catch (e) { console.error('uptime prefill error', e && e.message); }

  // Microsoft hosts check every 10 seconds (fast polling for status color)
  const checkMicrosoftOnce = async () => {
    const msHosts = ['https://outlook.office365.com/', 'https://advania-my.sharepoint.com/', 'https://login.microsoftonline.com/', 'https://portal.office.com/'];
    const msResults = [];
    for (const h of msHosts) {
      const r = await probeUrl(h, 3000);
      const reachable = (r && typeof r.status === 'number') ? (r.status < 500) : !!r.ok;
      msResults.push({ host: h.replace(/^https?:\/\//, ''), ok: reachable, status: r.status });
    }
    const msDown = msResults.filter(x => !x.ok).length;
    let msColor = 'green'; if (msDown === 1) msColor = 'yellow'; if (msDown >= 2) msColor = 'red';
    global._serviceSummary = global._serviceSummary || {};
    global._serviceSummary.microsoft = { ts: Date.now(), color: msColor, hosts: msResults };
  };
  checkMicrosoftOnce().catch(() => {});
  setInterval(() => checkMicrosoftOnce().catch(() => {}), 10 * 1000);

  // VPN is handled inside checkServices() now (no separate hourly appends)

  // Cloudflare & AWS periodic checks every minute
  const checkCloudflareAws = async () => {
    try {
      // cloudflare
      const cf1 = await probeUrl('https://1.1.1.1/cdn-cgi/trace', 3000);
      const cf0 = await probeUrl('https://1.0.0.1/cdn-cgi/trace', 3000);
      global._serviceSummary = global._serviceSummary || {};
      const cfDown = [cf1, cf0].filter(x => !x.ok).length;
      let cfColor = 'green'; if (cfDown === 1) cfColor = 'yellow'; if (cfDown >= 2) cfColor = 'red';
      global._serviceSummary.cloudflare = { ts: Date.now(), color: cfColor, hosts: [ { host: '1.1.1.1', ok: cf1.ok }, { host: '1.0.0.1', ok: cf0.ok } ] };

      // aws
      const awsProbe = await probeUrl('https://status.aws.amazon.com/', 5000);
      let awsColor = awsProbe.ok ? 'green' : 'red';
      global._serviceSummary.aws = { ts: Date.now(), color: awsColor, ok: awsProbe.ok };
    } catch (e) { /* ignore */ }
  };
  checkCloudflareAws().catch(() => {});
  setInterval(() => checkCloudflareAws().catch(() => {}), 60 * 1000);

})();

app.get('/api/uptime', async (req, res) => {
  // return uptime history (timestamp + ok) limited to most recent N
  try {
    // only return last 24 hourly entries
    res.json(global._uptimeHistory.slice(-24));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// fetch single CVE details from CIRCL by ID
app.get('/api/cve/:id', async (req, res) => {
  const id = req.params.id;
  if (!id) return res.status(400).json({ error: 'missing id' });
  try {
    const r = await fetch(`https://cve.circl.lu/api/cve/${encodeURIComponent(id)}`);
    if (!r.ok) return res.status(r.status).json({ error: 'fetch failed' });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/cve-stats', async (req, res) => {
  // Serve persisted 30-day CVE counts if available, otherwise compute on demand.
  try {
    const HIST = path.join(__dirname, 'cve_history.json');
    try {
      const raw = await fs.readFile(HIST, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length >= 1) return res.json(parsed.slice(-30));
    } catch (e) {
      // file missing or invalid, fall through to compute
    }
    // compute live as fallback
    const compute = await computeCveCountsFromSource();
    res.json(compute);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// helper: compute 30-day counts from configured source (CIRCL)
async function computeCveCountsFromSource() {
  const r = await fetch(CIRCL_LAST);
  let data = await r.json();
  if (!Array.isArray(data)) {
    if (data && Array.isArray(data.value)) data = data.value;
    else data = [];
  }
  const counts = {};
  const now = new Date();
  for (let i = 0; i < 30; i++) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const key = d.toISOString().slice(0, 10);
    counts[key] = 0;
  }
  function parseDateString(pd) {
    if (!pd) return null;
    const dt = new Date(pd);
    if (!isNaN(dt.getTime())) return dt.toISOString().slice(0, 10);
    const m = pd && pd.match && pd.match(/(\d{4}-\d{2}-\d{2})/);
    if (m) return m[1];
    const tryParse = Date.parse(pd);
    if (!isNaN(tryParse)) return (new Date(tryParse)).toISOString().slice(0, 10);
    return null;
  }
  data.forEach(it => {
    const candidates = [];
    if (it.Published) candidates.push(it.Published);
    if (it.published) candidates.push(it.published);
    if (it.cveMetadata && it.cveMetadata.datePublished) candidates.push(it.cveMetadata.datePublished);
    if (it.cveMetadata && it.cveMetadata.dateUpdated) candidates.push(it.cveMetadata.dateUpdated);
    if (it.document && it.document.tracking) {
      const tr = it.document.tracking;
      if (tr.current_release_date) candidates.push(tr.current_release_date);
      if (tr.initial_release_date) candidates.push(tr.initial_release_date);
      if (tr.generator && tr.generator.date) candidates.push(tr.generator.date);
    }
    if (it.document && it.document.notes && it.document.notes.length) {
      it.document.notes.forEach(n => { if (n.title) candidates.push(n.title); if (n.text) candidates.push(n.text); });
    }
    let day = null;
    for (const pd of candidates) {
      day = parseDateString(pd);
      if (day) break;
    }
    if (!day) return;
    if (counts.hasOwnProperty(day)) counts[day]++;
  });
  // fallback: if almost empty, spread items evenly across days
  const total = Object.values(counts).reduce((s, v) => s + v, 0);
  if (total < 2 && data.length > 0) {
    const days = Object.keys(counts).sort();
    for (let i = 0; i < data.length; i++) {
      const idx = i % days.length;
      counts[days[idx]] = (counts[days[idx]] || 0) + 1;
    }
  }
  const out = Object.keys(counts).sort().map(d => ({ date: d, count: counts[d] }));
  return out;
}

// persist CVE history to disk
async function saveCveHistory(arr) {
  const HIST = path.join(__dirname, 'cve_history.json');
  try { await fs.writeFile(HIST, JSON.stringify(arr, null, 2), 'utf8'); } catch (e) { console.error('saveCveHistory', e && e.message); }
}

// update CVE history from source and persist
async function updateCveHistoryFromSource() {
  try {
    // Prefer NVD for historical counts (more complete). If it fails, fall back to CIRCL.
    try {
      const arr = await fetchCveCountsFromNvd();
      if (Array.isArray(arr) && arr.length) {
        const last30 = arr.slice(-30);
        await saveCveHistory(last30);
        return last30;
      }
    } catch (nvdErr) {
      console.error('NVD fetch failed, trying feed fallback then falling back to CIRCL', nvdErr && nvdErr.message);
      try {
        const feedArr = await fetchCveCountsFromNvdFeed();
        if (Array.isArray(feedArr) && feedArr.length) {
          const last30f = feedArr.slice(-30);
          await saveCveHistory(last30f);
          return last30f;
        }
      } catch (feedErr) {
        console.error('NVD feed fallback failed', feedErr && feedErr.message);
      }
    }
    const arr2 = await computeCveCountsFromSource();
    if (Array.isArray(arr2) && arr2.length) {
      const last30b = arr2.slice(-30);
      await saveCveHistory(last30b);
      return last30b;
    }
  } catch (e) { console.error('updateCveHistoryFromSource', e && e.message); }
  return null;
}

// Fetch count of CVEs for a single day (YYYY-MM-DD). Prefer NVD v2, fall back to CIRCL parsing.
async function fetchCountForSingleDay(dayStr) {
  // build start/end ISO strings
  const start = new Date(dayStr + 'T00:00:00Z');
  const end = new Date(dayStr + 'T23:59:59Z');
  const headers = { 'User-Agent': 'CVE-dashboard/1.0 (https://example)' };
  if (process.env.NVD_API_KEY) headers['apiKey'] = process.env.NVD_API_KEY;
  try {
    const base2 = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    const ps = 2000; let startIndex = 0; let totalResults = Infinity; let fetched = 0; let loop = 0; let count = 0;
    while (fetched < totalResults && loop < 100) {
      const url = `${base2}?pubStartDate=${encodeURIComponent(start.toISOString())}&pubEndDate=${encodeURIComponent(end.toISOString())}&resultsPerPage=${ps}&startIndex=${startIndex}`;
      const r = await fetch(url, { headers });
      if (!r.ok) throw new Error('NVD v2 error ' + r.status);
      const j = await r.json();
      const items = (j && j.vulnerabilities) || [];
      count += items.length;
      fetched += items.length; startIndex += items.length; loop++;
      if (items.length === 0) break;
      await sleep(600);
    }
    return count;
  } catch (e) {
    // fallback: compute from CIRCL recent feed
    try {
      const arr = await computeCveCountsFromSource();
      const found = (arr || []).find(x => x.date === dayStr);
      return found ? found.count : 0;
    } catch (e2) { return 0; }
  }
}

// Update only the previous day's count at midnight and persist into cve_history.json
async function updatePreviousDayCount() {
  const now = new Date();
  const prev = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const dayStr = prev.toISOString().slice(0,10);
  try {
    const cnt = await fetchCountForSingleDay(dayStr);
    // read existing history
    const HIST = path.join(__dirname, 'cve_history.json');
    let arr = [];
    try { arr = JSON.parse(await fs.readFile(HIST, 'utf8')); } catch (e) { arr = []; }
    if (!Array.isArray(arr)) arr = [];
    // replace or add
    const idx = arr.findIndex(x => x.date === dayStr);
    if (idx >= 0) arr[idx].count = cnt; else arr.push({ date: dayStr, count: cnt });
    // ensure sorted and keep last 90 days max
    arr = arr.sort((a,b)=> a.date < b.date ? -1 : 1).slice(-90);
    await saveCveHistory(arr);
    return { date: dayStr, count: cnt };
  } catch (e) {
    console.error('updatePreviousDayCount', e && e.message);
    throw e;
  }
}

// Fetch CVE items from NVD REST API and compute daily counts for last 30 days
async function fetchCveCountsFromNvd() {
  const base = 'https://services.nvd.nist.gov/rest/json/cves/1.0';
  const now = new Date();
  const counts = {};
  for (let i = 0; i < 30; i++) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const key = d.toISOString().slice(0, 10);
    counts[key] = 0;
  }
  // build query window: from 30 days ago 00:00 UTC to now
  const startDate = new Date(now.getTime() - 29 * 24 * 60 * 60 * 1000);
  startDate.setUTCHours(0,0,0,0);
  const endDate = new Date();
  endDate.setUTCHours(23,59,59,999);
  function nvdDateString(d) {
    // format: YYYY-MM-DDTHH:MM:SS:000 UTC-00:00
    const Y = d.getUTCFullYear(); const M = String(d.getUTCMonth()+1).padStart(2,'0'); const D = String(d.getUTCDate()).padStart(2,'0');
    const h = String(d.getUTCHours()).padStart(2,'0'); const m = String(d.getUTCMinutes()).padStart(2,'0'); const s = String(d.getUTCSeconds()).padStart(2,'0');
    return `${Y}-${M}-${D}T${h}:${m}:${s}:000 UTC-00:00`;
  }
  const ps = 2000; let startIndex = 0; let totalResults = Infinity; let fetched = 0; let loop = 0;
  const headers = { 'User-Agent': 'CVE-dashboard/1.0 (https://example)' };
  if (process.env.NVD_API_KEY) headers['apiKey'] = process.env.NVD_API_KEY;
  // First try NVD v1 REST endpoint. If it returns 403 or fails, fall back to v2.
  try {
    while (fetched < totalResults && loop < 100) {
      const url = `${base}?pubStartDate=${encodeURIComponent(nvdDateString(startDate))}&pubEndDate=${encodeURIComponent(nvdDateString(endDate))}&startIndex=${startIndex}&resultsPerPage=${ps}`;
      console.log('NVD v1 request:', url);
      const r = await fetch(url, { headers });
      if (!r.ok) {
        const txt = await r.text().catch(() => '<no-body>');
        console.error('NVD v1 response:', r.status, (txt && txt.slice) ? txt.slice(0,200) : txt);
        const err = new Error('NVD API error ' + r.status + ' ' + ((txt && txt.slice) ? txt.slice(0,200) : ''));
        err.status = r.status;
        throw err;
      }
      const j = await r.json();
      const items = (j && j.result && j.result.CVE_Items) || [];
      items.forEach(it => {
        const pd = it.publishedDate || (it.published && it.publishedDate) || null;
        if (!pd) return;
        const day = (new Date(pd)).toISOString().slice(0,10);
        if (counts.hasOwnProperty(day)) counts[day]++;
      });
      // be polite to NVD: pause between paged requests (avoid 429/403)
      await sleep(800);
      totalResults = (j && j.totalResults) || ((j && j.resultsPerPage) ? j.resultsPerPage : items.length);
      fetched += items.length;
      startIndex += items.length;
      loop++;
      if (items.length === 0) break;
    }
  } catch (v1err) {
    // If v1 is blocked (403) or otherwise fails, try the v2 API which may accept the key/IP.
    try {
      const base2 = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
      // reset counters for v2 fetch
      fetched = 0; startIndex = 0; loop = 0; totalResults = Infinity;
      // Use a simpler v2 query (paged) and filter dates client-side to avoid date-format issues
      while (fetched < totalResults && loop < 100) {
        const url = `${base2}?pubStartDate=${encodeURIComponent(startDate.toISOString())}&pubEndDate=${encodeURIComponent(endDate.toISOString())}&resultsPerPage=${ps}&startIndex=${startIndex}`;
        console.log('NVD v2 request (filtered):', url);
        const r = await fetch(url, { headers });
        if (!r.ok) {
          const txt = await r.text().catch(() => '<no-body>');
          console.error('NVD v2 response:', r.status, (txt && txt.slice) ? txt.slice(0,200) : txt);
          throw new Error('NVD v2 API error ' + r.status + ' ' + ((txt && txt.slice) ? txt.slice(0,200) : ''));
        }
        const j = await r.json();
        const items = (j && j.vulnerabilities) || [];
        console.log('NVD v2 page', loop, 'items', items.length, 'totalResults', j && j.totalResults);
        items.forEach(it => {
          // try multiple locations for published date and only count items within our 30-day window
          const candidates = [];
          if (it.published) candidates.push(it.published);
          if (it.publishedDate) candidates.push(it.publishedDate);
          if (it.cve) {
            if (it.cve.published) candidates.push(it.cve.published);
            if (it.cve.publishedDate) candidates.push(it.cve.publishedDate);
            if (it.cve.lastModifiedDate) candidates.push(it.cve.lastModifiedDate);
          }
          let pd = null;
          for (const c of candidates) {
            if (!c) continue;
            const d = new Date(c);
            if (!isNaN(d.getTime())) { pd = d.toISOString(); break; }
            const m = (c && c.match && c.match(/(\d{4}-\d{2}-\d{2})/)) || null;
            if (m) { pd = m[1]; break; }
          }
          if (!pd) return;
          const day = pd.slice(0,10);
          if (counts.hasOwnProperty(day)) counts[day]++;
        });
        // pause between paged requests to avoid hitting rate limits
        await sleep(800);
        totalResults = (j && j.totalResults) || ((j && j.resultsPerPage) ? j.resultsPerPage : items.length);
        fetched += items.length;
        startIndex += items.length;
        loop++;
        if (items.length === 0) break;
      }
    } catch (v2err) {
      // rethrow original or v2 error to be handled by caller
      throw v2err || v1err;
    }
  }
  return Object.keys(counts).sort().map(d => ({ date: d, count: counts[d] }));
}

// If NVD REST API is blocked (403), try downloading the yearly JSON feeds (gz) and parsing locally
async function fetchCveCountsFromNvdFeed() {
  const now = new Date();
  const counts = {};
  for (let i = 0; i < 30; i++) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    counts[d.toISOString().slice(0,10)] = 0;
  }
  // Allow using local NVD feed files (set NVD_FEED_DIR to a directory containing nvdcve-1.1-YYYY.json.gz)
  const localDir = process.env.NVD_FEED_DIR;
  const years = [now.getUTCFullYear(), now.getUTCFullYear() - 1];
  if (localDir) {
    try {
      const dirents = await fs.readdir(localDir);
      for (const f of dirents) {
        if (!/nvdcve-1\.1-\d{4}\.json\.gz$/.test(f)) continue;
        try {
          const buf = await fs.readFile(path.join(localDir, f));
          const out = zlib.gunzipSync(buf).toString('utf8');
          const j = JSON.parse(out);
          const items = j.CVE_Items || [];
          items.forEach(it => {
            const pd = it.publishedDate || it.published || null;
            if (!pd) return;
            const day = (new Date(pd)).toISOString().slice(0,10);
            if (counts.hasOwnProperty(day)) counts[day]++;
          });
        } catch (e) { console.error('local feed parse error', f, e && e.message); }
      }
      return Object.keys(counts).sort().map(d => ({ date: d, count: counts[d] }));
    } catch (e) { console.warn('NVD_FEED_DIR read failed', e && e.message); }
  }
  // fallback: remote download of yearly feeds
  for (const y of years) {
    const url = `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-${y}.json.gz`;
    try {
      console.log('NVD feed request:', url);
      const r = await fetch(url, { headers: { 'User-Agent': 'CVE-dashboard/1.0 (https://example)' } });
      if (!r.ok) {
        const txt = await r.text().catch(() => '<no-body>');
        console.warn('NVD feed fetch failed', r.status, (txt && txt.slice) ? txt.slice(0,200) : txt);
        continue;
      }
      const buf = Buffer.from(await r.arrayBuffer());
      const out = zlib.gunzipSync(buf).toString('utf8');
      const j = JSON.parse(out);
      const items = j.CVE_Items || [];
      items.forEach(it => {
        const pd = it.publishedDate || it.published || null;
        if (!pd) return;
        const day = (new Date(pd)).toISOString().slice(0,10);
        if (counts.hasOwnProperty(day)) counts[day]++;
      });
    } catch (e) {
      console.error('fetchCveCountsFromNvdFeed error', e && e.message);
    }
  }
  return Object.keys(counts).sort().map(d => ({ date: d, count: counts[d] }));
}

// schedule nightly update at local 00:00
function scheduleNightlyUpdate() {
  const now = new Date();
  const next = new Date(now);
  next.setHours(24,0,0,0);
  const delay = next.getTime() - now.getTime();
  setTimeout(async () => {
    // At midnight update the previous day's CVE count specifically
    await updatePreviousDayCount();
    setInterval(updatePreviousDayCount, 24 * 60 * 60 * 1000);
  }, delay);
}

// seed/prefill on startup, then update hourly (CIRCL-based)
updateCveHistoryFromSource().then(() => {
  // run hourly
  setInterval(updateCveHistoryFromSource, 60 * 60 * 1000);
}).catch(() => {
  setInterval(updateCveHistoryFromSource, 60 * 60 * 1000);
});
// also schedule nightly update (keeps earlier behavior)
scheduleNightlyUpdate();

// Aggregated RSS/Atom news feed for IT/security sources
app.get('/api/rss', async (req, res) => {
  console.log('/api/rss requested');
  // Curated feed list (user's FreshRSS selection), CVE feeds excluded
  const feeds = [
    'https://www.advania.se/nyheter/rss.xml',
    'https://computersweden.se/feed/',
    'https://www.bleepingcomputer.com/feed/',
    'https://feeds.feedburner.com/TheHackersNews',
    'https://techcrunch.com/feed/',
    'https://www.neowin.net/rss/index.xml',
    'https://www.securityweek.com/feed/',
    'https://www.schneier.com/blog/atom.xml',
    'https://www.reddit.com/r/netsec/.rss'
  ];
  const count = parseInt(req.query.count || '50', 10);
  const offset = parseInt(req.query.offset || '0', 10);

  // Cache feeds in-memory and refresh every 10 minutes
  const RSS_TTL = 10 * 60 * 1000; // 10 minutes
  if (!global._rssCache) global._rssCache = { items: [], updated: 0, promise: null };

  async function fetchFeeds() {
    const results = await Promise.allSettled(feeds.map(u => fetch(u).then(r => r.text())));
    const items = [];
    const pushItem = (title, link, date, source) => {
      if (!title || !link) return;
      const d = date ? new Date(date) : new Date();
      items.push({ title: title.trim(), link: link.trim(), pubDate: d.toISOString(), source });
    };
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
        return { t, l, pd };
      };
      matchItems.forEach(b => { const {t,l,pd}=extract(b); pushItem(t,l,pd,source); });
      matchEntries.forEach(b => { const {t,l,pd}=extract(b); pushItem(t,l,pd,source); });
    }
    items.sort((a,b)=> new Date(b.pubDate) - new Date(a.pubDate));
    return items;
  }

  try {
    const now = Date.now();
    const cache = global._rssCache;
    if (cache.items.length > 0 && (now - cache.updated) < RSS_TTL) {
      return res.json(cache.items.slice(offset, offset + count));
    }
    if (cache.promise) {
      const items = await cache.promise;
      return res.json(items.slice(offset, offset + count));
    }
    cache.promise = fetchFeeds().then(items => {
      cache.items = items;
      cache.updated = Date.now();
      cache.promise = null;
      return items;
    }).catch(err => {
      cache.promise = null;
      throw err;
    });
    const items = await cache.promise;
    res.json(items.slice(offset, offset + count));
  } catch (err) {
    console.error('/api/rss error', err && err.message);
    res.status(500).json({ error: err.message || 'fetch failed' });
  }
});

// Note: previous simple aggregator removed to avoid duplicate routes.

// Export helpers so external scripts can trigger updates (useful for CLI runs)
module.exports = {
  updateCveHistoryFromSource,
  updatePreviousDayCount,
  fetchCveCountsFromNvd,
  fetchCveCountsFromNvdFeed,
  computeCveCountsFromSource
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
