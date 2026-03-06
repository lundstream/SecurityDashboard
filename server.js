const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const zlib = require('zlib');

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const CIRCL_LAST = 'https://cve.circl.lu/api/last';

// Service status cache
if (!global._serviceCache) global._serviceCache = { status: {}, updated: 0 };

// Uptime history for norrmoln.se (hourly samples)
if (!global._uptimeHistory) global._uptimeHistory = [];

// Seed dummy uptime history for immediate visualization (will be replaced by real pings)
function seedDummyUptime() {
  if (Array.isArray(global._uptimeHistory) && global._uptimeHistory.length > 0) return;
  const now = Date.now();
  const HOUR = 60 * 60 * 1000;
  const SAMPLES = 24; // seed 24 hourly samples
  for (let i = SAMPLES - 1; i >= 0; i--) {
    const t = new Date(now - i * HOUR).toISOString();
    const ok = (i % 13 !== 0);
    global._uptimeHistory.push({ t, ok });
  }
}

const SERVICE_CHECK_TTL = 60 * 1000; // 1 minute
const UPTIME_POLL_INTERVAL = 60 * 60 * 1000; // 1 hour

const services = {
  cloudflare: 'https://www.cloudflare.com/',
  aws: 'https://aws.amazon.com/',
  microsoft: 'https://www.microsoft.com/'
};

async function checkServices() {
  const now = Date.now();
  const cache = global._serviceCache;
  if (now - cache.updated < SERVICE_CHECK_TTL && cache.status && Object.keys(cache.status).length) return cache.status;
  const results = {};
  await Promise.all(Object.keys(services).map(async k => {
    try {
      const r = await fetch(services[k], { method: 'HEAD' });
      results[k] = (r && r.ok) ? 'up' : 'down';
    } catch (e) { results[k] = 'down'; }
  }));
  cache.status = results; cache.updated = Date.now();
  return results;
}

// uptime poller: ping norrmoln.se and store timestamp + ok
async function pollUptime() {
  try {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), 10000);
    const r = await fetch('https://norrmoln.se/', { method: 'HEAD', signal: controller.signal });
    clearTimeout(to);
    global._uptimeHistory.push({ t: new Date().toISOString(), ok: !!(r && r.ok) });
  } catch (e) {
    global._uptimeHistory.push({ t: new Date().toISOString(), ok: false });
  }
  // sliding window: keep last MAX entries, drop oldest when overflowing
  const MAX = 144;
  while (global._uptimeHistory.length > MAX) global._uptimeHistory.shift();
}

// seed dummy data then start polling uptime
seedDummyUptime();
pollUptime();
setInterval(pollUptime, UPTIME_POLL_INTERVAL);


app.get('/api/cves', async (req, res) => {
  const count = parseInt(req.query.count || '50', 10);
  const offset = parseInt(req.query.offset || '0', 10);
  try {
    const r = await fetch(CIRCL_LAST);
    let data = await r.json();
    // CIRCL /api/last sometimes returns an object with `value` array (CSAF) or a plain array
    if (!Array.isArray(data)) {
      if (data && Array.isArray(data.value)) data = data.value;
      else return res.status(502).json({ error: 'unexpected response' });
    }
    res.json(data.slice(offset, offset + count));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

app.get('/api/status', async (req, res) => {
  try {
    const st = await checkServices();
    res.json(st);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/uptime', async (req, res) => {
  // return uptime history (timestamp + ok) limited to most recent N
  try {
    res.json(global._uptimeHistory.slice(-144));
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
  while (fetched < totalResults && loop < 100) {
    const url = `${base}?pubStartDate=${encodeURIComponent(nvdDateString(startDate))}&pubEndDate=${encodeURIComponent(nvdDateString(endDate))}&startIndex=${startIndex}&resultsPerPage=${ps}`;
    const r = await fetch(url, { headers });
    if (!r.ok) throw new Error('NVD API error '+r.status);
    const j = await r.json();
    const items = (j && j.result && j.result.CVE_Items) || [];
    items.forEach(it => {
      const pd = it.publishedDate || (it.published && it.publishedDate) || null;
      if (!pd) return;
      const day = (new Date(pd)).toISOString().slice(0,10);
      if (counts.hasOwnProperty(day)) counts[day]++;
    });
    totalResults = (j && j.totalResults) || ((j && j.resultsPerPage) ? j.resultsPerPage : items.length);
    fetched += items.length;
    startIndex += items.length;
    loop++;
    if (items.length === 0) break;
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
      const r = await fetch(url, { headers: { 'User-Agent': 'CVE-dashboard/1.0 (https://example)' } });
      if (!r.ok) { console.warn('NVD feed fetch failed', r.status); continue; }
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
    await updateCveHistoryFromSource();
    setInterval(updateCveHistoryFromSource, 24 * 60 * 60 * 1000);
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
  fetchCveCountsFromNvd,
  fetchCveCountsFromNvdFeed,
  computeCveCountsFromSource
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
