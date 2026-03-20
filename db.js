const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Use /app/data in Docker (volume), otherwise project root
const dataDir = fs.existsSync(path.join(__dirname, 'data')) ? path.join(__dirname, 'data') : __dirname;
const DB_PATH = path.join(dataDir, 'dashboard.db');
let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initTables();
  }
  return db;
}

function initTables() {
  const d = getDb();

  d.exec(`
    CREATE TABLE IF NOT EXISTS cves (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      published TEXT,
      fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  d.exec(`
    CREATE TABLE IF NOT EXISTS news (
      id TEXT PRIMARY KEY,
      title TEXT,
      link TEXT,
      pub_date TEXT,
      source TEXT,
      fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  d.exec(`
    CREATE TABLE IF NOT EXISTS uptime (
      ts INTEGER PRIMARY KEY,
      ok INTEGER NOT NULL,
      details TEXT
    )
  `);

  d.exec(`
    CREATE TABLE IF NOT EXISTS cve_daily_counts (
      date TEXT PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0
    )
  `);

  // Migration: add cvss_score column if missing
  try { d.exec(`ALTER TABLE cves ADD COLUMN cvss_score REAL`); } catch (e) { /* already exists */ }
  // Migration: add enrichment columns
  try { d.exec(`ALTER TABLE cves ADD COLUMN kev INTEGER DEFAULT 0`); } catch (e) {}
  try { d.exec(`ALTER TABLE cves ADD COLUMN has_exploit INTEGER DEFAULT 0`); } catch (e) {}
  try { d.exec(`ALTER TABLE cves ADD COLUMN has_patch INTEGER DEFAULT 0`); } catch (e) {}
  try { d.exec(`ALTER TABLE cves ADD COLUMN vendor TEXT`); } catch (e) {}
  try { d.exec(`ALTER TABLE cves ADD COLUMN discovered TEXT`); } catch (e) {}
  // Migration: add language column to ai_analysis if missing
  try { d.exec(`ALTER TABLE ai_analysis ADD COLUMN language TEXT NOT NULL DEFAULT 'en'`); } catch (e) {}
  // Migration: add description column to news if missing
  try { d.exec(`ALTER TABLE news ADD COLUMN description TEXT DEFAULT ''`); } catch (e) {}
  // Migration: add EPSS score column to cves if missing
  try { d.exec(`ALTER TABLE cves ADD COLUMN epss_score REAL`); } catch (e) {}

  // KEV (Known Exploited Vulnerabilities) cache
  d.exec(`
    CREATE TABLE IF NOT EXISTS kev (
      cve_id TEXT PRIMARY KEY,
      vendor TEXT,
      product TEXT,
      date_added TEXT,
      description TEXT
    )
  `);

  // Pre-generated reports
  d.exec(`
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      generated_at TEXT NOT NULL,
      data TEXT NOT NULL
    )
  `);

  // AI analysis reports
  d.exec(`
    CREATE TABLE IF NOT EXISTS ai_analysis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      period TEXT NOT NULL,
      analysis TEXT NOT NULL,
      language TEXT NOT NULL DEFAULT 'en',
      generated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // --- Indexes for query performance ---
  d.exec(`CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor COLLATE NOCASE)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_news_pub_date ON news(pub_date)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_news_source ON news(source)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev(date_added)`);
  d.exec(`CREATE INDEX IF NOT EXISTS idx_ai_period_lang ON ai_analysis(period, language, generated_at)`);

  // Backfill tracking: mark days as fully backfilled from NVD
  d.exec(`
    CREATE TABLE IF NOT EXISTS backfill_status (
      date TEXT PRIMARY KEY,
      nvd_total INTEGER NOT NULL DEFAULT 0,
      fetched INTEGER NOT NULL DEFAULT 0,
      completed_at TEXT
    )
  `);
}

// --- CVE slim helper (extract only fields the frontend needs) ---
function slimCve(row) {
  let obj;
  try { obj = JSON.parse(row.data); } catch (e) { obj = {}; }

  // --- extract ID ---
  let cveId = row.id || '';

  // --- extract title ---
  let title = '';
  if (obj.title) title = obj.title;
  else if (obj.summary && obj.summary.length < 140) title = obj.summary;
  else if (obj.cveMetadata && obj.cveMetadata.title) title = obj.cveMetadata.title;
  else if (Array.isArray(obj.descriptions) && obj.descriptions.length) {
    const d = obj.descriptions.find(d => d.lang === 'en') || obj.descriptions[0];
    if (d && d.value && d.value.length < 140) title = d.value;
  }
  if (!title && obj.containers && obj.containers.cna) {
    const cna = obj.containers.cna;
    if (cna.title) title = cna.title;
    else if (cna.descriptions && cna.descriptions.length) {
      const d = cna.descriptions[0];
      title = d.title || d.value || d.description || '';
      if (title.length < 140) { /* keep as title */ } else title = '';
    }
  }
  if (!title && obj.document && obj.document.title) title = obj.document.title;

  // --- extract description/summary ---
  let summary = '';
  if (obj.details) summary = obj.details;
  else if (obj.description) summary = typeof obj.description === 'string' ? obj.description : '';
  else if (obj.summary) summary = obj.summary;
  else if (Array.isArray(obj.descriptions) && obj.descriptions.length) {
    const d = obj.descriptions.find(d => d.lang === 'en') || obj.descriptions[0];
    if (d && d.value) summary = d.value;
  }
  if (!summary && obj.containers && obj.containers.cna) {
    const cna = obj.containers.cna;
    if (cna.descriptions && cna.descriptions.length) {
      const desc = cna.descriptions[0];
      summary = desc.value || desc.description || desc.text || '';
    } else if (typeof cna.descriptions === 'string') summary = cna.descriptions;
    else if (cna.title && !summary) summary = cna.title;
  }
  if (!summary && obj.document && obj.document.notes && obj.document.notes.length) {
    const note = obj.document.notes.find(n => n.category === 'summary') || obj.document.notes[0];
    if (note) summary = note.text || note.title || note.summary || '';
  }
  // Truncate very long summaries server-side to keep response size reasonable
  if (summary.length > 2000) summary = summary.slice(0, 2000);

  // --- extract CVSS ---
  let cvss = row.cvss_score != null ? row.cvss_score : null;
  if (cvss == null) {
    cvss = extractCvssFromObj(obj);
  }

  // --- extract published date ---
  let published = row.published || null;
  if (!published) {
    published = obj.Published || obj.published ||
      (obj.cveMetadata && (obj.cveMetadata.datePublished || obj.cveMetadata.dateUpdated)) ||
      (obj.document && obj.document.tracking && (obj.document.tracking.current_release_date || obj.document.tracking.initial_release_date)) ||
      null;
  }

  return {
    id: cveId,
    title: title || '',
    summary: summary || '',
    cvss: cvss,
    published: published,
    url: obj.url || '',
    _kev: row.kev || 0,
    _exploit: row.has_exploit || 0,
    _patch: row.has_patch || 0,
    _vendor: row.vendor ? row.vendor.charAt(0).toUpperCase() + row.vendor.slice(1) : '',
    _discovered: row.discovered || '',
    _epss: row.epss_score != null ? row.epss_score : null
  };
}

// Extract CVSS score from parsed CVE object (server-side mirror of frontend logic)
function extractCvssFromObj(it) {
  if (!it) return null;
  if (typeof it.cvss === 'number') return it.cvss;
  if (it.cvss && !isNaN(Number(it.cvss))) return Number(it.cvss);
  if (it.cvss3 && it.cvss3.baseScore) return Number(it.cvss3.baseScore);
  try {
    if (it.metrics) {
      const m = it.metrics;
      if (m.cvssMetricV31 && m.cvssMetricV31.length) return Number(m.cvssMetricV31[0].cvssData.baseScore);
      if (m.cvssMetricV40 && m.cvssMetricV40.length) return Number(m.cvssMetricV40[0].cvssData.baseScore);
      if (m.cvssMetricV30 && m.cvssMetricV30.length) return Number(m.cvssMetricV30[0].cvssData.baseScore);
      if (m.cvssMetricV2 && m.cvssMetricV2.length) return Number(m.cvssMetricV2[0].cvssData.baseScore);
    }
  } catch (e) {}
  try {
    const cont = it.containers || null;
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
  return null;
}

// --- CVE helpers ---
function upsertCve(id, data, published, cvssScore, enrichment) {
  const d = getDb();
  const e = enrichment || {};
  const stmt = d.prepare(`
    INSERT INTO cves (id, data, published, cvss_score, kev, has_exploit, has_patch, vendor, discovered)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET data=excluded.data, published=COALESCE(excluded.published, cves.published), cvss_score=excluded.cvss_score,
      kev=COALESCE(excluded.kev, cves.kev), has_exploit=COALESCE(excluded.has_exploit, cves.has_exploit),
      has_patch=COALESCE(excluded.has_patch, cves.has_patch), vendor=excluded.vendor,
      discovered=COALESCE(excluded.discovered, cves.discovered)
  `);
  stmt.run(id, typeof data === 'string' ? data : JSON.stringify(data), published || null,
    cvssScore != null && !isNaN(cvssScore) ? cvssScore : null,
    e.kev != null ? (e.kev ? 1 : 0) : null,
    e.has_exploit != null ? (e.has_exploit ? 1 : 0) : null,
    e.has_patch != null ? (e.has_patch ? 1 : 0) : null,
    e.vendor || null, e.discovered || null);
}

function getCves(count, offset) {
  const d = getDb();
  return d.prepare(`SELECT id, data, published, cvss_score, kev, has_exploit, has_patch, vendor, discovered, epss_score FROM cves ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(count, offset).map(slimCve);
}

function getCvesFiltered(count, offset, cvssMin) {
  const d = getDb();
  if (!cvssMin || isNaN(cvssMin)) return getCves(count, offset);
  return d.prepare(`SELECT id, data, published, cvss_score, kev, has_exploit, has_patch, vendor, discovered, epss_score FROM cves WHERE cvss_score IS NOT NULL AND cvss_score >= ? ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(cvssMin, count, offset).map(slimCve);
}

function getCveCount() {
  return getDb().prepare(`SELECT COUNT(*) as cnt FROM cves`).get().cnt;
}

function purgeCves(maxAgeDays) {
  const d = getDb();
  const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString();
  // Keep high-risk CVEs (KEV, exploited, or CVSS >= 8) for up to 1 year
  const riskCutoff = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
  const info = d.prepare(`DELETE FROM cves WHERE published < ? AND published IS NOT NULL
    AND NOT (published >= ? AND (kev = 1 OR has_exploit = 1 OR cvss_score >= 8))`).run(cutoff, riskCutoff);
  // Also purge CVEs with null published that were fetched long ago
  const nullInfo = d.prepare(`DELETE FROM cves WHERE published IS NULL AND fetched_at < ?`).run(cutoff);
  // Purge CVEs whose ID year is more than 2 years old (stale entries from feeds)
  const cutoffYear = new Date().getFullYear() - 2;
  const yearInfo = d.prepare(`DELETE FROM cves WHERE CAST(SUBSTR(id, 5, 4) AS INTEGER) > 0
    AND CAST(SUBSTR(id, 5, 4) AS INTEGER) < ?
    AND kev != 1 AND (has_exploit != 1 OR has_exploit IS NULL)`).run(cutoffYear);
  return info.changes + nullInfo.changes + yearInfo.changes;
}

// --- News helpers ---
function upsertNews(item) {
  const d = getDb();
  // Use link as id (most unique)
  const id = item.link || (item.title + '|' + item.source);
  const stmt = d.prepare(`
    INSERT INTO news (id, title, link, pub_date, source, description) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET title=excluded.title, pub_date=excluded.pub_date, description=COALESCE(excluded.description, news.description)
  `);
  stmt.run(id, item.title || '', item.link || '', item.pubDate || item.pub_date || null, item.source || '', item.description || '');
}

function getNews(count, offset, sources) {
  const d = getDb();
  if (sources && sources.length > 0) {
    const placeholders = sources.map(() => '?').join(',');
    return d.prepare(`SELECT title, link, pub_date as pubDate, source, description FROM news WHERE source IN (${placeholders}) ORDER BY pub_date DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(...sources, count, offset);
  }
  return d.prepare(`SELECT title, link, pub_date as pubDate, source, description FROM news ORDER BY pub_date DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(count, offset);
}

function getNewsSources() {
  const d = getDb();
  return d.prepare(`SELECT DISTINCT source FROM news WHERE source IS NOT NULL AND source != '' ORDER BY source`).all().map(r => r.source);
}

function getNewsCount() {
  return getDb().prepare(`SELECT COUNT(*) as cnt FROM news`).get().cnt;
}

function purgeNews(maxAgeDays) {
  const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString();
  const info = getDb().prepare(`DELETE FROM news WHERE pub_date < ? AND pub_date IS NOT NULL`).run(cutoff);
  return info.changes;
}

// --- Uptime helpers ---
function insertUptime(ts, ok, details) {
  const d = getDb();
  d.prepare(`INSERT OR REPLACE INTO uptime (ts, ok, details) VALUES (?, ?, ?)`).run(ts, ok ? 1 : 0, JSON.stringify(details || []));
}

function getUptime(hours) {
  const cutoff = Date.now() - hours * 60 * 60 * 1000;
  return getDb().prepare(`SELECT ts, ok, details FROM uptime WHERE ts >= ? ORDER BY ts ASC`).all(cutoff).map(r => ({
    ts: r.ts,
    ok: !!r.ok,
    details: r.details ? JSON.parse(r.details) : []
  }));
}

function purgeUptime(maxAgeDays) {
  const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
  return getDb().prepare(`DELETE FROM uptime WHERE ts < ?`).run(cutoff).changes;
}

function getUptimeCount() {
  return getDb().prepare(`SELECT COUNT(*) as cnt FROM uptime`).get().cnt;
}

// --- CVE daily counts ---
function upsertCveDailyCount(date, count) {
  getDb().prepare(`INSERT OR REPLACE INTO cve_daily_counts (date, count) VALUES (?, ?)`).run(date, count);
}

function getCveDailyCounts(days) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  return getDb().prepare(`SELECT date, count FROM cve_daily_counts WHERE date >= ? ORDER BY date ASC`).all(cutoff);
}

function closeDb() {
  if (db) { db.close(); db = null; }
}

// --- KEV helpers ---
function upsertKev(cveId, vendor, product, dateAdded, description) {
  getDb().prepare(`INSERT OR REPLACE INTO kev (cve_id, vendor, product, date_added, description) VALUES (?,?,?,?,?)`)
    .run(cveId, vendor || '', product || '', dateAdded || '', description || '');
}

function getKevSet() {
  const rows = getDb().prepare(`SELECT cve_id FROM kev`).all();
  return new Set(rows.map(r => r.cve_id));
}

function getKevEntries(days) {
  if (days) {
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    return getDb().prepare(`SELECT * FROM kev WHERE date_added >= ? ORDER BY date_added DESC`).all(cutoff);
  }
  return getDb().prepare(`SELECT * FROM kev ORDER BY date_added DESC`).all();
}

function updateCveEnrichment(cveId, fields) {
  const d = getDb();
  const sets = [];
  const vals = [];
  if (fields.kev != null) { sets.push('kev=?'); vals.push(fields.kev ? 1 : 0); }
  if (fields.has_exploit != null) { sets.push('has_exploit=?'); vals.push(fields.has_exploit ? 1 : 0); }
  if (fields.has_patch != null) { sets.push('has_patch=?'); vals.push(fields.has_patch ? 1 : 0); }
  if (fields.vendor != null) { sets.push('vendor=?'); vals.push(fields.vendor); }
  if (fields.discovered != null) { sets.push('discovered=?'); vals.push(fields.discovered); }
  if (fields.epss_score != null) { sets.push('epss_score=?'); vals.push(fields.epss_score); }
  if (fields.published != null) { sets.push('published=COALESCE(published,?)'); vals.push(fields.published); }
  if (sets.length === 0) return;
  vals.push(cveId);
  d.prepare(`UPDATE cves SET ${sets.join(',')} WHERE id=?`).run(...vals);
}

// --- Report helpers ---
function saveReport(data) {
  const id = new Date().toISOString().slice(0, 10);
  const d = getDb();
  d.prepare(`INSERT OR REPLACE INTO reports (id, generated_at, data) VALUES (?, datetime('now'), ?)`)
    .run(id, JSON.stringify(data));
}

function getLatestReport() {
  const row = getDb().prepare(`SELECT data, generated_at FROM reports ORDER BY generated_at DESC LIMIT 1`).get();
  if (!row) return null;
  return { generatedAt: row.generated_at, ...JSON.parse(row.data) };
}

// Report-specific queries
function getReportCves(options) {
  const d = getDb();
  const cutoff = new Date(Date.now() - (options.days || 30) * 24 * 60 * 60 * 1000).toISOString();
  const cutoffDate = cutoff.slice(0, 10);

  // For KEV queries, filter by kev.date_added instead of cves.published
  if (options.kevOnly) {
    let sql = `SELECT k.cve_id, k.vendor AS kev_vendor, k.product AS kev_product, k.description AS kev_description, k.date_added,
      c.data, c.cvss_score, c.kev, c.has_exploit, c.has_patch, c.vendor, c.discovered, c.published, c.epss_score
      FROM kev k LEFT JOIN cves c ON k.cve_id = c.id WHERE k.date_added >= ?`;
    const params = [cutoffDate];
    if (options.vendor) {
      const vendors = Array.isArray(options.vendor) ? options.vendor : [options.vendor];
      sql += ` AND lower(k.vendor) IN (${vendors.map(() => '?').join(',')})`;
      params.push(...vendors.map(v => v.toLowerCase()));
    }
    sql += ` ORDER BY k.date_added DESC`;
    if (options.limit) { sql += ` LIMIT ?`; params.push(options.limit); }
    return d.prepare(sql).all(...params).map(r => {
      if (!r.data) {
        // No CVE data in local DB — build a minimal object from KEV catalog info
        // KEV entries are "Known Exploited" by definition → _exploit: 1
        return {
          id: r.cve_id,
          descriptions: r.kev_description ? [{ lang: 'en', value: r.kev_description }] : [],
          _kev: 1, _exploit: 1, _patch: 0,
          _vendor: r.kev_vendor || '',
          _discovered: '', _cvss: null,
          _published: r.date_added || null,
          _epss: r.epss_score != null ? r.epss_score : null
        };
      }
      const obj = JSON.parse(r.data);
      obj._kev = r.kev || 0; obj._exploit = r.has_exploit || 0; obj._patch = r.has_patch || 0;
      obj._vendor = r.vendor || r.kev_vendor || ''; obj._discovered = r.discovered || ''; obj._cvss = r.cvss_score;
      obj._epss = r.epss_score != null ? r.epss_score : null;
      return obj;
    });
  }

  let sql = `SELECT data, cvss_score, kev, has_exploit, has_patch, vendor, discovered, published, epss_score FROM cves WHERE published >= ?`;
  const params = [cutoff];
  if (options.minCvss != null) { sql += ` AND cvss_score IS NOT NULL AND cvss_score >= ?`; params.push(options.minCvss); }
  if (options.maxCvss != null) { sql += ` AND (cvss_score IS NULL OR cvss_score < ?)`; params.push(options.maxCvss); }
  if (options.patchOnly === true) { sql += ` AND has_patch = 1`; }
  if (options.noPatchOnly === true) { sql += ` AND has_patch = 0`; }
  if (options.vendor) {
    const vendors = Array.isArray(options.vendor) ? options.vendor : [options.vendor];
    sql += ` AND lower(vendor) IN (${vendors.map(() => '?').join(',')})`;
    params.push(...vendors.map(v => v.toLowerCase()));
  }
  sql += ` ORDER BY cvss_score DESC, published DESC`;
  if (options.limit) { sql += ` LIMIT ?`; params.push(options.limit); }
  return d.prepare(sql).all(...params).map(r => {
    const obj = JSON.parse(r.data);
    obj._kev = r.kev || 0; obj._exploit = r.has_exploit || 0; obj._patch = r.has_patch || 0;
    obj._vendor = r.vendor || ''; obj._discovered = r.discovered || ''; obj._cvss = r.cvss_score;
    obj._epss = r.epss_score != null ? r.epss_score : null;
    return obj;
  });
}

function getReportStats(days, vendor) {
  const d = getDb();
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const cutoffDate = cutoff.slice(0, 10);
  let vf = '', vp = [];
  if (vendor) {
    const vendors = Array.isArray(vendor) ? vendor : [vendor];
    vf = ` AND lower(vendor) IN (${vendors.map(() => '?').join(',')})`;
    vp = vendors.map(v => v.toLowerCase());
  }
  const total = d.prepare(`SELECT COUNT(*) as cnt FROM cves WHERE published >= ?` + vf).get(cutoff, ...vp).cnt;
  const critical = d.prepare(`SELECT COUNT(*) as cnt FROM cves WHERE published >= ? AND cvss_score >= 9` + vf).get(cutoff, ...vp).cnt;
  // Count KEVs by their KEV catalog date_added, not CVE published date
  let kevSql = `SELECT COUNT(*) as cnt FROM kev WHERE date_added >= ?`;
  let kevParams = [cutoffDate];
  if (vendor) {
    const vendors = Array.isArray(vendor) ? vendor : [vendor];
    kevSql += ` AND lower(vendor) IN (${vendors.map(() => '?').join(',')})`;
    kevParams.push(...vendors.map(v => v.toLowerCase()));
  }
  const kevCount = d.prepare(kevSql).get(...kevParams).cnt;
  return { total, critical, kevCount };
}

function getTopVendors(days, limit) {
  const d = getDb();
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  return d.prepare(`SELECT UPPER(SUBSTR(MAX(vendor),1,1)) || SUBSTR(MAX(vendor),2) as vendor, COUNT(*) as cnt FROM cves WHERE published >= ? AND vendor IS NOT NULL AND vendor != '' GROUP BY vendor COLLATE NOCASE ORDER BY cnt DESC LIMIT ?`).all(cutoff, limit);
}

function getTopVendorsWithBreakdown(days, limit, vendorFilter) {
  const d = getDb();
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  let vf = '', vp = [];
  if (vendorFilter) {
    const vendors = Array.isArray(vendorFilter) ? vendorFilter : [vendorFilter];
    vf = ` AND lower(vendor) IN (${vendors.map(() => '?').join(',')})`;
    vp = vendors.map(v => v.toLowerCase());
  }
  return d.prepare(`SELECT UPPER(SUBSTR(MAX(vendor),1,1)) || SUBSTR(MAX(vendor),2) as vendor, COUNT(*) as cnt,
    SUM(CASE WHEN cvss_score >= 9 THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN cvss_score >= 7 AND cvss_score < 9 THEN 1 ELSE 0 END) as high,
    SUM(CASE WHEN cvss_score < 7 OR cvss_score IS NULL THEN 1 ELSE 0 END) as other,
    SUM(CASE WHEN kev = 1 THEN 1 ELSE 0 END) as kev
    FROM cves WHERE published >= ? AND vendor IS NOT NULL AND vendor != ''` + vf + `
    GROUP BY vendor COLLATE NOCASE ORDER BY cnt DESC LIMIT ?`).all(cutoff, ...vp, limit);
}

function getVendorList(days) {
  const d = getDb();
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  return d.prepare(`SELECT UPPER(SUBSTR(MAX(vendor),1,1)) || SUBSTR(MAX(vendor),2) as vendor, COUNT(*) as cnt FROM cves WHERE published >= ? AND vendor IS NOT NULL AND vendor != '' GROUP BY vendor COLLATE NOCASE ORDER BY cnt DESC`).all(cutoff);
}

// --- AI analysis helpers ---
function saveAiAnalysis(period, analysis, language) {
  getDb().prepare(`INSERT INTO ai_analysis (period, analysis, language) VALUES (?, ?, ?)`).run(period, analysis, language || 'en');
}

function getLatestAiAnalysis(period, language) {
  return getDb().prepare(`SELECT analysis, generated_at FROM ai_analysis WHERE period = ? AND language = ? ORDER BY generated_at DESC LIMIT 1`).get(period, language || 'en') || null;
}

function getRecentNews(days) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  return getDb().prepare(`SELECT title, link, source, pub_date as pubDate FROM news WHERE pub_date >= ? ORDER BY pub_date DESC LIMIT 50`).all(cutoff);
}

function searchCves(query, limit) {
  const d = getDb();
  const like = '%' + query + '%';
  return d.prepare(`SELECT id, data, published, cvss_score, kev, has_exploit, has_patch, vendor, discovered, epss_score FROM cves WHERE id LIKE ? OR vendor LIKE ? ORDER BY published DESC LIMIT ?`).all(like, like, limit).map(slimCve);
}

function searchNews(query, limit) {
  const d = getDb();
  const like = '%' + query + '%';
  return d.prepare(`SELECT title, link, pub_date as pubDate, source, description FROM news WHERE title LIKE ? OR source LIKE ? ORDER BY pub_date DESC LIMIT ?`).all(like, like, limit);
}

// --- Maintenance ---
function vacuum() {
  const d = getDb();
  try {
    d.pragma('wal_checkpoint(TRUNCATE)');
    d.exec('VACUUM');
    console.log('DB maintenance: VACUUM + WAL checkpoint complete');
  } catch (e) {
    console.error('DB maintenance error:', e.message);
  }
}

function trimOversizedBlobs(maxBytes) {
  maxBytes = maxBytes || 500000; // 500 KB default
  const d = getDb();
  const rows = d.prepare('SELECT id, LENGTH(data) as len FROM cves WHERE LENGTH(data) > ?').all(maxBytes);
  if (rows.length === 0) return 0;
  const stmt = d.prepare('UPDATE cves SET data = ? WHERE id = ?');
  let trimmed = 0;
  for (const row of rows) {
    try {
      const raw = d.prepare('SELECT data FROM cves WHERE id = ?').get(row.id);
      const obj = JSON.parse(raw.data);
      // Strip heavy nested data, keep essential fields
      const slim = {
        id: obj.id, descriptions: obj.descriptions,
        metrics: obj.metrics, references: obj.references,
        configurations: obj.configurations,
        containers: obj.containers ? {
          cna: obj.containers.cna ? {
            affected: obj.containers.cna.affected,
            references: obj.containers.cna.references,
            descriptions: obj.containers.cna.descriptions,
            metrics: obj.containers.cna.metrics
          } : undefined
        } : undefined
      };
      stmt.run(JSON.stringify(slim), row.id);
      trimmed++;
    } catch (e) {}
  }
  if (trimmed > 0) console.log(`DB maintenance: trimmed ${trimmed} oversized CVE blobs (>${(maxBytes/1024).toFixed(0)} KB)`);
  return trimmed;
}

// --- Software Inventory helpers (Patch Tuesday) ---
function initInventoryTable() {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS software_inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      vendor TEXT NOT NULL DEFAULT '',
      version TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL DEFAULT 'other',
      added_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  getDb().exec(`CREATE INDEX IF NOT EXISTS idx_inventory_vendor ON software_inventory(vendor COLLATE NOCASE)`);
}

function getInventory() {
  initInventoryTable();
  return getDb().prepare(`SELECT id, name, vendor, version, category, added_at FROM software_inventory ORDER BY vendor, name`).all();
}

function addInventoryItem(item) {
  initInventoryTable();
  const stmt = getDb().prepare(`INSERT INTO software_inventory (name, vendor, version, category) VALUES (?, ?, ?, ?)`);
  const info = stmt.run(item.name || '', item.vendor || '', item.version || '', item.category || 'other');
  return info.lastInsertRowid;
}

function updateInventoryItem(id, item) {
  initInventoryTable();
  getDb().prepare(`UPDATE software_inventory SET name=?, vendor=?, version=?, category=? WHERE id=?`)
    .run(item.name || '', item.vendor || '', item.version || '', item.category || 'other', id);
}

function deleteInventoryItem(id) {
  initInventoryTable();
  getDb().prepare(`DELETE FROM software_inventory WHERE id=?`).run(id);
}

// --- Risk-priority helpers ---
function getHighRiskCves(count, offset, maxAgeDays, vendor) {
  const d = getDb();
  const cutoff = new Date(Date.now() - (maxAgeDays || 90) * 24 * 60 * 60 * 1000).toISOString();
  let where = `WHERE published >= ? AND published IS NOT NULL AND cvss_score IS NOT NULL`;
  const params = [cutoff];
  if (vendor) {
    const vendors = Array.isArray(vendor) ? vendor : [vendor];
    where += ` AND lower(vendor) IN (${vendors.map(() => '?').join(',')})`;
    params.push(...vendors.map(v => v.toLowerCase()));
  }
  // Risk score: CVSS*10 + KEV*40 + exploit*25 + no-patch*20 + recency(0-20) + EPSS*100
  const sql = `SELECT id, data, published, cvss_score, kev, has_exploit, has_patch, vendor, discovered, epss_score,
    CAST(
      (cvss_score * 10)
      + (CASE WHEN kev = 1 THEN 40 ELSE 0 END)
      + (CASE WHEN has_exploit = 1 THEN 25 ELSE 0 END)
      + (CASE WHEN has_patch = 0 THEN 20 ELSE 0 END)
      + (CASE WHEN julianday('now') - julianday(published) <= 7 THEN 20
              WHEN julianday('now') - julianday(published) <= 30 THEN 14
              WHEN julianday('now') - julianday(published) <= 90 THEN 7
              ELSE 0 END)
      + (COALESCE(epss_score, 0) * 100)
    AS REAL) as risk_score
    FROM cves ${where}
    ORDER BY risk_score DESC, cvss_score DESC, published DESC
    LIMIT ? OFFSET ?`;
  params.push(count || 15, offset || 0);
  return d.prepare(sql).all(...params).map(row => {
    const slim = slimCve(row);
    slim._riskScore = Math.round(row.risk_score);
    return slim;
  });
}

function getRiskVendorStats(maxAgeDays, vendors) {
  const d = getDb();
  const cutoff = new Date(Date.now() - (maxAgeDays || 90) * 24 * 60 * 60 * 1000).toISOString();
  let where = `WHERE published >= ? AND published IS NOT NULL AND cvss_score IS NOT NULL
    AND vendor IS NOT NULL AND vendor != ''`;
  const params = [cutoff];
  if (vendors && vendors.length) {
    where += ` AND lower(vendor) IN (${vendors.map(() => '?').join(',')})`;
    params.push(...vendors.map(v => v.toLowerCase()));
  }
  return d.prepare(`SELECT UPPER(SUBSTR(MAX(vendor),1,1)) || SUBSTR(MAX(vendor),2) as vendor,
    COUNT(*) as total,
    SUM(CASE WHEN (cvss_score * 10
      + (CASE WHEN kev = 1 THEN 40 ELSE 0 END)
      + (CASE WHEN has_exploit = 1 THEN 25 ELSE 0 END)
      + (CASE WHEN has_patch = 0 THEN 20 ELSE 0 END)
      + (COALESCE(epss_score, 0) * 100)) >= 200 THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN (cvss_score * 10
      + (CASE WHEN kev = 1 THEN 40 ELSE 0 END)
      + (CASE WHEN has_exploit = 1 THEN 25 ELSE 0 END)
      + (CASE WHEN has_patch = 0 THEN 20 ELSE 0 END)
      + (COALESCE(epss_score, 0) * 100)) >= 150 THEN 1 ELSE 0 END) as high_count,
    ROUND(AVG(
      (cvss_score * 10)
      + (CASE WHEN kev = 1 THEN 40 ELSE 0 END)
      + (CASE WHEN has_exploit = 1 THEN 25 ELSE 0 END)
      + (CASE WHEN has_patch = 0 THEN 20 ELSE 0 END)
      + (COALESCE(epss_score, 0) * 100)
    ), 1) as avg_risk,
    SUM(CASE WHEN kev = 1 THEN 1 ELSE 0 END) as kev_count,
    SUM(CASE WHEN has_exploit = 1 THEN 1 ELSE 0 END) as exploit_count
    FROM cves ${where}
    GROUP BY vendor COLLATE NOCASE
    HAVING high_count > 0
    ORDER BY critical_count DESC, high_count DESC, avg_risk DESC
    LIMIT 10`).all(...params);
}

// --- Backfill tracking helpers ---
function getBackfillStatus(date) {
  return getDb().prepare('SELECT * FROM backfill_status WHERE date = ?').get(date) || null;
}

function markBackfillComplete(date, nvdTotal, fetched) {
  getDb().prepare(`
    INSERT INTO backfill_status (date, nvd_total, fetched, completed_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(date) DO UPDATE SET nvd_total=excluded.nvd_total, fetched=excluded.fetched, completed_at=excluded.completed_at
  `).run(date, nvdTotal, fetched);
}

function getIncompleteBackfillDays(maxDays) {
  const d = getDb();
  const now = new Date();
  const days = [];
  for (let i = maxDays - 1; i >= 1; i--) {
    const day = new Date(now.getTime() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const status = d.prepare('SELECT completed_at FROM backfill_status WHERE date = ?').get(day);
    if (!status || !status.completed_at) days.push(day);
  }
  return days;
}

module.exports = {
  getDb,
  upsertCve, getCves, getCvesFiltered, getCveCount, purgeCves,
  upsertNews, getNews, getNewsCount, getNewsSources, purgeNews,
  insertUptime, getUptime, purgeUptime, getUptimeCount,
  upsertCveDailyCount, getCveDailyCounts,
  upsertKev, getKevSet, getKevEntries, updateCveEnrichment,
  saveReport, getLatestReport, getReportCves, getReportStats, getTopVendors, getTopVendorsWithBreakdown, getVendorList,
  saveAiAnalysis, getLatestAiAnalysis, getRecentNews,
  searchCves, searchNews,
  getInventory, addInventoryItem, updateInventoryItem, deleteInventoryItem,
  getHighRiskCves, getRiskVendorStats,
  getBackfillStatus, markBackfillComplete, getIncompleteBackfillDays,
  closeDb,
  vacuum, trimOversizedBlobs
};
