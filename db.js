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
}

// --- CVE helpers ---
function upsertCve(id, data, published, cvssScore, enrichment) {
  const d = getDb();
  const e = enrichment || {};
  const stmt = d.prepare(`
    INSERT INTO cves (id, data, published, cvss_score, kev, has_exploit, has_patch, vendor, discovered)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET data=excluded.data, published=excluded.published, cvss_score=excluded.cvss_score,
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
  return d.prepare(`SELECT data, kev, has_exploit, has_patch, vendor, discovered FROM cves ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(count, offset).map(r => {
    const obj = JSON.parse(r.data);
    obj._kev = r.kev || 0;
    obj._exploit = r.has_exploit || 0;
    obj._patch = r.has_patch || 0;
    obj._vendor = r.vendor || '';
    obj._discovered = r.discovered || '';
    return obj;
  });
}

function getCvesFiltered(count, offset, cvssMin) {
  const d = getDb();
  if (!cvssMin || isNaN(cvssMin)) return getCves(count, offset);
  return d.prepare(`SELECT data, kev, has_exploit, has_patch, vendor, discovered FROM cves WHERE cvss_score IS NOT NULL AND cvss_score >= ? ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(cvssMin, count, offset).map(r => {
    const obj = JSON.parse(r.data);
    obj._kev = r.kev || 0;
    obj._exploit = r.has_exploit || 0;
    obj._patch = r.has_patch || 0;
    obj._vendor = r.vendor || '';
    obj._discovered = r.discovered || '';
    return obj;
  });
}

function getCveCount() {
  return getDb().prepare(`SELECT COUNT(*) as cnt FROM cves`).get().cnt;
}

function purgeCves(maxAgeDays) {
  const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString();
  const info = getDb().prepare(`DELETE FROM cves WHERE published < ? AND published IS NOT NULL`).run(cutoff);
  return info.changes;
}

// --- News helpers ---
function upsertNews(item) {
  const d = getDb();
  // Use link as id (most unique)
  const id = item.link || (item.title + '|' + item.source);
  const stmt = d.prepare(`
    INSERT INTO news (id, title, link, pub_date, source) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET title=excluded.title, pub_date=excluded.pub_date
  `);
  stmt.run(id, item.title || '', item.link || '', item.pubDate || item.pub_date || null, item.source || '');
}

function getNews(count, offset, sources) {
  const d = getDb();
  if (sources && sources.length > 0) {
    const placeholders = sources.map(() => '?').join(',');
    return d.prepare(`SELECT title, link, pub_date as pubDate, source FROM news WHERE source IN (${placeholders}) ORDER BY pub_date DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(...sources, count, offset);
  }
  return d.prepare(`SELECT title, link, pub_date as pubDate, source FROM news ORDER BY pub_date DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(count, offset);
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
      c.data, c.cvss_score, c.kev, c.has_exploit, c.has_patch, c.vendor, c.discovered, c.published
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
          _published: r.date_added || null
        };
      }
      const obj = JSON.parse(r.data);
      obj._kev = r.kev || 0; obj._exploit = r.has_exploit || 0; obj._patch = r.has_patch || 0;
      obj._vendor = r.vendor || r.kev_vendor || ''; obj._discovered = r.discovered || ''; obj._cvss = r.cvss_score;
      return obj;
    });
  }

  let sql = `SELECT data, cvss_score, kev, has_exploit, has_patch, vendor, discovered, published FROM cves WHERE published >= ?`;
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
  return getDb().prepare(`SELECT title, source, pub_date as pubDate FROM news WHERE pub_date >= ? ORDER BY pub_date DESC LIMIT 50`).all(cutoff);
}

function searchCves(query, limit) {
  const d = getDb();
  const like = '%' + query + '%';
  return d.prepare(`SELECT data, kev, has_exploit, has_patch, vendor, discovered FROM cves WHERE id LIKE ? OR vendor LIKE ? OR data LIKE ? ORDER BY published DESC LIMIT ?`).all(like, like, like, limit).map(r => {
    const obj = JSON.parse(r.data);
    obj._kev = r.kev || 0;
    obj._exploit = r.has_exploit || 0;
    obj._patch = r.has_patch || 0;
    obj._vendor = r.vendor || '';
    obj._discovered = r.discovered || '';
    return obj;
  });
}

function searchNews(query, limit) {
  const d = getDb();
  const like = '%' + query + '%';
  return d.prepare(`SELECT title, link, pub_date as pubDate, source FROM news WHERE title LIKE ? OR source LIKE ? ORDER BY pub_date DESC LIMIT ?`).all(like, like, limit);
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
  closeDb
};
