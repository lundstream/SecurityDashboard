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
}

// --- CVE helpers ---
function upsertCve(id, data, published, cvssScore) {
  const d = getDb();
  const stmt = d.prepare(`
    INSERT INTO cves (id, data, published, cvss_score) VALUES (?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET data=excluded.data, published=excluded.published, cvss_score=excluded.cvss_score
  `);
  stmt.run(id, typeof data === 'string' ? data : JSON.stringify(data), published || null, cvssScore != null && !isNaN(cvssScore) ? cvssScore : null);
}

function getCves(count, offset) {
  const d = getDb();
  return d.prepare(`SELECT data FROM cves ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(count, offset).map(r => JSON.parse(r.data));
}

function getCvesFiltered(count, offset, cvssMin) {
  const d = getDb();
  if (!cvssMin || isNaN(cvssMin)) return getCves(count, offset);
  return d.prepare(`SELECT data FROM cves WHERE cvss_score IS NOT NULL AND cvss_score >= ? ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(cvssMin, count, offset).map(r => JSON.parse(r.data));
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

function getNews(count, offset) {
  const d = getDb();
  return d.prepare(`SELECT title, link, pub_date as pubDate, source FROM news ORDER BY pub_date DESC, fetched_at DESC LIMIT ? OFFSET ?`).all(count, offset);
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

module.exports = {
  getDb,
  upsertCve, getCves, getCvesFiltered, getCveCount, purgeCves,
  upsertNews, getNews, getNewsCount, purgeNews,
  insertUptime, getUptime, purgeUptime, getUptimeCount,
  upsertCveDailyCount, getCveDailyCounts,
  closeDb
};
