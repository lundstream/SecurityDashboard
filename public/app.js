async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('Fetch error ' + r.status);
  return r.json();
}

// client-side cache of loaded CVEs (pages appended here)
window._cves = window._cves || [];

// Parse a CVSS v3 vector string into a numeric base score, or return NaN
function parseCvssV3(parts) {
  const AV = { N:0.85, A:0.62, L:0.55, P:0.2 };
  const AC = { L:0.77, H:0.44 };
  const PR_U = { N:0.85, L:0.62, H:0.27 };
  const PR_C = { N:0.85, L:0.50, H:0.50 };
  const UI = { N:0.85, R:0.62 };
  const IM = { N:0, L:0.22, H:0.56 };
  const scope = parts.S;
  const av = AV[parts.AV], ac = AC[parts.AC];
  const pr = scope === 'C' ? PR_C[parts.PR] : PR_U[parts.PR];
  const ui = UI[parts.UI];
  const c = IM[parts.C], i = IM[parts.I], a = IM[parts.A];
  if ([av, ac, pr, ui, c, i, a].some(x => x === undefined)) return NaN;
  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const isc = scope === 'C'
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  if (isc <= 0) return 0;
  const exp = 8.22 * av * ac * pr * ui;
  const raw = scope === 'C' ? Math.min(1.08 * (isc + exp), 10) : Math.min(isc + exp, 10);
  return Math.ceil(raw * 10) / 10;
}

// Approximate CVSS v4 base score from vector metrics
function parseCvssV4(parts) {
  // Impact values for Vulnerable system (VC/VI/VA) and Subsequent system (SC/SI/SA)
  const IM = { N:0, L:0.22, H:0.56 };
  const vc = IM[parts.VC], vi = IM[parts.VI], va = IM[parts.VA];
  const sc = IM[parts.SC], si = IM[parts.SI], sa = IM[parts.SA];
  if ([vc, vi, va, sc, si, sa].some(x => x === undefined)) return NaN;
  // Exploitability weights
  const AV = { N:0.85, A:0.62, L:0.55, P:0.2 };
  const AC = { L:0.77, H:0.44 };
  const AT = { N:1.0, P:0.7 };
  const PR = { N:0.85, L:0.62, H:0.27 };
  const UI = { N:0.85, P:0.62, A:0.43 };
  const av = AV[parts.AV], ac = AC[parts.AC], at = AT[parts.AT];
  const pr = PR[parts.PR], ui = UI[parts.UI];
  if ([av, ac, at, pr, ui].some(x => x === undefined)) return NaN;
  // Combined impact from both vulnerable and subsequent systems
  const vulnImpact = 1 - (1 - vc) * (1 - vi) * (1 - va);
  const subImpact  = 1 - (1 - sc) * (1 - si) * (1 - sa);
  const totalImpact = 1 - (1 - vulnImpact) * (1 - subImpact * 0.5);
  const isc = 6.42 * totalImpact;
  if (isc <= 0) return 0;
  const exp = 8.22 * av * ac * at * pr * ui;
  const raw = Math.min(isc + exp, 10);
  return Math.ceil(raw * 10) / 10;
}

function parseCvssVector(vec) {
  if (!vec || typeof vec !== 'string') return NaN;
  const trimmed = vec.trim();
  const verMatch = trimmed.match(/^CVSS:(3\.[01]|4\.0)\//i);
  if (!verMatch) return NaN;
  const parts = {};
  for (const seg of trimmed.split('/').slice(1)) {
    const colon = seg.indexOf(':');
    if (colon > 0) parts[seg.slice(0, colon).toUpperCase()] = seg.slice(colon + 1).toUpperCase();
  }
  return verMatch[1].startsWith('4') ? parseCvssV4(parts) : parseCvssV3(parts);
}

function getCvssNumeric(it){
  if(!it) return NaN;
  // try legacy flat fields
  if(typeof it.cvss === 'number') return it.cvss;
  if(it.cvss && !isNaN(Number(it.cvss))) return Number(it.cvss);
  if(it.cvss3 && it.cvss3.baseScore) return Number(it.cvss3.baseScore);
  // NVD v2 metrics format
  try{
    if(it.metrics){
      const m = it.metrics;
      if(m.cvssMetricV31 && m.cvssMetricV31.length) return Number(m.cvssMetricV31[0].cvssData.baseScore);
      if(m.cvssMetricV40 && m.cvssMetricV40.length) return Number(m.cvssMetricV40[0].cvssData.baseScore);
      if(m.cvssMetricV30 && m.cvssMetricV30.length) return Number(m.cvssMetricV30[0].cvssData.baseScore);
      if(m.cvssMetricV2 && m.cvssMetricV2.length) return Number(m.cvssMetricV2[0].cvssData.baseScore);
    }
  }catch(e){}
  // NVD v2 style inside containers.adp[*] and CIRCL containers.cna
  try{
    const cont = it.containers || null;
    if(cont){
      const sources = [].concat(cont.adp || [], cont.cna ? [cont.cna] : []);
      for(const a of sources){
        if(a.metrics && a.metrics.length){
          for(const m of a.metrics){
            if(m.cvssV4_0 && m.cvssV4_0.baseScore) return Number(m.cvssV4_0.baseScore);
            if(m.cvssV3_1 && m.cvssV3_1.baseScore) return Number(m.cvssV3_1.baseScore);
            if(m.cvssV3 && m.cvssV3.baseScore) return Number(m.cvssV3.baseScore);
            if(m.cvssV3_0 && m.cvssV3_0.baseScore) return Number(m.cvssV3_0.baseScore);
          }
        }
      }
    }
  }catch(e){/* ignore */}
  // OSV/GHSA format: severity[].score is a CVSS vector string
  if(Array.isArray(it.severity)){
    for(const s of it.severity){
      if(s && s.score){
        const n = parseCvssVector(s.score);
        if(!isNaN(n)) return n;
      }
    }
  }
  // CSAF format: vulnerabilities[*].scores[*].cvss_v3.baseScore
  try {
    if (Array.isArray(it.vulnerabilities)) {
      for (const v of it.vulnerabilities) {
        if (v && Array.isArray(v.scores)) {
          for (const sc of v.scores) {
            if (sc.cvss_v3 && sc.cvss_v3.baseScore) return Number(sc.cvss_v3.baseScore);
            if (sc.cvss_v4 && sc.cvss_v4.baseScore) return Number(sc.cvss_v4.baseScore);
          }
        }
      }
    }
  } catch (e) { /* ignore */ }
  // fallback: severity text → approximate numeric
  const sevText = (it.database_specific && it.database_specific.severity)
    || (it.document && it.document.aggregate_severity && it.document.aggregate_severity.text)
    || '';
  if (sevText) {
    const sev = String(sevText).toUpperCase();
    if(sev === 'CRITICAL') return 9.0;
    if(sev === 'HIGH' || sev === 'IMPORTANT') return 7.5;
    if(sev === 'MEDIUM' || sev === 'MODERATE') return 5.0;
    if(sev === 'LOW')      return 2.0;
  }
  return NaN;
}

function applyCvssFilterAndRender(){
  const sel = document.getElementById('cvss-filter');
  const container = document.getElementById('cve-items');
  if(!container) return;
  // prefer programmatic value set by custom dropdown
  const val = (window._cvssFilterValue !== undefined) ? window._cvssFilterValue : (sel ? sel.value : 'all');
  let threshold = NaN;
  if(val !== 'all') threshold = Number(val) || NaN;
  // Only show items that have a real CVE-YYYY-NNNN id (skip GHSA-only advisories)
  const cveOnly = (window._cves || []).filter(it => {
    const id = extractCveId(it);
    return id && /^CVE-/i.test(id);
  });
  const filtered = cveOnly.filter(it => {
    if(isNaN(threshold)) return true;
    const score = getCvssNumeric(it);
    return !isNaN(score) && score >= threshold;
  });
  if(!filtered.length && !isNaN(threshold)){
    container.innerHTML = '<div style="color:var(--muted);padding:12px">No CVEs with CVSS ≥ ' + threshold + ' found in current page.</div>';
    return;
  }
  container.innerHTML = renderCveItems(filtered.length ? filtered : cveOnly);
}

// prefer items that mention resolution/patch/fix/workaround/mitigat and ensure minimum count
function selectResolutionItems(items, minCount){
  if(!Array.isArray(items) || items.length===0) return [];
  const re = /\b(patch|patched|fix|fixed|resolve|resolved|resolution|mitigat|mitigated|workaround)\b/i;
  const matched = [];
  const others = [];
  for(const it of items){
    const s = (typeof it === 'string') ? it : JSON.stringify(it);
    if(re.test(s)) matched.push(it);
    else others.push(it);
  }
  const out = [];
  for(const m of matched) { if(out.length>=minCount) break; out.push(m); }
  let i=0;
  while(out.length < Math.min(minCount, items.length) && i < others.length){ out.push(others[i++]); }
  return out;
}

// Shared helper: extract CVE-YYYY-NNNN id from an item (returns '' if not found)
function extractCveId(it) {
  if (!it) return '';
  if (it.cveMetadata && it.cveMetadata.cveId) return it.cveMetadata.cveId.toUpperCase();
  // explicit aliases array (OSV/GHSA) may contain CVE identifiers
  try {
    if (Array.isArray(it.aliases) && it.aliases.length) {
      for (const a of it.aliases) {
        if (!a) continue;
        const ma = String(a).match(/CVE-\d{4}-\d{4,7}/i);
        if (ma) return ma[0].toUpperCase();
      }
    }
  } catch (e) { /* ignore */ }
  // scan full JSON for CVE pattern as a fallback
  try {
    const s = JSON.stringify(it);
    const m = s.match(/CVE-\d{4}-\d{4,7}/i);
    if (m) return m[0].toUpperCase();
  } catch (e) { /* ignore */ }
  // check explicit id fields
  const raw = it.id || it.CVE || it.cve || '';
  if (raw) {
    const m2 = String(raw).match(/CVE-\d{4}-\d{4,7}/i);
    if (m2) return m2[0].toUpperCase();
  }
  return '';
}

// --- Rendering helpers ---
function renderCveItems(items) {
  if (!items || !items.length) return '';
  function extractId(it) {
    // always prefer a CVE id; never fall back to GHSA
    return extractCveId(it);
  }
  function extractTitle(it) {
    if (!it) return '';
    if (it.title) return it.title;
    if (it.summary && it.summary.length && it.summary.length < 140) return it.summary;
    if (it.cveMetadata && it.cveMetadata.title) return it.cveMetadata.title;
    // NVD v2: short descriptions
    if (Array.isArray(it.descriptions) && it.descriptions.length) {
      const d = it.descriptions.find(d => d.lang === 'en') || it.descriptions[0];
      if (d && d.value && d.value.length < 140) return d.value;
    }
    if (it.containers && it.containers.cna) {
      const cna = it.containers.cna;
      if (cna.title) return cna.title;
      if (cna.descriptions && cna.descriptions.length) {
        const d = cna.descriptions[0];
        return d.title || d.value || d.description || '';
      }
    }
    if (it.document && it.document.title) return it.document.title;
    // fallback: try to extract a short summary sentence
    const s = extractSummary(it) || '';
    const m = s.match(/^(.{20,160}?)(?:[\.!?]\s|$)/);
    return m ? m[1] : '';
  }
  function extractSummary(it) {
    if (!it) return '';
    if (it.details) return it.details;
    if (it.description) return it.description;
    if (it.summary) return it.summary;
    // NVD v2 format: descriptions array
    if (Array.isArray(it.descriptions) && it.descriptions.length) {
      const d = it.descriptions.find(d => d.lang === 'en') || it.descriptions[0];
      if (d && d.value) return d.value;
    }
    if (it.containers && it.containers.cna) {
      const cna = it.containers.cna;
      if (cna.descriptions && cna.descriptions.length) {
        const desc = cna.descriptions[0];
        return desc.value || desc.description || desc.text || '';
      }
      if (cna.descriptions && typeof cna.descriptions === 'string') return cna.descriptions;
      if (cna.title) return cna.title;
    }
    if (it.document && it.document.notes && it.document.notes.length) {
      const note = it.document.notes.find(n => n.category === 'summary') || it.document.notes[0];
      if (note) return note.text || note.title || note.summary || '';
    }
    return '';
  }
  function extractPublished(it) {
    const p = it.Published || it.published || (it.cveMetadata && it.cveMetadata.datePublished) || (it.cveMetadata && it.cveMetadata.dateUpdated) || (it.document && it.document.tracking && (it.document.tracking.current_release_date || it.document.tracking.initial_release_date)) || null;
    if (!p) return 'N/A';
    const d = new Date(p);
    if (!isNaN(d.getTime())) return d.toLocaleString();
    return String(p);
  }
  function extractCvss(it) {
    const n = getCvssNumeric(it);
    if (!isNaN(n)) return n.toFixed(1);
    if (it && it.database_specific && it.database_specific.severity) return it.database_specific.severity;
    if (it && it.document && it.document.aggregate_severity) return it.document.aggregate_severity.text || 'N/A';
    return 'N/A';
  }
  return items.map(it => {
    const id = extractId(it) || '';
    const title = extractTitle(it) || id || '(no id)';
    let url = '#';
    if (id && id.toUpperCase().startsWith('CVE-')) url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + encodeURIComponent(id);
    else if (id && id.toUpperCase().startsWith('GHSA-')) url = 'https://github.com/advisories/' + encodeURIComponent(id);
    else if (it && it.url) url = it.url;
    const cvss = extractCvss(it);
    // color-code CVSS score
    let cvssStyle = '';
    const cvssNum = parseFloat(cvss);
    if (!isNaN(cvssNum)) {
      if (cvssNum >= 9) cvssStyle = 'color:#e74c3c;font-weight:700';
      else if (cvssNum >= 8) cvssStyle = 'color:#e67e22;font-weight:700';
      else if (cvssNum >= 6) cvssStyle = 'color:#f1c40f;font-weight:600';
    }
    const published = extractPublished(it);
    let rawSummary = extractSummary(it) || '';
    // Strip markdown to plain text: remove code blocks, headers, links, images, bold/italic, lists
    let summary = rawSummary
      .replace(/```[\s\S]*?```/g, '')           // fenced code blocks
      .replace(/`[^`]*`/g, '')                   // inline code
      .replace(/^#{1,6}\s+.*$/gm, '')            // markdown headers
      .replace(/!\[[^\]]*\]\([^)]*\)/g, '')      // images
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')   // links → text
      .replace(/(\*\*|__)(.*?)\1/g, '$2')        // bold
      .replace(/(\*|_)(.*?)\1/g, '$2')           // italic
      .replace(/^\s*[-*+]\s+/gm, '')             // unordered list markers
      .replace(/^\s*\d+\.\s+/gm, '')             // ordered list markers
      .replace(/\n{2,}/g, '\n')                  // collapse blank lines
      .replace(/\n/g, ' ')
      .replace(/\s{2,}/g, ' ')
      .trim();
    // avoid duplicating title when summary begins with the same text
    if (title && summary) {
      const tnorm = title.replace(/\s+/g,' ').trim();
      if (summary.indexOf(tnorm) === 0) {
        summary = summary.slice(tnorm.length).trim();
      }
    }
    // Truncate to ~300 chars at a word boundary
    if (summary.length > 300) {
      summary = summary.slice(0, 300).replace(/\s+\S*$/, '') + '…';
    }
    if (!summary) summary = 'Recently published \u2014 description pending';
    const zeroTag = /\bzero[- ]?day\b|\b0[- ]?day\b|zero\sday/i.test(summary) ? '<span class="tag">Possible Zero-Day</span>' : '';
    // Render as: ID: Title  (link the ID when present). Fall back to title when no ID.
    let headHtml = '';
    if (id) {
      const idUrl = (id.toUpperCase().startsWith('CVE-')) ? ('https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + encodeURIComponent(id)) : (id.toUpperCase().startsWith('GHSA-') ? ('https://github.com/advisories/' + encodeURIComponent(id)) : url);
      const safeId = escapeHtml(id);
      const safeTitle = escapeHtml(title && title !== id ? title : '');
      headHtml = `<a href="${idUrl}" target="_blank" rel="noopener">${safeId}</a>` + (safeTitle ? (': ' + safeTitle) : '');
    } else {
      headHtml = `<a href="${url}" target="_blank" rel="noopener">${escapeHtml(title)}</a>`;
    }
    // append zero-day tag after the title
    const zeroHtml = zeroTag ? (' ' + zeroTag) : '';
    // Enrichment badges
    const discovered = it._discovered ? fmtDate(it._discovered) : '';
    const kevBadge = it._kev ? '<span class="badge badge-kev">KEV</span>' : '';
    const exploitBadge = it._exploit ? '<span class="badge badge-exploit">Exploit</span>' : '<span class="badge badge-no">No exploit</span>';
    const patchBadge = it._patch ? '<span class="badge badge-patch">Patch</span>' : '<span class="badge badge-nopatch">No patch</span>';
    const discoveredLine = discovered ? `Discovered: ${discovered} • ` : '';
    return `
      <div class="card">
        <div>${headHtml}${zeroHtml}</div>
        <div class="meta"><span style="${cvssStyle}">CVSS: ${cvss}</span> • ${discoveredLine}Published: ${published}</div>
        <div class="cve-badges">${exploitBadge} ${patchBadge} ${kevBadge}</div>
        <div class="desc">${escapeHtml(summary)}</div>
      </div>
    `;
  }).join('');
}

function fmtDate(dt) {
  if (!dt) return 'N/A';
  const d = (dt instanceof Date) ? dt : new Date(dt);
  if (isNaN(d.getTime())) return 'N/A';
  return d.toISOString().slice(0, 10);
}

// small helper to escape HTML in title/summary strings
function escapeHtml(s){
  if(!s) return '';
  return String(s).replace(/[&<>\"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; });
}

function renderNewsItems(items) {
  if (!items || !items.length) return '';
  function fmt(dt) {
    if (!dt) return 'N/A';
    const d = (dt instanceof Date) ? dt : new Date(dt);
    if (isNaN(d.getTime())) return 'N/A';
    const pad = n => String(n).padStart(2, '0');
    const YYYY = d.getFullYear();
    const MM = pad(d.getMonth() + 1);
    const DD = pad(d.getDate());
    const hh = pad(d.getHours());
    const mm = pad(d.getMinutes());
    return `${YYYY}-${MM}-${DD} ${hh}:${mm}`;
  }
  return items.map(it => {
    const title = it.title || '(no title)';
    const link = it.link || '#';
    const pubRaw = it.pubDate || it.updated || it.published || null;
    const pub = fmt(pubRaw);
    const src = it.source || '';
    return `
      <div class="card">
        <div><a href="${link}" target="_blank" rel="noopener">${title}</a></div>
        <div class="meta">${src} • ${pub}</div>
      </div>
    `;
  }).join('');
}

// --- Pagination state ---
let newsPageSize = 15;
let newsOffset = 0;
let _newsPreloaded = null;   // background-fetched next batch
let _newsPreloading = false;
let _newsSources = [];       // selected source URLs (empty = all)

let cvePageSize = 10;
let cveOffset = 0;
let _cvePreloaded = null;    // background-fetched next batch
let _cvePreloading = false;

// helper to update button visibility
function updateButtonVisibility(container, btn) {
  if (!container || !btn) return;
  const available = btn.dataset.available === 'true';
  if (!available) { btn.style.display = 'none'; return; }
  // show when footer is visible (IntersectionObserver also drives this)
  if (container.scrollHeight - container.scrollTop - container.clientHeight < 60) btn.style.display = 'inline-block';
  else btn.style.display = 'none';
}

// silently prefetch the next news batch
async function preloadNews(offset) {
  if (_newsPreloading || _newsPreloaded !== null) return;
  _newsPreloading = true;
  try {
    let url = `/api/rss?count=${newsPageSize}&offset=${offset}`;
    if (_newsSources.length) url += '&source=' + encodeURIComponent(_newsSources.join(','));
    const data = await fetchJSON(url);
    _newsPreloaded = Array.isArray(data) ? data : [];
  } catch (e) { _newsPreloaded = []; }
  _newsPreloading = false;
}

// load a page of news and append
async function loadNews(offsetArg) {
  const offset = (typeof offsetArg === 'number') ? offsetArg : newsOffset;
  const btn = document.getElementById('news-load-more');
  const container = document.getElementById('news-items');
  if (btn) { btn.disabled = true; btn.textContent = 'Loading...'; }
  let news;
  if (offset > 0 && _newsPreloaded !== null) {
    // use already-prefetched data — instant display
    news = _newsPreloaded;
    _newsPreloaded = null;
  } else {
    try {
      let url = `/api/rss?count=${newsPageSize}&offset=${offset}`;
      if (_newsSources.length) url += '&source=' + encodeURIComponent(_newsSources.join(','));
      news = await fetchJSON(url);
    } catch (e) {
      if (offset === 0) container.innerHTML = 'Error: ' + e.message;
      if (btn) { btn.disabled = false; btn.textContent = 'Load more'; btn.dataset.available = 'false'; }
      return;
    }
  }
  // Fallback: if DB returned less than a full page and we're paging, try live source
  if (offset > 0 && Array.isArray(news) && news.length < newsPageSize) {
    try {
      const more = await fetchJSON(`/api/rss/more?count=${newsPageSize}&offset=${offset}`);
      if (Array.isArray(more) && more.length) news = news.concat(more);
    } catch (e) { /* ignore fallback error */ }
  }
  if (offset === 0) {
    container.innerHTML = renderNewsItems(news);
  } else {
    container.innerHTML += renderNewsItems(news);
  }
  newsOffset = offset + (Array.isArray(news) ? news.length : 0);
  if (btn) {
    btn.disabled = false;
    btn.textContent = 'Load more';
    btn.dataset.available = (Array.isArray(news) && news.length === newsPageSize) ? 'true' : 'false';
    updateButtonVisibility(document.getElementById('news-list'), btn);
  }
  // kick off background prefetch of the next batch
  if (Array.isArray(news) && news.length === newsPageSize) {
    setTimeout(() => preloadNews(newsOffset), 200);
  }
}

// silently prefetch the next CVE batch
async function preloadCves(offset) {
  if (_cvePreloading || _cvePreloaded !== null) return;
  _cvePreloading = true;
  try {
    let url = `/api/cves?count=${cvePageSize}&offset=${offset}`;
    if (window._cvssMin) url += `&cvssMin=${window._cvssMin}`;
    const data = await fetchJSON(url);
    _cvePreloaded = Array.isArray(data) ? data : [];
  } catch (e) { _cvePreloaded = []; }
  _cvePreloading = false;
}

// load a page of CVEs and append
async function loadCves(offsetArg) {
  const offset = (typeof offsetArg === 'number') ? offsetArg : cveOffset;
  const btn = document.getElementById('cve-load-more');
  const container = document.getElementById('cve-items');
  if (btn) { btn.disabled = true; btn.textContent = 'Loading...'; }
  let cves;
  if (offset > 0 && _cvePreloaded !== null) {
    // use already-prefetched data — instant display
    cves = _cvePreloaded;
    _cvePreloaded = null;
  } else {
    try {
      let url = `/api/cves?count=${cvePageSize}&offset=${offset}`;
      if (window._cvssMin) url += `&cvssMin=${window._cvssMin}`;
      cves = await fetchJSON(url);
    } catch (e) {
      container.innerHTML = 'Error: ' + e.message;
      if (btn) { btn.disabled = false; btn.textContent = 'Load more'; btn.dataset.available = 'false'; }
      return;
    }
  }
  // Fallback: if DB returned less than a full page and we're paging, try live source
  if (offset > 0 && Array.isArray(cves) && cves.length < cvePageSize && !window._cvssMin) {
    try {
      const more = await fetchJSON(`/api/cves/more?count=${cvePageSize}&offset=${offset}`);
      if (Array.isArray(more) && more.length) cves = cves.concat(more);
    } catch (e) { /* ignore fallback error */ }
  }
  // maintain client-side cache
  if (offset === 0) window._cves = [];
  if (Array.isArray(cves)) window._cves = window._cves.concat(cves);
  cveOffset = offset + (Array.isArray(cves) ? cves.length : 0);
  // render (server already filtered by CVSS when applicable)
  if (window._cves.length === 0 && window._cvssMin) {
    container.innerHTML = '<div style="color:var(--muted);padding:12px">No CVEs with CVSS \u2265 ' + window._cvssMin + ' found yet. Data is still being collected.</div>';
  } else {
    container.innerHTML = renderCveItems(window._cves);
  }
  if (btn) {
    btn.disabled = false;
    btn.textContent = 'Load more';
    btn.dataset.available = (Array.isArray(cves) && cves.length === cvePageSize) ? 'true' : 'false';
    updateButtonVisibility(document.getElementById('cve-list'), btn);
  }
  // kick off background prefetch of the next batch
  if (Array.isArray(cves) && cves.length === cvePageSize) {
    setTimeout(() => preloadCves(cveOffset), 200);
  }
}

// setup IntersectionObserver on the footer so the button shows when footer enters view
function setupFooterObserver(listId, btnId) {
  const list = document.getElementById(listId);
  const btn = document.getElementById(btnId);
  if (!list || !btn) return;
  const footer = list.querySelector('.list-footer');
  if (!footer) return;
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(entries => {
      for (const en of entries) {
        if (en.isIntersecting) updateButtonVisibility(list, btn);
        else btn.style.display = 'none';
      }
    }, { root: list, threshold: 0.01 });
    io.observe(footer);
  } else {
    list.addEventListener('scroll', () => updateButtonVisibility(list, btn));
  }
  btn.addEventListener('click', () => {
    if (btnId === 'news-load-more') loadNews(newsOffset);
    else if (btnId === 'cve-load-more') loadCves(cveOffset);
  });
}

// --- URL-to-friendly-name mapping for news sources ---
const SOURCE_NAMES = {
  'https://www.bleepingcomputer.com/feed/': 'BleepingComputer',
  'https://feeds.feedburner.com/TheHackersNews': 'The Hacker News',
  'https://techcrunch.com/feed/': 'TechCrunch',
  'https://www.securityweek.com/feed/': 'SecurityWeek',
  'https://www.schneier.com/blog/atom.xml': 'Schneier on Security',
  'https://www.reddit.com/r/netsec/.rss': 'r/netsec',
  'https://computersweden.se/feed/': 'Computer Sweden',
  'https://neowin.net/news/rss/': 'Neowin',
  'https://advania.se/feed/': 'Advania',
};
function friendlySourceName(url) {
  if (SOURCE_NAMES[url]) return SOURCE_NAMES[url];
  try { const u = new URL(url); return u.hostname.replace(/^www\./, ''); } catch (e) { return url; }
}

// --- News source filter dropdown ---
async function setupNewsSourceFilter() {
  const btn = document.getElementById('news-source-btn');
  const menu = document.getElementById('news-source-menu');
  if (!btn || !menu) return;

  // Fetch available sources
  let sources = [];
  try { sources = await fetchJSON('/api/news-sources'); } catch (e) {}

  // Build menu items
  menu.innerHTML = '<li class="cvss-option" data-value="all" role="option" aria-selected="true">All</li>' +
    sources.map(s => `<li class="cvss-option" data-value="${s}" role="option">${friendlySourceName(s)}</li>`).join('');

  let selectedSource = null; // null = all

  function closeMenu() { menu.setAttribute('aria-hidden', 'true'); btn.setAttribute('aria-expanded', 'false'); }
  function openMenu() { menu.setAttribute('aria-hidden', 'false'); btn.setAttribute('aria-expanded', 'true'); }

  function updateSelection() {
    menu.querySelectorAll('.cvss-option').forEach(o => {
      const v = o.getAttribute('data-value');
      if (v === 'all') o.setAttribute('aria-selected', selectedSource === null ? 'true' : 'false');
      else o.setAttribute('aria-selected', v === selectedSource ? 'true' : 'false');
    });
    btn.firstChild.nodeValue = selectedSource ? friendlySourceName(selectedSource) + ' ' : 'All ';
  }

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = menu.getAttribute('aria-hidden') === 'false';
    if (open) closeMenu(); else openMenu();
  });

  menu.querySelectorAll('.cvss-option').forEach(li => {
    li.addEventListener('click', () => {
      const v = li.getAttribute('data-value');
      selectedSource = (v === 'all') ? null : v;
      _newsSources = selectedSource ? [selectedSource] : [];
      updateSelection();
      closeMenu();
      // Reset pagination and reload
      newsOffset = 0;
      _newsPreloaded = null;
      _newsPreloading = false;
      loadNews(0);
    });
  });

  document.addEventListener('click', () => { closeMenu(); });
  closeMenu();
}

function init() {
  setupFooterObserver('news-list', 'news-load-more');
  setupFooterObserver('cve-list', 'cve-load-more');
  // initial loads
  loadCves(0);
  loadNews(0);
  // fetch header status and charts
  fetchAndRenderStatus();
  fetchAndRenderUptime();
  fetchUptimeStats();
  fetchAndRenderCveStats();
  setupCveSearch();
  setupReportDropdown();
  setupLinksDropdown();
  setupNewsSourceFilter();
  fetchVisitorIp();
  fetchPublicSettings();
  fetchAndRenderVendorDonut();
  setupThemeToggle();
  // setup CVSS filter listener
  const sel = document.getElementById('cvss-filter');
  if(sel){ sel.addEventListener('change', () => { window._cvssMin = sel.value === 'all' ? null : Number(sel.value); cveOffset = 0; _cvePreloaded = null; _cvePreloading = false; loadCves(0); }); }
  // init custom dropdown if present
  const dd = document.getElementById('cvss-dropdown');
  if(dd){
    const btn = document.getElementById('cvss-dropdown-btn');
    const menu = document.getElementById('cvss-dropdown-menu');
    window._cvssMin = null;
    function closeMenu(){ if(menu){ menu.setAttribute('aria-hidden','true'); btn.setAttribute('aria-expanded','false'); } }
    function openMenu(){ if(menu){ menu.setAttribute('aria-hidden','false'); btn.setAttribute('aria-expanded','true'); } }
    btn.addEventListener('click', (e)=>{ e.stopPropagation(); const open = menu.getAttribute('aria-hidden') === 'false'; if(open) closeMenu(); else openMenu(); });
    // option clicks
    menu.querySelectorAll('.cvss-option').forEach(li=>{
      li.addEventListener('click', (ev)=>{
        const v = li.getAttribute('data-value');
        window._cvssMin = (v === 'all') ? null : Number(v);
        // update label on button
        btn.firstChild.nodeValue = (li.textContent || li.innerText) + ' ';
        // mark selected
        menu.querySelectorAll('.cvss-option').forEach(o=>o.removeAttribute('aria-selected'));
        li.setAttribute('aria-selected','true');
        // reset pagination and reload from server
        cveOffset = 0;
        _cvePreloaded = null;
        _cvePreloading = false;
        loadCves(0);
        closeMenu();
      });
    });
    // close on outside click
    document.addEventListener('click', ()=>{ closeMenu(); });
    // initialize
    closeMenu();
  }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

// --- header/status/chart helpers ---
async function fetchAndRenderStatus() {
  try {
    const res = await fetchJSON('/api/status');
    // map service name -> entry
    const map = {};
    if (Array.isArray(res.services)) {
      res.services.forEach(s => { if (s && s.name) map[s.name] = s; });
    }
    // helper to apply color to header id and make clickable
    function apply(id, entry, href) {
      const el = document.getElementById(id);
      if (!el) return;
      const dot = el.querySelector('span.dot');
      const label = el.querySelector('div') || el;
      if (!dot) return;
      const color = (entry && entry.color) || (entry && entry.ok ? 'green' : 'red');
      const bg = color === 'green' ? '#2ecc71' : (color === 'yellow' ? '#f9a825' : '#e74c3c');
      dot.style.backgroundColor = bg;
      dot.style.boxShadow = color === 'green' ? '0 0 6px rgba(46,204,113,0.35)' : '0 0 6px rgba(231,76,60,0.2)';
      dot.setAttribute('aria-label', (entry && entry.ok) ? 'up' : 'down');
      if (label && entry && entry.color) label.title = `${entry.name} ${entry.color}`;
      // make clickable to official status page
      if (href) {
        el.style.cursor = 'pointer';
        el.onclick = () => window.open(href, '_blank');
      }
    }
    // possible service keys returned: 'cloudflare','aws','microsoft'
    apply('svc-cloudflare', map['cloudflare'] || map['cloudflare_trace'] || map['1.1.1.1'], 'https://www.cloudflarestatus.com');
    apply('svc-aws', map['aws'] || map['status.aws'], 'https://health.aws.amazon.com/health/status');
    apply('svc-microsoft', map['microsoft'] || map['microsoft_o365'], 'https://status.cloud.microsoft');

    // Render Microsoft tooltip with individual host status
    const msEntry = map['microsoft'];
    const msTip = document.getElementById('ms-tooltip');
    if (msEntry && msEntry.hosts && msTip) {
      msTip.innerHTML = msEntry.hosts.map(h => {
        const bg = h.ok ? '#2ecc71' : '#e74c3c';
        const shadow = h.ok ? '0 0 6px rgba(46,204,113,0.35)' : '0 0 6px rgba(231,76,60,0.2)';
        const host = escapeHtml((h.host || '').replace(/\/+$/, ''));
        return `<div class="ms-row"><span class="dot" style="background:${bg};box-shadow:${shadow}"></span><span>${host}</span></div>`;
      }).join('');
    } else if (msTip && msTip.textContent === 'Loading...') {
      msTip.innerHTML = '<div class="ms-row" style="color:var(--muted)">Checking services…</div>';
    }
  } catch (e) { console.error('status', e); }
}

// --- CVE search ---
function renderSingleCve(it) {
  if (!it) return '<div>No result</div>';
  return renderCveItems([it]);
}

function setupCveSearch(){
  const input = document.getElementById('cve-search');
  if (!input) return;
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const q = (input.value || '').trim();
      if (!q) return;
      const url = 'https://www.cve.org/CVERecord/SearchResults?query=' + encodeURIComponent(q);
      window.open(url, '_blank');
      input.value = '';
    }
  });
}

function setupReportDropdown() {
  const btn = document.getElementById('report-dropdown-btn');
  const menu = document.getElementById('report-dropdown-menu');
  if (!btn || !menu) return;
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.classList.toggle('open');
    // close links dropdown
    const lm = document.getElementById('links-dropdown-menu');
    if (lm) lm.classList.remove('open');
  });
  document.addEventListener('click', () => menu.classList.remove('open'));
  menu.addEventListener('click', (e) => e.stopPropagation());
}

function setupLinksDropdown() {
  const btn = document.getElementById('links-dropdown-btn');
  const menu = document.getElementById('links-dropdown-menu');
  if (!btn || !menu) return;
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.classList.toggle('open');
    // close report dropdown
    const rm = document.getElementById('report-dropdown-menu');
    if (rm) rm.classList.remove('open');
  });
  document.addEventListener('click', () => menu.classList.remove('open'));
  menu.addEventListener('click', (e) => e.stopPropagation());
}

// refresh service status periodically so UI updates when server cache changes
setInterval(() => { try { fetchAndRenderStatus(); } catch (e) {} }, 60 * 1000);

async function fetchAndRenderUptime(){
  try {
    const data = await fetchJSON('/api/uptime');
    const canvas = document.getElementById('uptime-canvas');
    if (!canvas) return;
    if (!Array.isArray(data) || data.length === 0) {
      const ctx = canvas.getContext('2d'); ctx.clearRect(0,0,canvas.width,canvas.height); return;
    }
    // limit to last 24 hours (by timestamp) — prefer entries within last 24h
    const DAY_MS = 24 * 60 * 60 * 1000;
    const recent = data.filter(d => d && d.ts && d.ts >= (Date.now() - DAY_MS));
    const use = (recent && recent.length) ? recent : data.slice(-24);
    // prepare labels (short time) and values
    const labels = use.map(d => new Date(d.ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }));
    const values = use.map(d => d.ok ? 1 : 0);
    const bgColors = use.map(d => d.ok ? 'rgba(126,243,179,0.95)' : 'rgba(255,134,179,0.95)');
    // destroy existing chart if present
    if (window.uptimeChart) { window.uptimeChart.destroy(); window.uptimeChart = null; }
    const ctx = canvas.getContext('2d');
    window.uptimeChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ data: values, backgroundColor: bgColors, borderRadius: 3 }] },
      options: {
        maintainAspectRatio: false,
        layout: { padding: { top: 2, bottom: 0, left: 0, right: 0 } },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: items => { return items && items[0] && items[0].label ? items[0].label : '' },
              label: ctx => ctx.raw === 1 ? 'OK' : 'FAIL'
            }
          }
        },
        scales: {
          x: { ticks: { display: false }, grid: { display: false } },
          y: { display: false, beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }
        },
        interaction: { mode: 'index', intersect: false }
      }
    });
  } catch (e) { console.error('uptime', e); }
}


async function fetchAndRenderCveStats(){
  try {
    const data = await fetchJSON('/api/cve-stats');
    const canvas = document.getElementById('cve-canvas');
    if (!canvas) return;
    if (!Array.isArray(data) || data.length === 0) { const ctx = canvas.getContext('2d'); ctx.clearRect(0,0,canvas.width,canvas.height); return; }
    // prepare labels (short date) and counts
    const labels = data.map(d => (new Date(d.date)).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }));
    const counts = data.map(d => d.count || 0);
    // destroy existing chart
    if (window.cveChart) { window.cveChart.destroy(); window.cveChart = null; }
    const ctx = document.getElementById('cve-canvas').getContext('2d');

    // compute color per bar based on value percentile in range
    const min = Math.min(...counts);
    const max = Math.max(...counts);
    function pickColor(val){
      if (max === min) return '#7b2cff';
      const pct = ((val - min) / (max - min)) * 100;
      if (pct <= 25) return '#7b2cff';
      if (pct <= 50) return '#9b63ff';
      if (pct <= 75) return '#d77bff';
      return '#ff6fb1';
    }
    const colors = counts.map(v => pickColor(v));

    const isLight = document.documentElement.classList.contains('light-theme');
    const tickColor = isLight ? 'rgba(40,20,60,0.6)' : 'rgba(255,255,255,0.6)';
    const gridColor = isLight ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';

    window.cveChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ data: counts, backgroundColor: colors, borderRadius:4 }] },
      options: {
        maintainAspectRatio: false,
        layout: { padding: { top: 2, bottom: 0, left: 0, right: 0 } },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { title: items => { return items && items[0] && items[0].label ? items[0].label : '' }, label: ctx => `${ctx.parsed.y}` } }
        },
        scales: {
          x: { ticks: { display: false }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: tickColor }, grid: { color: gridColor } }
        },
        interaction: { mode: 'nearest', intersect: true },
      }
    });
  } catch (e) { console.error('cve-stats', e); }
}

// --- Visitor IP + country flag ---
async function fetchVisitorIp(retries) {
  retries = retries || 0;
  try {
    const res = await fetchJSON('/api/myip');
    const addrEl = document.getElementById('ip-addr');
    const flagEl = document.getElementById('ip-flag');
    if (addrEl && res.ip) addrEl.textContent = res.ip;
    if (flagEl && res.countryCode) {
      const cc = res.countryCode.toLowerCase();
      flagEl.innerHTML = `<img src="https://flagcdn.com/20x15/${cc}.png" width="20" height="15" alt="${res.countryCode}" style="vertical-align:middle;border-radius:2px">`;
    }
  } catch (e) {
    console.error('visitor ip', e);
    if (retries < 3) setTimeout(() => fetchVisitorIp(retries + 1), 3000);
  }
}

// --- Uptime stats (30-day percentage) ---
async function fetchUptimeStats() {
  try {
    const res = await fetchJSON('/api/uptime-stats');
    const el = document.getElementById('uptime-pct');
    if (!el) return;
    const pct = res.percentage;
    let text, color;
    if (pct >= 100) { text = '100%'; color = '#2ecc71'; }
    else if (pct >= 99) { text = pct.toFixed(1) + '%'; color = '#2ecc71'; }
    else if (pct >= 95) { text = pct.toFixed(1) + '%'; color = '#f9a825'; }
    else if (pct >= 90) { text = pct.toFixed(1) + '%'; color = '#e67e22'; }
    else { text = pct.toFixed(1) + '%'; color = '#e74c3c'; }
    el.innerHTML = `<span style="color:${color};font-weight:600">${text}</span> last 30 days`;
  } catch (e) { console.error('uptime-stats', e); }
}

// --- Public settings (logo, site name, links) ---
async function fetchPublicSettings() {
  try {
    const res = await fetchJSON('/api/settings/public');
    if (res.siteName) {
      const el = document.querySelector('.site-title');
      if (el) el.textContent = res.siteName;
      document.title = res.siteName;
      // Update footer GitHub link text
      const ghSpan = document.querySelector('.footer-github span');
      if (ghSpan) ghSpan.textContent = res.siteName + ' on GitHub';
    }
    if (res.logo) {
      const logoEl = document.querySelector('.logo');
      if (logoEl) {
        logoEl.innerHTML = `<img src="${escapeHtml(res.logo)}" alt="Logo" style="width:100%;height:100%;object-fit:contain;border-radius:8px">`;
      }
    }
    // Populate links dropdown
    if (res.links) {
      const label = document.getElementById('links-dropdown-label');
      if (label && res.links.name) label.textContent = res.links.name;
      const menu = document.getElementById('links-dropdown-menu');
      if (menu && Array.isArray(res.links.items)) {
        menu.innerHTML = res.links.items.map(l =>
          `<a href="${escapeHtml(l.url)}" target="_blank" rel="noopener"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg> ${escapeHtml(l.title)}</a>`
        ).join('');
      }
    }
  } catch (e) { console.error('settings', e); }
}

// --- Vendor donut chart on dashboard ---
async function fetchAndRenderVendorDonut() {
  try {
    const vendors = await fetchJSON('/api/top-vendors');
    const canvas = document.getElementById('vendor-donut-canvas');
    if (!canvas || !Array.isArray(vendors) || vendors.length === 0) return;
    const labels = vendors.map(v => v.vendor || 'Unknown');
    const counts = vendors.map(v => v.cnt || 0);
    const colors = ['#8400ff','#9b63ff','#b47aff','#d77bff','#ff6fb1','#ff4da6','#e74c3c','#e67e22','#f1c40f'];
    const isLight = document.documentElement.classList.contains('light-theme');
    const labelColor = isLight ? '#1a0a2e' : '#efe8ff';
    new Chart(canvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data: counts, backgroundColor: colors.slice(0, labels.length), borderWidth: 0 }]
      },
      options: {
        maintainAspectRatio: false,
        cutout: '55%',
        plugins: {
          legend: { display: true, position: 'right', labels: { color: labelColor, boxWidth: 10, font: { size: 10 }, padding: 6 } },
          tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed} CVEs` } }
        }
      }
    });
  } catch (e) { console.error('vendor-donut', e); }
}

// --- Light/Dark theme toggle ---
function setupThemeToggle() {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  // Inline SVGs so toggle works even if feather-icons CDN is unavailable
  const sunSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  const moonSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  const saved = localStorage.getItem('theme');
  if (saved === 'light') document.documentElement.classList.add('light-theme');
  updateThemeIcon();
  btn.addEventListener('click', () => {
    document.documentElement.classList.toggle('light-theme');
    const isLight = document.documentElement.classList.contains('light-theme');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    updateThemeIcon();
    updateChartColors();
  });
  function updateThemeIcon() {
    const isLight = document.documentElement.classList.contains('light-theme');
    btn.innerHTML = isLight ? moonSvg : sunSvg;
  }
}

function updateChartColors() {
  const isLight = document.documentElement.classList.contains('light-theme');
  const tickColor = isLight ? 'rgba(40,20,60,0.6)' : 'rgba(255,255,255,0.6)';
  const gridColor = isLight ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';
  const labelColor = isLight ? '#1a0a2e' : '#efe8ff';
  if (window.cveChart) {
    window.cveChart.options.scales.y.ticks.color = tickColor;
    window.cveChart.options.scales.y.grid.color = gridColor;
    window.cveChart.update();
  }
  // Update all Chart.js instances (vendor donut legend etc.)
  const allCharts = Object.values(Chart.instances || {});
  allCharts.forEach(c => {
    if (c.config && c.config.type === 'doughnut' && c.options.plugins.legend) {
      c.options.plugins.legend.labels.color = labelColor;
      c.update();
    }
  });
}
