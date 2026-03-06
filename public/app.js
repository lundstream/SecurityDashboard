async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('Fetch error ' + r.status);
  return r.json();
}

// client-side cache of loaded CVEs (pages appended here)
window._cves = window._cves || [];

function getCvssNumeric(it){
  if(!it) return NaN;
  // try common locations for numeric CVSS scores
  if(typeof it.cvss === 'number') return it.cvss;
  if(it.cvss && !isNaN(Number(it.cvss))) return Number(it.cvss);
  if(it.cvss3 && it.cvss3.baseScore) return Number(it.cvss3.baseScore);
  // NVD v2 style inside containers.adp[*].metrics[*].cvssV3_1.baseScore
  try{
    const cont = it.containers || it.containers || null;
    if(cont && cont.adp && cont.adp.length){
      for(const a of cont.adp){
        if(a.metrics && a.metrics.length){
          for(const m of a.metrics){
            if(m.cvssV3_1 && m.cvssV3_1.baseScore) return Number(m.cvssV3_1.baseScore);
            if(m.cvssV3 && m.cvssV3.baseScore) return Number(m.cvssV3.baseScore);
          }
        }
      }
    }
  }catch(e){/* ignore */}
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
  const filtered = (window._cves || []).filter(it => {
    if(isNaN(threshold)) return true;
    const score = getCvssNumeric(it);
    return !isNaN(score) && score >= threshold;
  });
  // prefer CVE items that mention resolution/patch/fix; ensure at least 10 shown
  const display = selectResolutionItems(filtered, 10);
  container.innerHTML = renderCveItems(display.length ? display : filtered.slice(0, Math.max(10, filtered.length)));
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

// --- Rendering helpers ---
function renderCveItems(items) {
  if (!items || !items.length) return '';
  function extractId(it) {
    if (!it) return '';
    // prefer an explicit cveMetadata.cveId
    if (it.cveMetadata && it.cveMetadata.cveId) return it.cveMetadata.cveId;
    // inspect all text for a CVE id first (prefer CVE over GHSA)
    try {
      const s = JSON.stringify(it || '');
      const mCVE = s.match(/CVE-\d{4}-\d{4,7}/i);
      if (mCVE) return mCVE[0].toUpperCase();
    } catch (e) { /* ignore JSON errors */ }
    // if the explicit id field contains a CVE or GHSA, use it
    if (it.id) {
      const idStr = String(it.id);
      const mCVE2 = idStr.match(/CVE-\d{4}-\d{4,7}/i);
      if (mCVE2) return mCVE2[0].toUpperCase();
      const mGHSA2 = idStr.match(/GHSA-[\w-]+/i);
      if (mGHSA2) return mGHSA2[0].toUpperCase();
      return idStr;
    }
    if (it.CVE) return it.CVE;
    if (it.cve) return it.cve;
    // last-resort: look for GHSA in the whole object
    try {
      const s2 = JSON.stringify(it || '');
      const mGHSA = s2.match(/GHSA-[\w-]+/i);
      if (mGHSA) return mGHSA[0].toUpperCase();
    } catch (e) { /* ignore */ }
    return '';
  }
  function extractTitle(it) {
    if (!it) return '';
    if (it.title) return it.title;
    if (it.summary && it.summary.length && it.summary.length < 140) return it.summary;
    if (it.cveMetadata && it.cveMetadata.title) return it.cveMetadata.title;
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
    if (it.summary) return it.summary;
    if (it.description) return it.description;
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
    const p = it.Published || it.published || (it.cveMetadata && it.cveMetadata.datePublished) || (it.cveMetadata && it.cveMetadata.dateUpdated) || null;
    if (!p) return 'N/A';
    const d = new Date(p);
    if (!isNaN(d.getTime())) return d.toLocaleString();
    return String(p);
  }
  function extractCvss(it) {
    if (!it) return 'N/A';
    if (it.cvss) return it.cvss;
    if (it.cvss3 && it.cvss3.baseScore) return it.cvss3.baseScore;
    if (it.containers && it.containers.adp) {
      const adp = it.containers.adp[0];
      if (adp && adp.metrics && adp.metrics.length && adp.metrics[0].cvssV3_1) return adp.metrics[0].cvssV3_1.baseScore;
    }
    if (it.document && it.document.aggregate_severity) return it.document.aggregate_severity.text || 'N/A';
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
    const published = extractPublished(it);
    let summary = (extractSummary(it) || '').replace(/\n/g, ' ').trim();
    // avoid duplicating title when summary begins with the same text
    if (title && summary) {
      const tnorm = title.replace(/\s+/g,' ').trim();
      if (summary.indexOf(tnorm) === 0) {
        summary = summary.slice(tnorm.length).trim();
      }
    }
    if (!summary) summary = '(no summary)';
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
    return `
      <div class="card">
        <div>${headHtml}${zeroHtml}</div>
        <div class="meta">CVSS: ${cvss} • Published: ${published}</div>
        <div class="desc">${escapeHtml(summary)}</div>
      </div>
    `;
  }).join('');
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
let newsPageSize = 20;
let newsOffset = 0;
let cvePageSize = 20;
let cveOffset = 0;

// helper to update button visibility
function updateButtonVisibility(container, btn) {
  if (!container || !btn) return;
  const available = btn.dataset.available === 'true';
  if (!available) { btn.style.display = 'none'; return; }
  // show when footer is visible (IntersectionObserver also drives this)
  if (container.scrollHeight - container.scrollTop - container.clientHeight < 60) btn.style.display = 'inline-block';
  else btn.style.display = 'none';
}

// load a page of news and append
async function loadNews(offsetArg) {
  const offset = (typeof offsetArg === 'number') ? offsetArg : newsOffset;
  const btn = document.getElementById('news-load-more');
  const container = document.getElementById('news-items');
  if (btn) { btn.disabled = true; btn.textContent = 'Loading...'; }
  try {
    const news = await fetchJSON(`/api/rss?count=${newsPageSize}&offset=${offset}`);
    if (offset === 0) {
      // prefer resolution-related news; ensure at least 10 items shown
      const pref = selectResolutionItems(news, 10);
      if (pref && pref.length) {
        container.innerHTML = renderNewsItems(pref);
        newsOffset = pref.length;
      } else {
        container.innerHTML = renderNewsItems(news);
        newsOffset = news.length;
      }
    } else {
      container.innerHTML += renderNewsItems(news);
      newsOffset = offset + news.length;
    }
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Load more';
      btn.dataset.available = (news.length === newsPageSize) ? 'true' : 'false';
      updateButtonVisibility(document.getElementById('news-list'), btn);
    }
  } catch (e) {
    container.innerHTML = 'Error: ' + e.message;
    if (btn) { btn.disabled = false; btn.textContent = 'Load more'; btn.dataset.available = 'false'; }
  }
}

// load a page of CVEs and append
async function loadCves(offsetArg) {
  const offset = (typeof offsetArg === 'number') ? offsetArg : cveOffset;
  const btn = document.getElementById('cve-load-more');
  const container = document.getElementById('cve-items');
  if (btn) { btn.disabled = true; btn.textContent = 'Loading...'; }
  try {
    const cves = await fetchJSON(`/api/cves?count=${cvePageSize}&offset=${offset}`);
    // maintain client-side cache
    if (offset === 0) window._cves = [];
    if (Array.isArray(cves)) window._cves = window._cves.concat(cves);
    cveOffset = offset + (Array.isArray(cves) ? cves.length : 0);
    // render filtered view
    applyCvssFilterAndRender();
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Load more';
      btn.dataset.available = (Array.isArray(cves) && cves.length === cvePageSize) ? 'true' : 'false';
      updateButtonVisibility(document.getElementById('cve-list'), btn);
    }
  } catch (e) {
    container.innerHTML = 'Error: ' + e.message;
    if (btn) { btn.disabled = false; btn.textContent = 'Load more'; btn.dataset.available = 'false'; }
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

function init() {
  setupFooterObserver('news-list', 'news-load-more');
  setupFooterObserver('cve-list', 'cve-load-more');
  // initial loads
  loadCves(0);
  loadNews(0);
  // fetch header status and charts
  fetchAndRenderStatus();
  fetchAndRenderUptime();
  fetchAndRenderCveStats();
  setupCveSearch();
  // setup CVSS filter listener
  const sel = document.getElementById('cvss-filter');
  if(sel){ sel.addEventListener('change', () => { window._cvssFilterValue = sel.value; applyCvssFilterAndRender(); }); }
  // init custom dropdown if present
  const dd = document.getElementById('cvss-dropdown');
  if(dd){
    const btn = document.getElementById('cvss-dropdown-btn');
    const menu = document.getElementById('cvss-dropdown-menu');
    window._cvssFilterValue = 'all';
    function closeMenu(){ if(menu){ menu.setAttribute('aria-hidden','true'); btn.setAttribute('aria-expanded','false'); } }
    function openMenu(){ if(menu){ menu.setAttribute('aria-hidden','false'); btn.setAttribute('aria-expanded','true'); } }
    btn.addEventListener('click', (e)=>{ e.stopPropagation(); const open = menu.getAttribute('aria-hidden') === 'false'; if(open) closeMenu(); else openMenu(); });
    // option clicks
    menu.querySelectorAll('.cvss-option').forEach(li=>{
      li.addEventListener('click', (ev)=>{
        const v = li.getAttribute('data-value'); window._cvssFilterValue = v;
        // update label on button
        btn.firstChild.nodeValue = (li.textContent || li.innerText) + ' ';
        // mark selected
        menu.querySelectorAll('.cvss-option').forEach(o=>o.removeAttribute('aria-selected'));
        li.setAttribute('aria-selected','true');
        applyCvssFilterAndRender();
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
  } catch (e) { console.error('status', e); }
}

// --- CVE search ---
function renderSingleCve(it) {
  if (!it) return '<div>No result</div>';
  return renderCveItems([it]);
}

function setupCveSearch(){
  const btn = document.getElementById('cve-search-btn');
  const input = document.getElementById('cve-search');
  const out = document.getElementById('cve-search-results');
  if (!btn || !input || !out) return;
  btn.addEventListener('click', async () => {
    const q = (input.value || '').trim();
    if (!q) { out.innerHTML = '<div class="meta">Enter a CVE id</div>'; return; }
    // open cve.org in a new tab/window for the searched CVE
    const up = q.toUpperCase();
    const idMatch = up.match(/^CVE-\d{4}-\d{4,7}$/i);
    let url;
    if (idMatch) url = 'https://cve.org/' + up;
    else url = 'https://cve.org/search?q=' + encodeURIComponent(q);
    window.open(url, '_blank');
  });
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

    window.cveChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ data: counts, backgroundColor: colors, borderRadius:4 }] },
      options: {
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { title: items => { return items && items[0] && items[0].label ? items[0].label : '' }, label: ctx => `${ctx.parsed.y}` } }
        },
        scales: {
          x: { ticks: { display: false }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: 'rgba(255,255,255,0.85)' }, grid: { color: 'rgba(255,255,255,0.04)' } }
        },
        interaction: { mode: 'nearest', intersect: true },
      }
    });
  } catch (e) { console.error('cve-stats', e); }
}
