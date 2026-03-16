// risk.js — Top-priority CVE's page
(function(){
'use strict';

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('Fetch error ' + r.status);
  return r.json();
}

// --- i18n ---
let currentLang = localStorage.getItem('dashLang') || 'en';
const i18n = {
  en: {
    riskHeading: "Top-priority CVE's",
    riskVendor: 'Filter by vendor:', riskPeriod: 'Period:',
    riskLoadMore: 'Load more',
    riskFormulaTitle: 'How risk score is calculated',
    riskFormulaDesc: 'A CVE that is actively exploited (KEV), has a public exploit, no available patch, and was published recently will score highest, regardless of its CVSS severity rating alone.',
    riskScaleTitle: 'Score scale',
    riskVendorChart: 'Critical Risk CVEs per Vendor (120+)',
    risk30: '30 days', risk60: '60 days', risk180: '180 days',
    showMore: 'show more', showLess: 'show less',
    descPending: 'Recently published \u2014 description pending'
  },
  sv: {
    riskHeading: 'Prioriterade CVE:er',
    riskVendor: 'Filtrera p\u00e5 leverant\u00f6r:', riskPeriod: 'Period:',
    riskLoadMore: 'Ladda fler',
    riskFormulaTitle: 'Hur riskpo\u00e4ng ber\u00e4knas',
    riskFormulaDesc: 'En CVE som aktivt utnyttjas (KEV), har offentlig exploit, saknar patch och \u00e4r nyligen publicerad f\u00e5r h\u00f6gst po\u00e4ng, oavsett CVSS-niv\u00e5.',
    riskScaleTitle: 'Po\u00e4ngskala',
    riskVendorChart: 'Kritiska CVE:er per leverant\u00f6r (120+)',
    risk30: '30 dagar', risk60: '60 dagar', risk180: '180 dagar',
    showMore: 'visa mer', showLess: 'visa mindre',
    descPending: 'Nyligen publicerad \u2014 beskrivning inv\u00e4ntas'
  }
};
function t(key) { return (i18n[currentLang] || i18n.en)[key] || (i18n.en)[key] || key; }

function escapeHtml(s){
  if(!s) return '';
  return String(s).replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; });
}

function fmtDate(dt) {
  if (!dt) return 'N/A';
  const d = (dt instanceof Date) ? dt : new Date(dt);
  if (isNaN(d.getTime())) return 'N/A';
  return d.toISOString().slice(0, 10);
}

// --- Risk score helpers ---
function riskScoreColor(score) {
  if (score >= 120) return '#ff2244';
  if (score >= 100) return '#ff6622';
  if (score >= 80) return '#ffaa00';
  return '#44bb44';
}

// --- Render CVE items (matches Latest CVE's format) ---
function renderRiskItems(items) {
  if (!items || !items.length) return '<div style="color:var(--muted);padding:12px">No high-risk CVEs found for this period.</div>';
  return items.map(function(it) {
    var id = it.id || '';
    var score = it._riskScore || 0;
    var color = riskScoreColor(score);
    var cvss = it.cvss != null ? parseFloat(it.cvss).toFixed(1) : 'N/A';
    var cvssStyle = '';
    var cvssNum = parseFloat(cvss);
    if (!isNaN(cvssNum)) {
      if (cvssNum >= 9) cvssStyle = 'color:#e74c3c;font-weight:700';
      else if (cvssNum >= 8) cvssStyle = 'color:#e67e22;font-weight:700';
      else if (cvssNum >= 6) cvssStyle = 'color:#f1c40f;font-weight:600';
    }
    var url = id.startsWith('CVE-') ? 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + encodeURIComponent(id) : '#';
    var title = escapeHtml(it.title || '');
    var published = it.published ? fmtDate(it.published) : 'N/A';
    var discovered = it._discovered ? fmtDate(it._discovered) : '';
    var discoveredLine = discovered ? 'Discovered: ' + discovered + ' \u2022 ' : '';

    // Build head HTML: ID: Title (same as Latest CVE's)
    var headHtml = '';
    if (id) {
      headHtml = '<a href="' + url + '" target="_blank" rel="noopener">' + escapeHtml(id) + (title && title !== id ? ': ' + title : '') + '</a>';
    } else {
      headHtml = '<span>' + (title || '(no id)') + '</span>';
    }

    // Badges
    var kevBadge = it._kev ? '<span class="badge badge-kev">KEV</span>' : '';
    var exploitBadge = it._exploit ? '<span class="badge badge-exploit">Exploit</span>' : '<span class="badge badge-no">No exploit</span>';
    var patchBadge = it._patch ? '<span class="badge badge-patch">Patch</span>' : '<span class="badge badge-nopatch">No patch</span>';
    var riskBadge = '<span class="badge" style="background:' + color + ';color:#fff;font-weight:700">Risk rating: ' + score + '</span>';

    // Summary with truncation (300 chars like Latest CVE's)
    var rawSummary = it.summary || it.description || '';
    var summary = escapeHtml(rawSummary);
    var truncated = false;
    var fullSummary = summary;
    if (summary.length > 300) {
      summary = summary.slice(0, 300).replace(/\s+\S*$/, '') + '\u2026';
      truncated = true;
    }
    if (!summary) summary = t('descPending');

    return '<div class="card">' +
      '<div>' + headHtml + '</div>' +
      '<div class="meta"><span style="' + cvssStyle + '">CVSS: ' + cvss + '</span> \u2022 ' + discoveredLine + 'Published: ' + published + '</div>' +
      '<div class="cve-badges">' + exploitBadge + ' ' + patchBadge + ' ' + kevBadge + ' ' + riskBadge + '</div>' +
      '<div class="desc">' + (truncated ? '<span class="desc-short">' + summary + '</span><span class="desc-full" hidden>' + fullSummary + '</span> <a href="#" class="show-more">' + t('showMore') + '</a>' : summary) + '</div>' +
    '</div>';
  }).join('');
}

// --- State ---
var PAGE_SIZE = 15;
var offset = 0;
var maxAge = 60;
var selectedVendors = [];
var allVendors = [];

// Load saved default vendor filter from localStorage
(function loadDefaultVendors() {
  try {
    var saved = localStorage.getItem('riskDefaultVendors');
    if (saved) selectedVendors = JSON.parse(saved);
  } catch (e) {}
})();
var allItems = [];
var vendorChart = null;

// --- Load CVEs ---
async function loadRiskCves(resetOffset) {
  if (resetOffset) { offset = 0; allItems = []; }
  var btn = document.getElementById('risk-load-more');
  var container = document.getElementById('risk-items');
  if (btn) { btn.disabled = true; btn.textContent = 'Loading...'; }
  try {
    var url = '/api/risk-priority?count=' + PAGE_SIZE + '&offset=' + offset + '&maxAge=' + maxAge;
    if (selectedVendors.length === 1) url += '&vendor=' + encodeURIComponent(selectedVendors[0]);
    else if (selectedVendors.length > 1) selectedVendors.forEach(function(v){ url += '&vendor=' + encodeURIComponent(v); });
    var data = await fetchJSON(url);
    if (Array.isArray(data)) allItems = allItems.concat(data);
    offset += (Array.isArray(data) ? data.length : 0);
    container.innerHTML = renderRiskItems(allItems);
    if (btn) {
      btn.disabled = false;
      btn.textContent = t('riskLoadMore');
      btn.style.display = (Array.isArray(data) && data.length === PAGE_SIZE) ? '' : 'none';
    }
  } catch (e) {
    container.innerHTML = '<div style="color:var(--muted);padding:12px">Failed to load risk data.</div>';
    if (btn) { btn.disabled = false; btn.textContent = t('riskLoadMore'); }
  }
}

// --- Load vendor chart (purple/pink palette matching other charts) ---
var CHART_COLORS = ['#8400ff','#9b63ff','#b47aff','#d77bff','#ff6fb1','#ff4da6','#e74c3c','#e67e22','#f1c40f','#2ecc71'];

async function loadVendorChart() {
  try {
    var url = '/api/risk-vendors?maxAge=' + maxAge;
    if (selectedVendors.length) selectedVendors.forEach(function(v){ url += '&vendor=' + encodeURIComponent(v); });
    var data = await fetchJSON(url);
    var canvas = document.getElementById('risk-vendor-canvas');
    if (!canvas || !Array.isArray(data) || data.length === 0) return;
    var labels = data.map(function(v){ return v.vendor || 'Unknown'; });
    var criticals = data.map(function(v){ return v.critical_count || 0; });
    var totals = data.map(function(v){ return v.total || 0; });
    var kevCounts = data.map(function(v){ return v.kev_count || 0; });
    var barColors = labels.map(function(_, i){ return CHART_COLORS[i % CHART_COLORS.length]; });
    var isLight = document.documentElement.classList.contains('light-theme');
    var tickColor = isLight ? 'rgba(40,20,60,0.6)' : 'rgba(255,255,255,0.6)';
    var gridColor = isLight ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';

    if (vendorChart) vendorChart.destroy();
    vendorChart = new Chart(canvas.getContext('2d'), {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Critical CVEs (120+)',
          data: criticals,
          backgroundColor: barColors,
          borderRadius: 4,
          barPercentage: 0.7
        }]
      },
      options: {
        indexAxis: 'y',
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function(ctx) {
                var i = ctx.dataIndex;
                return ' Critical: ' + criticals[i] + ' | Total CVEs: ' + totals[i] + ' | KEV: ' + kevCounts[i];
              }
            }
          }
        },
        scales: {
          x: { beginAtZero: true, ticks: { color: tickColor, font: { size: 10 }, stepSize: 1 }, grid: { color: gridColor } },
          y: { ticks: { color: tickColor, font: { size: 11 } }, grid: { display: false } }
        }
      }
    });
  } catch (e) { console.error('risk-vendor-chart', e); }
}

// --- Vendor filter (search-input style like report page) ---
async function setupVendorFilter() {
  var input = document.getElementById('risk-vendor-search');
  var listEl = document.getElementById('risk-vendor-list');
  var tagEl = document.getElementById('risk-vendor-tag');
  if (!input || !listEl) return;

  // Always load all vendors regardless of day filter
  try { allVendors = await fetchJSON('/api/vendor-list?days=365'); } catch(e) { allVendors = []; }

  function renderTags() {
    if (!tagEl) return;
    if (selectedVendors.length === 0) { tagEl.innerHTML = ''; return; }
    tagEl.innerHTML = selectedVendors.map(function(v) {
      return '<span class="vendor-filter-tag" data-vendor="' + escapeHtml(v) + '">' + escapeHtml(v) + ' \u2715</span>';
    }).join(' ');
    tagEl.querySelectorAll('.vendor-filter-tag').forEach(function(tag) {
      tag.onclick = function() {
        selectedVendors = selectedVendors.filter(function(sv){ return sv !== tag.dataset.vendor; });
        renderTags();
        renderList(input.value);
        loadRiskCves(true);
        loadVendorChart();
      };
    });
  }

  function renderList(filter) {
    var filtered = filter ? allVendors.filter(function(v){ return v.vendor.toLowerCase().includes(filter.toLowerCase()); }) : allVendors;
    listEl.innerHTML = filtered.slice(0, 30).map(function(v) {
      return '<div class="vf-item' + (selectedVendors.includes(v.vendor) ? ' selected' : '') + '" data-vendor="' + escapeHtml(v.vendor) + '">' + escapeHtml(v.vendor) + ' <span style="color:var(--muted);font-size:0.8em">(' + v.cnt + ')</span></div>';
    }).join('');
  }

  input.addEventListener('focus', function() { renderList(input.value); listEl.classList.add('open'); });
  input.addEventListener('input', function() { renderList(input.value); listEl.classList.add('open'); });
  document.addEventListener('click', function(e) {
    if (!e.target.closest('.vendor-filter-wrap')) listEl.classList.remove('open');
  });
  listEl.addEventListener('click', function(e) {
    var item = e.target.closest('.vf-item');
    if (!item) return;
    var v = item.dataset.vendor;
    if (selectedVendors.includes(v)) {
      selectedVendors = selectedVendors.filter(function(sv){ return sv !== v; });
    } else {
      selectedVendors.push(v);
    }
    input.value = '';
    renderTags();
    renderList('');
    loadRiskCves(true);
    loadVendorChart();
  });

  // Save / Clear default vendor filter button
  var defaultBtn = document.getElementById('risk-vendor-save-default');
  if (defaultBtn) {
    function updateDefaultBtn() {
      var savedRaw = localStorage.getItem('riskDefaultVendors');
      var savedVendors = savedRaw ? JSON.parse(savedRaw) : [];
      var currentSorted = selectedVendors.slice().sort();
      var savedSorted = savedVendors.slice().sort();
      var matchesSaved = savedVendors.length > 0 && currentSorted.length === savedSorted.length && currentSorted.every(function(v, i){ return v === savedSorted[i]; });
      if (matchesSaved) {
        defaultBtn.textContent = 'Clear Default';
        defaultBtn.title = 'Remove saved default vendor filter';
        defaultBtn.style.display = 'inline-block';
        defaultBtn.onclick = function() {
          localStorage.removeItem('riskDefaultVendors');
          selectedVendors = [];
          renderTags();
          loadRiskCves(true);
          loadVendorChart();
        };
      } else if (selectedVendors.length > 0) {
        defaultBtn.textContent = 'Set as Default';
        defaultBtn.title = 'Save current vendor filter as default';
        defaultBtn.style.display = 'inline-block';
        defaultBtn.onclick = function() {
          localStorage.setItem('riskDefaultVendors', JSON.stringify(selectedVendors));
          updateDefaultBtn();
        };
      } else if (savedVendors.length > 0) {
        defaultBtn.textContent = 'Clear Default';
        defaultBtn.title = 'Remove saved default vendor filter';
        defaultBtn.style.display = 'inline-block';
        defaultBtn.onclick = function() {
          localStorage.removeItem('riskDefaultVendors');
          selectedVendors = [];
          renderTags();
          loadRiskCves(true);
          loadVendorChart();
        };
      } else {
        defaultBtn.style.display = 'none';
      }
    }
    // Patch renderTags to also update the default button
    var origRenderTags = renderTags;
    renderTags = function() { origRenderTags(); updateDefaultBtn(); };
    updateDefaultBtn();
  }

  // Render initial tags (from saved defaults)
  renderTags();
  renderList('');
}

// --- Age filter ---
function setupAgeFilter() {
  var btn = document.getElementById('risk-age-btn');
  var menu = document.getElementById('risk-age-menu');
  if (!btn || !menu) return;
  function closeMenu() { menu.setAttribute('aria-hidden', 'true'); btn.setAttribute('aria-expanded', 'false'); }
  function openMenu() { menu.setAttribute('aria-hidden', 'false'); btn.setAttribute('aria-expanded', 'true'); }
  btn.addEventListener('click', function(e) { e.stopPropagation(); var open = menu.getAttribute('aria-hidden') === 'false'; if (open) closeMenu(); else openMenu(); });
  menu.querySelectorAll('.cvss-option').forEach(function(li) {
    li.addEventListener('click', function() {
      var v = parseInt(li.getAttribute('data-value'), 10);
      maxAge = v;
      var textEl = document.getElementById('risk-age-text');
      if (textEl) textEl.textContent = li.textContent;
      menu.querySelectorAll('.cvss-option').forEach(function(o){ o.removeAttribute('aria-selected'); });
      li.setAttribute('aria-selected', 'true');
      loadRiskCves(true);
      loadVendorChart();
      closeMenu();
    });
  });
  document.addEventListener('click', function(){ closeMenu(); });
}

// --- Theme toggle ---
function setupThemeToggle() {
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;
  var sunSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  var moonSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  function updateIcon(){ btn.innerHTML = document.documentElement.classList.contains('light-theme') ? moonSvg : sunSvg; }
  updateIcon();
  btn.addEventListener('click', function(){
    document.documentElement.classList.toggle('light-theme');
    localStorage.setItem('theme', document.documentElement.classList.contains('light-theme') ? 'light' : 'dark');
    updateIcon();
    // reload chart with new colors
    loadVendorChart();
  });
}

// --- Language toggle ---
function setupLangToggle() {
  var btn = document.getElementById('lang-toggle-btn');
  if (!btn) return;
  btn.addEventListener('click', function(){
    currentLang = currentLang === 'en' ? 'sv' : 'en';
    localStorage.setItem('dashLang', currentLang);
    applyTranslations();
    // re-render items with updated language
    document.getElementById('risk-items').innerHTML = renderRiskItems(allItems);
  });
}

function applyTranslations() {
  var set = function(id, key){ var el = document.getElementById(id); if (el) el.textContent = t(key); };
  set('risk-heading-text', 'riskHeading');
  set('risk-vendor-label', 'riskVendor');
  set('risk-age-label', 'riskPeriod');
  set('risk-formula-title', 'riskFormulaTitle');
  set('risk-formula-desc', 'riskFormulaDesc');
  set('risk-scale-title', 'riskScaleTitle');
  set('risk-vendor-chart-title', 'riskVendorChart');
  var riskMore = document.getElementById('risk-load-more');
  if (riskMore && !riskMore.disabled) riskMore.textContent = t('riskLoadMore');
  document.querySelectorAll('#risk-age-menu .cvss-option').forEach(function(li){
    var v = li.getAttribute('data-value');
    if (v === '30') li.textContent = t('risk30');
    else if (v === '60') li.textContent = t('risk60');
    else if (v === '180') li.textContent = t('risk180');
  });
  var riskAgeText = document.getElementById('risk-age-text');
  if (riskAgeText) {
    if (maxAge === 30) riskAgeText.textContent = t('risk30');
    else if (maxAge === 180) riskAgeText.textContent = t('risk180');
    else riskAgeText.textContent = t('risk60');
  }
  var langLabel = document.getElementById('lang-label');
  if (langLabel) langLabel.textContent = currentLang.toUpperCase();
}

// --- Show more / show less handler ---
document.addEventListener('click', function(e) {
  if (!e.target.classList.contains('show-more')) return;
  e.preventDefault();
  var desc = e.target.closest('.desc');
  if (!desc) return;
  var short = desc.querySelector('.desc-short');
  var full = desc.querySelector('.desc-full');
  if (!short || !full) return;
  var expanding = full.hidden;
  short.hidden = expanding;
  full.hidden = !expanding;
  e.target.textContent = expanding ? t('showLess') : t('showMore');
});

// --- Init ---
function init() {
  loadRiskCves(true);
  loadVendorChart();
  setupVendorFilter();
  setupAgeFilter();
  setupThemeToggle();
  setupLangToggle();
  applyTranslations();

  var loadMoreBtn = document.getElementById('risk-load-more');
  if (loadMoreBtn) {
    loadMoreBtn.addEventListener('click', function(){ loadRiskCves(false); });
  }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();
