// report.js — Vulnerability Report page logic

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('Fetch error ' + r.status);
  return r.json();
}

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function fmtDate(dt) {
  if (!dt) return 'N/A';
  const d = new Date(dt);
  if (isNaN(d.getTime())) return 'N/A';
  return d.toISOString().slice(0, 10);
}

function renderCveCard(cve) {
  const id = escapeHtml(cve.id || '');
  const cvss = cve.cvss != null ? Number(cve.cvss).toFixed(1) : 'N/A';
  let cvssStyle = '';
  const n = parseFloat(cvss);
  if (!isNaN(n)) {
    if (n >= 9) cvssStyle = 'color:#e74c3c;font-weight:700';
    else if (n >= 8) cvssStyle = 'color:#e67e22;font-weight:700';
    else if (n >= 6) cvssStyle = 'color:#f1c40f;font-weight:600';
  }
  const vendor = cve.vendor ? escapeHtml(cve.vendor) : '';
  const published = fmtDate(cve.published);
  const discovered = cve.discovered ? fmtDate(cve.discovered) : '';
  const summary = escapeHtml(cve.summary || 'No description available');
  const truncated = summary.length > 250 ? summary.slice(0, 250).replace(/\s+\S*$/, '') + '\u2026' : summary;

  const kevBadge = cve.kev ? '<span class="badge badge-kev">KEV</span>' : '';
  const exploitBadge = cve.exploit ? '<span class="badge badge-exploit">Exploit</span>' : '<span class="badge badge-no">No exploit</span>';
  const patchBadge = cve.patch ? '<span class="badge badge-patch">Patch</span>' : '<span class="badge badge-nopatch">No patch</span>';

  const url = id.startsWith('CVE-') ? `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(id)}` : '#';
  const vendorHtml = vendor ? ` • Vendor: ${vendor}` : '';
  const discoveredHtml = discovered ? `Discovered: ${discovered} • ` : '';

  return `<div class="card">
    <div><a href="${url}" target="_blank" rel="noopener">${id}</a>${vendorHtml}</div>
    <div class="meta"><span style="${cvssStyle}">CVSS: ${cvss}</span> • ${discoveredHtml}Published: ${published}</div>
    <div class="cve-badges">${exploitBadge} ${patchBadge} ${kevBadge}</div>
    <div class="desc">${truncated}</div>
  </div>`;
}

const PAGE_SIZE = 10;
const cveData = {}; // keyed by containerId, stores full array

function renderCveList(containerId, cves, emptyMsg) {
  const el = document.getElementById(containerId);
  if (!el) return;
  cveData[containerId] = cves || [];
  if (!cves || cves.length === 0) {
    el.innerHTML = `<div style="color:var(--muted);padding:12px">${emptyMsg || 'No CVEs found.'}</div>`;
    const btn = document.getElementById(containerId.replace('-list', '-more'));
    if (btn) btn.style.display = 'none';
    return;
  }
  const show = cves.slice(0, PAGE_SIZE);
  el.innerHTML = show.map(renderCveCard).join('');
  const btn = document.getElementById(containerId.replace('-list', '-more'));
  if (btn) {
    btn.style.display = cves.length > PAGE_SIZE ? 'inline-block' : 'none';
    btn.dataset.shown = PAGE_SIZE;
    btn.onclick = () => loadMore(containerId, btn);
  }
}

function loadMore(containerId, btn) {
  const all = cveData[containerId];
  if (!all) return;
  let shown = parseInt(btn.dataset.shown) || PAGE_SIZE;
  const next = all.slice(shown, shown + PAGE_SIZE);
  const el = document.getElementById(containerId);
  if (el) el.insertAdjacentHTML('beforeend', next.map(renderCveCard).join(''));
  shown += next.length;
  btn.dataset.shown = shown;
  if (shown >= all.length) btn.style.display = 'none';
}

let vendorChartInstance = null;

function renderVendorChart(vendors) {
  const canvas = document.getElementById('vendor-chart');
  if (!canvas || !vendors || vendors.length === 0) return;
  if (vendorChartInstance) vendorChartInstance.destroy();

  const labels = vendors.map(v => v.vendor || 'Unknown');
  const totals = vendors.map(v => v.cnt || 0);

  const isLight = document.documentElement.classList.contains('light-theme');
  const tickColor = isLight ? '#1a0a2e' : '#efe8ff';
  const gridColor = isLight ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';

  vendorChartInstance = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'CVEs', data: totals, backgroundColor: '#8400ff', borderRadius: 4 }
      ]
    },
    options: {
      indexAxis: 'y',
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => {
              const i = items[0].dataIndex;
              return vendors[i].vendor || 'Unknown';
            },
            label: (ctx) => {
              const v = vendors[ctx.dataIndex];
              return 'Total CVEs: ' + (v.cnt || 0);
            },
            afterLabel: (ctx) => {
              const v = vendors[ctx.dataIndex];
              const lines = [];
              if (v.critical) lines.push('CVSS 9+: ' + v.critical);
              if (v.high) lines.push('CVSS 7\u20138.9: ' + v.high);
              if (v.other) lines.push('Other: ' + v.other);
              if (v.kev) lines.push('KEV: ' + v.kev);
              return lines;
            }
          }
        }
      },
      scales: {
        x: { beginAtZero: true, ticks: { color: tickColor }, grid: { color: gridColor } },
        y: { ticks: { color: tickColor, font: { size: 12 } }, grid: { display: false } }
      }
    }
  });
}

// Theme toggle (same inline SVG approach as main page)
function setupThemeToggle() {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  const sunSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  const moonSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  function updateIcon() {
    const isLight = document.documentElement.classList.contains('light-theme');
    btn.innerHTML = isLight ? moonSvg : sunSvg;
  }
  updateIcon();
  btn.addEventListener('click', () => {
    document.documentElement.classList.toggle('light-theme');
    const isLight = document.documentElement.classList.contains('light-theme');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    updateIcon();
    updateReportChartColors();
  });
}

function updateReportChartColors() {
  if (!vendorChartInstance) return;
  const isLight = document.documentElement.classList.contains('light-theme');
  const tickColor = isLight ? '#1a0a2e' : '#efe8ff';
  const gridColor = isLight ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';
  vendorChartInstance.options.scales.x.ticks.color = tickColor;
  vendorChartInstance.options.scales.x.grid.color = gridColor;
  vendorChartInstance.options.scales.y.ticks.color = tickColor;
  vendorChartInstance.update();
}

// Fetch public settings (logo, site name, footer)
async function fetchPublicSettings() {
  try {
    const res = await fetchJSON('/api/settings/public');
    if (res.siteName) {
      const el = document.querySelector('.site-title');
      if (el) el.textContent = res.siteName;
      document.title = res.siteName + ' — Vulnerability Report';
      const ghSpan = document.querySelector('.footer-github span');
      if (ghSpan) ghSpan.textContent = res.siteName + ' on GitHub';
    }
    if (res.logo) {
      const logoEl = document.querySelector('.logo');
      if (logoEl) logoEl.innerHTML = `<img src="${escapeHtml(res.logo)}" alt="Logo" style="width:100%;height:100%;object-fit:contain;border-radius:8px">`;
    }
    if (res.footerText) {
      const copy = document.querySelector('.copyright');
      if (copy) copy.textContent = res.footerText;
    }
    if (res.showGithubLink === false) {
      const ghLink = document.querySelector('.footer-github');
      if (ghLink) ghLink.style.display = 'none';
    }
  } catch (e) {}
}

let selectedVendors = [];
let currentPeriod = 'month';
let allVendors = [];
let currentAiLang = 'en';

async function setupVendorFilter() {
  const input = document.getElementById('vendor-search');
  const listEl = document.getElementById('vendor-list');
  const tagEl = document.getElementById('vendor-tag');
  if (!input || !listEl) return;

  const days = currentPeriod === 'week' ? 7 : 30;
  try { allVendors = await fetchJSON('/api/vendors?days=' + days); } catch(e) { allVendors = []; }

  function renderTags() {
    if (selectedVendors.length === 0) { tagEl.innerHTML = ''; return; }
    tagEl.innerHTML = selectedVendors.map(v =>
      `<span class="vendor-filter-tag" data-vendor="${escapeHtml(v)}">${escapeHtml(v)} ✕</span>`
    ).join(' ');
    tagEl.querySelectorAll('.vendor-filter-tag').forEach(tag => {
      tag.onclick = () => {
        selectedVendors = selectedVendors.filter(sv => sv !== tag.dataset.vendor);
        renderTags();
        renderList(input.value);
        loadReport();
      };
    });
  }

  function renderList(filter) {
    const filtered = filter ? allVendors.filter(v => v.vendor.toLowerCase().includes(filter.toLowerCase())) : allVendors;
    listEl.innerHTML = filtered.slice(0, 30).map(v =>
      `<div class="vf-item${selectedVendors.includes(v.vendor) ? ' selected' : ''}" data-vendor="${escapeHtml(v.vendor)}">${escapeHtml(v.vendor)} <span style="color:var(--muted);font-size:0.8em">(${v.cnt})</span></div>`
    ).join('');
  }

  input.addEventListener('focus', () => { renderList(input.value); listEl.classList.add('open'); });
  input.addEventListener('input', () => { renderList(input.value); listEl.classList.add('open'); });
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.vendor-filter-wrap')) listEl.classList.remove('open');
  });
  listEl.addEventListener('click', (e) => {
    const item = e.target.closest('.vf-item');
    if (!item) return;
    const vendor = item.dataset.vendor;
    if (selectedVendors.includes(vendor)) {
      selectedVendors = selectedVendors.filter(v => v !== vendor);
    } else {
      selectedVendors.push(vendor);
    }
    input.value = '';
    renderTags();
    renderList('');
    loadReport();
  });
}

async function loadReport() {
  const params = new URLSearchParams(window.location.search);
  const period = params.get('period') === 'week' ? 'week' : 'month';
  currentPeriod = period;
  const days = period === 'week' ? 7 : 30;
  const periodLabel = period === 'week' ? 'Last 7 Days' : 'Last 30 Days';

  // Update page title and section headings
  const titleEl = document.getElementById('report-title');
  if (titleEl) titleEl.textContent = period === 'week' ? 'Weekly Vulnerability Report' : 'Monthly Vulnerability Report';
  document.title = (period === 'week' ? 'Weekly' : 'Monthly') + ' Vulnerability Report';

  const summaryTitle = document.getElementById('summary-title');
  if (summaryTitle) summaryTitle.textContent = periodLabel + ' Summary';

  const kevLabel = document.getElementById('stat-kev-label');
  if (kevLabel) kevLabel.textContent = 'Known exploited vulnerabilities (KEV)';

  const vendorTitle = document.getElementById('vendor-title');
  if (vendorTitle) vendorTitle.innerHTML = '<i data-feather="bar-chart-2" style="width:18px;height:18px;color:var(--accent-pink)"></i> Most Targeted Vendors (' + periodLabel + ')';

  const kevTitle = document.getElementById('kev-title');
  if (kevTitle) kevTitle.innerHTML = '<i data-feather="alert-octagon" style="width:18px;height:18px;color:var(--accent-pink)"></i> Known Exploited Vulnerabilities (KEV) \u2014 ' + periodLabel;

  const nopatchTitle = document.getElementById('nopatch-title');
  if (nopatchTitle) nopatchTitle.innerHTML = '<i data-feather="shield-off" style="width:18px;height:18px;color:var(--accent-pink)"></i> CVSS 8+ \u2014 No Patch Available (' + periodLabel + ')';

  const patchedTitle = document.getElementById('patched-title');
  if (patchedTitle) patchedTitle.innerHTML = '<i data-feather="check-circle" style="width:18px;height:18px;color:var(--accent-pink)"></i> CVSS 9+ \u2014 Patch Available (' + periodLabel + ')';

  try {
    let url = '/api/report?period=' + period;
    if (selectedVendors.length > 0) url += '&vendor=' + encodeURIComponent(selectedVendors.join(','));
    const data = await fetchJSON(url);
    if (data.error) {
      document.getElementById('report-generated').textContent = data.error;
      return;
    }

    // Generated timestamp
    if (data.generatedAt) {
      document.getElementById('report-generated').textContent = 'Report generated: ' + new Date(data.generatedAt).toLocaleString();
    }

    // Stats
    if (data.stats) {
      document.getElementById('stat-total').textContent = data.stats.total || 0;
      document.getElementById('stat-critical').textContent = data.stats.critical || 0;
      document.getElementById('stat-kev').textContent = data.stats.kevCount || 0;
    }

    // Vendor chart
    if (data.topVendors && data.topVendors.length > 0) {
      renderVendorChart(data.topVendors);
    }

    // CVE lists
    renderCveList('kev-list', data.kevCves, 'No known exploited vulnerabilities found in the ' + periodLabel.toLowerCase() + '.');
    renderCveList('nopatch-list', data.highNoPatch, 'No CVSS 8+ CVEs without patches found.');
    renderCveList('patched-list', data.critWithPatch, 'No CVSS 9+ CVEs with patches found.');

    // Re-run feather icons for dynamically set titles
    if (window.feather) feather.replace();
  } catch (e) {
    document.getElementById('report-generated').textContent = 'Error loading report: ' + e.message;
  }
}

// PDF export
function setupPdfExport() {
  const btn = document.getElementById('export-pdf-btn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const content = document.getElementById('main-content');
    if (!content) return;
    btn.disabled = true;
    btn.textContent = 'Generating PDF...';

    const mainContent = document.getElementById('main-content');
    const header = document.querySelector('header');
    const footer = document.getElementById('site-footer');
    const reportLists = document.querySelectorAll('.report-list');
    const loadMoreBtns = document.querySelectorAll('.load-more-btn');
    const vendorFilter = document.querySelector('.vendor-filter');
    const exportRow = btn.closest('div');
    const bodyEl = document.body;
    const htmlEl = document.documentElement;
    const beforeEl = bodyEl; // for ::before pseudo-element

    // Remember original theme state
    const wasLight = htmlEl.classList.contains('light-theme');

    // Save original styles
    const origMain = mainContent.style.cssText;
    const origHeader = header ? header.style.cssText : '';
    const origFooter = footer ? footer.style.cssText : '';
    const origBody = bodyEl.style.cssText;
    const origListStyles = [];
    reportLists.forEach(l => origListStyles.push(l.style.cssText));

    // Force light theme for PDF
    if (!wasLight) htmlEl.classList.add('light-theme');

    // Inject temporary PDF styles to hide pseudo-elements and force white bg
    const pdfStyle = document.createElement('style');
    pdfStyle.textContent = 'body::before{display:none !important} body{background:#ffffff !important;display:block !important} .report-list a{color:#1a0a2e !important} h1,h2,h3{color:#1a0a2e !important} .badge-no{background:rgba(40,20,60,0.06) !important;color:rgba(40,20,60,0.5) !important} .badge-nopatch{background:rgba(200,40,40,0.08) !important;color:#c0392b !important} #ai-content h2,#ai-content h3{color:#8400ff !important} #ai-content strong{color:#1a0a2e !important} #ai-content a{color:#1a0a2e !important} #synthwave-canvas{display:none !important} .stat-number{-webkit-text-fill-color:#8400ff !important;color:#8400ff !important;background:none !important;-webkit-background-clip:unset !important;background-clip:unset !important} h1 svg,h1 i{display:none !important} .report-section{page-break-inside:avoid;break-inside:avoid} .card{page-break-inside:avoid;break-inside:avoid} #ai-card{page-break-inside:auto;break-inside:auto} #ai-content li{page-break-inside:avoid;break-inside:avoid} #ai-content h2,#ai-content h3{page-break-after:avoid;break-after:avoid} #ai-content p{page-break-inside:avoid;break-inside:avoid} .report-list .card{page-break-inside:avoid;break-inside:avoid}';
    document.head.appendChild(pdfStyle);

    // Override body for PDF: white bg, no honeycomb overlay
    bodyEl.style.cssText = 'margin:0;font-family:Inter,Arial,Helvetica,sans-serif;color:#1a0a2e;background:#ffffff;overflow:visible;height:auto;';

    // Apply PDF-friendly styles
    // Add logo above the report title for PDF
    const pdfLogo = document.createElement('div');
    pdfLogo.id = 'pdf-logo';
    pdfLogo.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:12px;';
    pdfLogo.innerHTML = '<div style="width:44px;height:44px;border-radius:8px;background:linear-gradient(90deg,#ff4da6,#8400ff);display:flex;align-items:center;justify-content:center"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path></svg></div><span style="font-family:geist-mono,Orbitron,Inter,sans-serif;font-weight:700;font-size:1.2em;color:#1a0a2e">Security dashboard</span>';
    const reportWrapper = mainContent.querySelector('div');
    if (reportWrapper) reportWrapper.insertBefore(pdfLogo, reportWrapper.firstChild);

    mainContent.style.cssText = 'position:static;overflow:visible;max-height:none;padding:20px;background:#ffffff;color:#1a0a2e;display:block;';
    if (header) header.style.display = 'none';
    if (footer) footer.style.display = 'none';
    if (vendorFilter) vendorFilter.style.display = 'none';
    if (exportRow) exportRow.style.display = 'none';
    reportLists.forEach(l => { l.style.cssText = 'max-height:none;overflow:visible;'; });
    loadMoreBtns.forEach(b => { b.style.display = 'none'; });

    // Hide vendor chart section in PDF
    const vendorSection = document.getElementById('vendor-title');
    const vendorSectionEl = vendorSection ? vendorSection.closest('.report-section') : null;
    const origVendorSection = vendorSectionEl ? vendorSectionEl.style.cssText : '';
    if (vendorSectionEl) vendorSectionEl.style.display = 'none';

    // Hide KEV, Patched, and NoPatch list sections in PDF
    const kevSection = document.getElementById('kev-title');
    const kevSectionEl = kevSection ? kevSection.closest('.report-section') : null;
    const origKevSection = kevSectionEl ? kevSectionEl.style.cssText : '';
    if (kevSectionEl) kevSectionEl.style.display = 'none';

    const patchedSection = document.getElementById('patched-title');
    const patchedSectionEl = patchedSection ? patchedSection.closest('.report-section') : null;
    const origPatchedSection = patchedSectionEl ? patchedSectionEl.style.cssText : '';
    if (patchedSectionEl) patchedSectionEl.style.display = 'none';

    const nopatchSection = document.getElementById('nopatch-title');
    const nopatchSectionEl = nopatchSection ? nopatchSection.closest('.report-section') : null;
    const origNopatchSection = nopatchSectionEl ? nopatchSectionEl.style.cssText : '';
    if (nopatchSectionEl) nopatchSectionEl.style.display = 'none';

    // Save AI card original style BEFORE any modifications
    const aiCard = document.getElementById('ai-card');
    const origAiCard = aiCard ? aiCard.style.cssText : '';

    // Force all cards to light styling (must capture originals before modifying aiCard)
    const allCards = mainContent.querySelectorAll('.card');
    const origCardStyles = [];
    allCards.forEach(c => {
      origCardStyles.push(c.style.cssText);
      c.style.cssText = c.style.cssText + ';background:rgba(255,255,255,0.95);border:1px solid rgba(100,60,140,0.12);color:#1a0a2e;box-shadow:0 2px 8px rgba(100,60,140,0.08);';
    });

    // Remove AI card max-height so analysis is shown in full
    if (aiCard) aiCard.style.cssText = 'overflow:visible;max-height:none;padding:16px;background:none;border:none;color:#1a0a2e;box-shadow:none;border-radius:0;';

    // Force text colors to dark
    const allMeta = mainContent.querySelectorAll('.meta, .desc, .generated-at, .stat-label');
    const origMetaStyles = [];
    allMeta.forEach(el => {
      origMetaStyles.push(el.style.cssText);
      el.style.color = 'rgba(40,20,60,0.6)';
    });

    // Force section headings to dark
    const allH2 = mainContent.querySelectorAll('h2');
    const origH2Styles = [];
    allH2.forEach(el => {
      origH2Styles.push(el.style.cssText);
      el.style.color = '#1a0a2e';
    });

    // Update vendor chart to light colors
    if (vendorChartInstance) {
      vendorChartInstance.options.scales.x.ticks.color = '#1a0a2e';
      vendorChartInstance.options.scales.x.grid.color = 'rgba(100,60,140,0.08)';
      vendorChartInstance.options.scales.y.ticks.color = '#1a0a2e';
      vendorChartInstance.update();
    }

    // Force chart container background
    const chartContainer = mainContent.querySelector('.chart-container');
    const origChartContainer = chartContainer ? chartContainer.style.cssText : '';
    if (chartContainer) chartContainer.style.cssText = chartContainer.style.cssText + ';background:rgba(100,60,140,0.03);border-radius:10px;';

    const opt = {
      margin: [10, 10, 10, 10],
      filename: 'vulnerability-report.pdf',
      image: { type: 'jpeg', quality: 0.95 },
      html2canvas: { scale: 2, useCORS: true, scrollY: 0, windowHeight: document.body.scrollHeight, backgroundColor: '#ffffff' },
      jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
      pagebreak: { mode: ['css', 'legacy'], avoid: ['.card', '.stat-card', '.report-section', 'li', 'h2', 'h3'] }
    };

    try {
      await html2pdf().set(opt).from(mainContent).save();
    } catch (e) { /* ignore */ }

    // Restore everything
    const pdfLogoEl = document.getElementById('pdf-logo');
    if (pdfLogoEl) pdfLogoEl.remove();
    pdfStyle.remove();
    bodyEl.style.cssText = origBody;
    mainContent.style.cssText = origMain;
    if (header) header.style.cssText = origHeader;
    if (footer) footer.style.cssText = origFooter;
    if (vendorFilter) vendorFilter.style.display = '';
    if (exportRow) exportRow.style.display = '';
    if (vendorSectionEl) vendorSectionEl.style.cssText = origVendorSection;
    if (kevSectionEl) kevSectionEl.style.cssText = origKevSection;
    if (patchedSectionEl) patchedSectionEl.style.cssText = origPatchedSection;
    if (nopatchSectionEl) nopatchSectionEl.style.cssText = origNopatchSection;
    reportLists.forEach((l, i) => { l.style.cssText = origListStyles[i]; });
    loadMoreBtns.forEach(b => { b.style.display = ''; });
    allCards.forEach((c, i) => { c.style.cssText = origCardStyles[i]; });
    // Restore AI card AFTER allCards (since allCards also includes ai-card)
    if (aiCard) aiCard.style.cssText = origAiCard;
    allMeta.forEach((el, i) => { el.style.cssText = origMetaStyles[i]; });
    allH2.forEach((el, i) => { el.style.cssText = origH2Styles[i]; });
    if (chartContainer) chartContainer.style.cssText = origChartContainer;

    // Restore original theme
    if (!wasLight) {
      htmlEl.classList.remove('light-theme');
    }

    // Restore chart colors to current theme
    if (vendorChartInstance) {
      const isLight = htmlEl.classList.contains('light-theme');
      const tickColor = isLight ? '#1a0a2e' : '#efe8ff';
      const gridColor = isLight ? 'rgba(100,60,140,0.08)' : 'rgba(255,255,255,0.04)';
      vendorChartInstance.options.scales.x.ticks.color = tickColor;
      vendorChartInstance.options.scales.x.grid.color = gridColor;
      vendorChartInstance.options.scales.y.ticks.color = tickColor;
      vendorChartInstance.update();
    }

    btn.disabled = false;
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Export to PDF';
  });
}

// Markdown to HTML with nested list support (bullets inside numbered lists)
function mdToHtml(md) {
  if (!md) return '';
  const lines = md.split('\n');
  let html = '';
  // Stack tracks open list types: 'ul' or 'ol'
  const stack = [];
  let olLiOpen = false; // true when an <ol><li> is open and may receive nested <ul>

  function closeTo(depth) {
    while (stack.length > depth) {
      const tag = stack.pop();
      html += '</li></' + tag + '>';
    }
    olLiOpen = false;
  }

  function closeAll() { closeTo(0); }

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === '') continue;

    const isBullet = trimmed.startsWith('- ') || trimmed.startsWith('* ');
    const isNumbered = /^\d+[\.\)] /.test(trimmed);
    const isHeading = trimmed.startsWith('## ');
    const isSubHeading = trimmed.startsWith('### ');

    if (isSubHeading) {
      closeAll();
      html += '<h3>' + inlineMd(trimmed.slice(4)) + '</h3>';
    } else if (isHeading) {
      closeAll();
      html += '<h2>' + inlineMd(trimmed.slice(3)) + '</h2>';
    } else if (isNumbered) {
      // Close any nested ul first, but keep the parent ol
      if (stack.length > 0 && stack[stack.length - 1] === 'ul') {
        closeTo(stack.length - 1);
      }
      // Close previous ol li if open
      if (olLiOpen) { html += '</li>'; olLiOpen = false; }
      // If no ol on stack, close everything and start one
      if (stack.length === 0 || stack[stack.length - 1] !== 'ol') {
        closeAll();
        html += '<ol>';
        stack.push('ol');
      }
      html += '<li>' + inlineMd(trimmed.replace(/^\d+[\.\)] /, ''));
      olLiOpen = true;
    } else if (isBullet) {
      // Nest inside an open ol li, or start a standalone ul
      if (olLiOpen && (stack.length === 0 || stack[stack.length - 1] === 'ol')) {
        html += '<ul>';
        stack.push('ul');
        olLiOpen = false;
      }
      if (stack.length === 0 || stack[stack.length - 1] !== 'ul') {
        closeAll();
        html += '<ul>';
        stack.push('ul');
      }
      html += '<li>' + inlineMd(trimmed.slice(2)) + '</li>';
    } else {
      closeAll();
      html += '<p>' + inlineMd(trimmed) + '</p>';
    }
  }
  closeAll();
  return html;
}

function inlineMd(text) {
  let s = escapeHtml(text);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`(.+?)`/g, '<code>$1</code>');
  s = s.replace(/\b(CVE-\d{4}-\d{4,})\b/g, '<a href="https://nvd.nist.gov/vuln/detail/$1" target="_blank" rel="noopener">$1</a>');
  return s;
}

// Fetch and render AI analysis
async function loadAiAnalysis(lang) {
  lang = lang || currentAiLang || 'en';
  const params = new URLSearchParams(window.location.search);
  const period = params.get('period') === 'week' ? 'week' : 'month';
  const contentEl = document.getElementById('ai-content');
  const metaEl = document.getElementById('ai-meta');
  const genEl = document.getElementById('ai-generated-at');

  try {
    const data = await fetchJSON('/api/ai-analysis?period=' + period + '&lang=' + lang);
    if (data.analysis) {
      contentEl.innerHTML = mdToHtml(data.analysis);
      if (data.generatedAt && genEl) {
        genEl.textContent = new Date(data.generatedAt).toLocaleString();
        metaEl.style.display = 'block';
      }
    } else {
      contentEl.innerHTML = '<span style="color:var(--muted)">' +
        (lang === 'sv' ? 'Ingen AI-analys tillg\u00e4nglig \u00e4nnu.' : 'No AI analysis available yet. Analysis runs automatically on Sunday nights (weekly) and end of month (monthly).') +
        '</span>';
    }
  } catch (e) {
    contentEl.innerHTML = '<span style="color:var(--muted)">' +
      (lang === 'sv' ? 'Kunde inte ladda AI-analys.' : 'Could not load AI analysis.') +
      '</span>';
  }
}

// Language toggle for AI analysis + report headings
function setupLangToggle() {
  const btn = document.getElementById('lang-toggle-btn');
  const label = document.getElementById('lang-label');
  if (!btn) return;
  function updateLabel() {
    if (label) label.textContent = currentAiLang.toUpperCase();
  }
  updateLabel();
  btn.addEventListener('click', () => {
    currentAiLang = currentAiLang === 'en' ? 'sv' : 'en';
    updateLabel();
    loadAiAnalysis(currentAiLang);
    translateHeadings(currentAiLang);
  });
}

function translateHeadings(lang) {
  const params = new URLSearchParams(window.location.search);
  const period = params.get('period') === 'week' ? 'week' : 'month';
  const periodLabel = lang === 'sv'
    ? (period === 'week' ? 'Senaste 7 dagarna' : 'Senaste 30 dagarna')
    : (period === 'week' ? 'Last 7 Days' : 'Last 30 Days');
  const sv = lang === 'sv';

  const titleEl = document.getElementById('report-title');
  if (titleEl) titleEl.textContent = sv
    ? (period === 'week' ? 'Veckovis s\u00e5rbarhetsrapport' : 'M\u00e5natlig s\u00e5rbarhetsrapport')
    : (period === 'week' ? 'Weekly Vulnerability Report' : 'Monthly Vulnerability Report');

  const summaryTitle = document.getElementById('summary-title');
  if (summaryTitle) summaryTitle.textContent = sv ? 'Sammanfattning f\u00f6r ' + periodLabel.toLowerCase() : periodLabel + ' Summary';

  const totalLabel = document.getElementById('stat-total-label');
  if (totalLabel) totalLabel.textContent = sv ? 'Nya publicerade s\u00e5rbarheter' : 'New vulnerabilities published';

  const critLabel = document.getElementById('stat-critical-label');
  if (critLabel) critLabel.textContent = sv ? 'Kritiska s\u00e5rbarheter (CVSS \u2265 9)' : 'Critical vulnerabilities (CVSS \u2265 9)';

  const vendorTitle = document.getElementById('vendor-title');
  if (vendorTitle) vendorTitle.innerHTML = '<i data-feather="bar-chart-2" style="width:18px;height:18px;color:var(--accent-pink)"></i> ' +
    (sv ? 'Mest drabbade leverant\u00f6rer (' + periodLabel + ')' : 'Most Targeted Vendors (' + periodLabel + ')');

  const aiTitle = document.getElementById('ai-title');
  if (aiTitle) aiTitle.innerHTML = '<i data-feather="cpu" style="width:18px;height:18px;color:var(--accent-pink)"></i> ' +
    (sv ? 'AI-s\u00e4kerhetsanalys' : 'AI Security Analysis');

  const nopatchTitle = document.getElementById('nopatch-title');
  if (nopatchTitle) nopatchTitle.innerHTML = '<i data-feather="shield-off" style="width:18px;height:18px;color:var(--accent-pink)"></i> ' +
    (sv ? 'CVSS 8+ \u2014 Ingen patch tillg\u00e4nglig (' + periodLabel + ')' : 'CVSS 8+ \u2014 No Patch Available (' + periodLabel + ')');

  const patchedTitle = document.getElementById('patched-title');
  if (patchedTitle) patchedTitle.innerHTML = '<i data-feather="check-circle" style="width:18px;height:18px;color:var(--accent-pink)"></i> ' +
    (sv ? 'CVSS 9+ \u2014 Patch tillg\u00e4nglig (' + periodLabel + ')' : 'CVSS 9+ \u2014 Patch Available (' + periodLabel + ')');

  // KEV title stays in English always
  const kevTitle = document.getElementById('kev-title');
  if (kevTitle) kevTitle.innerHTML = '<i data-feather="alert-octagon" style="width:18px;height:18px;color:var(--accent-pink)"></i> Known Exploited Vulnerabilities (KEV) \u2014 ' + periodLabel;

  document.title = (titleEl ? titleEl.textContent : '') + (sv ? ' \u2014 S\u00e4kerhetsinstrumentpanel' : '');

  if (window.feather) feather.replace();
}

// Visitor IP for footer
async function fetchVisitorIp(retries) {
  retries = retries || 0;
  try {
    const res = await fetchJSON('/api/myip');
    const addrEl = document.getElementById('ip-addr');
    const flagEl = document.getElementById('ip-flag');
    if (addrEl && res.ip) addrEl.textContent = res.ip;
    if (flagEl && res.countryCode) {
      const cc = res.countryCode.toLowerCase();
      flagEl.innerHTML = '<img src="https://flagcdn.com/20x15/' + cc + '.png" width="20" height="15" alt="' + escapeHtml(res.countryCode) + '" style="vertical-align:middle;border-radius:2px">';
    }
  } catch (e) {
    if (retries < 3) setTimeout(() => fetchVisitorIp(retries + 1), 3000);
  }
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();
  fetchPublicSettings();
  loadReport();
  setupVendorFilter();
  setupPdfExport();
  fetchVisitorIp();
  loadAiAnalysis();
  setupLangToggle();
});
