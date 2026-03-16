// newssummary.js — News Summary page logic

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('Error ' + r.status);
  return r.json();
}

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

// --- i18n ---
let currentLang = localStorage.getItem('dashLang') || 'en';

const nsI18n = {
  en: {
    dashboard: 'Dashboard',
    heading: 'News Summary',
    subtitle: 'Weekly IT news analysis from a Swedish perspective — for IT consultants.',
    aiHeading: 'AI News Analysis',
    noAnalysis: 'No AI analysis available yet. Analysis is generated automatically every week.',
    lastUpdated: 'Last updated',
    errorLoad: 'Could not load analysis.',
    loading: 'Loading...'
  },
  sv: {
    dashboard: 'Dashboard',
    heading: 'Omvärldsanalys',
    subtitle: 'Veckovis IT-nyhetsanalys ur ett svenskt perspektiv — för IT-konsulter.',
    aiHeading: 'AI-nyhetsanalys',
    noAnalysis: 'Ingen AI-analys tillgänglig ännu. Analysen genereras automatiskt varje vecka.',
    lastUpdated: 'Senast uppdaterad',
    errorLoad: 'Kunde inte ladda analysen.',
    loading: 'Laddar...'
  }
};

function t(key) { return (nsI18n[currentLang] || nsI18n.en)[key] || (nsI18n.en)[key] || key; }

function applyTranslations() {
  const set = (id, key) => { const el = document.getElementById(id); if (el) el.textContent = t(key); };
  set('nav-dashboard-label', 'dashboard');
  set('ns-heading', 'heading');
  set('ns-subtitle', 'subtitle');
  set('ai-heading', 'aiHeading');
  const langLabel = document.getElementById('lang-label');
  if (langLabel) langLabel.textContent = currentLang.toUpperCase();
}

function setupLangToggle() {
  const btn = document.getElementById('lang-toggle');
  if (!btn) return;
  btn.addEventListener('click', () => {
    currentLang = currentLang === 'en' ? 'sv' : 'en';
    localStorage.setItem('dashLang', currentLang);
    applyTranslations();
    loadNewsAnalysis();
  });
}

// --- Theme toggle ---
function setupThemeToggle() {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  const sunSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  const moonSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  function updateIcon() {
    btn.innerHTML = document.documentElement.classList.contains('light-theme') ? moonSvg : sunSvg;
  }
  updateIcon();
  btn.addEventListener('click', () => {
    document.documentElement.classList.toggle('light-theme');
    localStorage.setItem('theme', document.documentElement.classList.contains('light-theme') ? 'light' : 'dark');
    updateIcon();
  });
}

// --- Visitor IP ---
async function fetchVisitorIp() {
  try {
    const res = await fetchJSON('/api/myip');
    const addrEl = document.getElementById('ip-addr');
    const flagEl = document.getElementById('ip-flag');
    if (addrEl && res.ip) addrEl.textContent = res.ip;
    if (flagEl && res.countryCode) {
      const cc = res.countryCode.toLowerCase();
      flagEl.innerHTML = '<img src="https://flagcdn.com/20x15/' + cc + '.png" width="20" height="15" alt="' + escapeHtml(res.countryCode) + '" style="vertical-align:middle;border-radius:2px">';
    }
  } catch (e) {}
}

// --- Public settings ---
async function fetchPublicSettings() {
  try {
    const res = await fetchJSON('/api/settings/public');
    if (res.siteName) {
      const el = document.querySelector('.site-title');
      if (el) el.textContent = res.siteName;
      document.title = res.siteName + ' — News Summary';
      const ghSpan = document.querySelector('.footer-github span');
      if (ghSpan) ghSpan.textContent = res.siteName + ' on GitHub';
    }
    if (res.logo) {
      const logoEl = document.querySelector('.logo');
      if (logoEl) logoEl.innerHTML = '<img src="' + escapeHtml(res.logo) + '" alt="Logo" style="width:100%;height:100%;object-fit:contain;border-radius:8px">';
    }
  } catch (e) {}
}

// --- Markdown to HTML ---
function mdToHtml(md) {
  if (!md) return '';
  const lines = md.split('\n');
  let html = '';
  const stack = [];
  let olLiOpen = false;

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
    const isSubHeading = trimmed.startsWith('### ');
    const isHeading = trimmed.startsWith('## ');
    const isH1 = !isHeading && !isSubHeading && trimmed.startsWith('# ');

    if (isH1) {
      closeAll();
      html += '<h2>' + inlineMd(trimmed.slice(2)) + '</h2>';
    } else if (isSubHeading) {
      closeAll();
      html += '<h3>' + inlineMd(trimmed.slice(4)) + '</h3>';
    } else if (isHeading) {
      closeAll();
      html += '<h2>' + inlineMd(trimmed.slice(3)) + '</h2>';
    } else if (isNumbered) {
      if (stack.length > 0 && stack[stack.length - 1] === 'ul') closeTo(stack.length - 1);
      if (olLiOpen) { html += '</li>'; olLiOpen = false; }
      if (stack.length === 0 || stack[stack.length - 1] !== 'ol') { closeAll(); html += '<ol>'; stack.push('ol'); }
      html += '<li>' + inlineMd(trimmed.replace(/^\d+[\.\)] /, ''));
      olLiOpen = true;
    } else if (isBullet) {
      if (olLiOpen && (stack.length === 0 || stack[stack.length - 1] === 'ol')) { html += '<ul>'; stack.push('ul'); olLiOpen = false; }
      if (stack.length === 0 || stack[stack.length - 1] !== 'ul') { closeAll(); html += '<ul>'; stack.push('ul'); }
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
  // Extract markdown links before escaping
  const links = [];
  let s = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => {
    const i = links.length;
    links.push({ label, url });
    return '\x00LINK' + i + '\x00';
  });
  s = escapeHtml(s);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`(.+?)`/g, '<code>$1</code>');
  // Restore links
  s = s.replace(/\x00LINK(\d+)\x00/g, (_, i) => {
    const l = links[Number(i)];
    return '<a href="' + escapeHtml(l.url).replace(/&amp;/g, '&') + '" target="_blank" rel="noopener">' + escapeHtml(l.label) + '</a>';
  });
  s = s.replace(/\b(CVE-\d{4}-\d{4,})\b/g, '<a href="https://nvd.nist.gov/vuln/detail/$1" target="_blank" rel="noopener">$1</a>');
  return s;
}

// --- Load and render AI analysis ---
async function loadNewsAnalysis() {
  const contentEl = document.getElementById('ai-content');
  const updatedEl = document.getElementById('ai-updated');
  try {
    const data = await fetchJSON('/api/newssummary?lang=' + currentLang);
    if (data.analysis) {
      contentEl.innerHTML = mdToHtml(data.analysis);
      if (updatedEl && data.analysisGeneratedAt) {
        const d = new Date(data.analysisGeneratedAt);
        updatedEl.textContent = t('lastUpdated') + ': ' + d.toLocaleString(currentLang === 'sv' ? 'sv-SE' : 'en-US');
      }
    } else {
      contentEl.innerHTML = '<div class="empty-state">' + escapeHtml(t('noAnalysis')) + '</div>';
      if (updatedEl) updatedEl.textContent = '';
    }
  } catch (e) {
    contentEl.innerHTML = '<div class="empty-state">' + escapeHtml(t('errorLoad')) + '</div>';
  }
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();
  setupLangToggle();
  applyTranslations();
  fetchPublicSettings();
  fetchVisitorIp();
  loadNewsAnalysis();
});
