// tools.js — Security Tools page logic

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const body = await r.text();
    throw new Error(body || 'Error ' + r.status);
  }
  return r.json();
}

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function showResult(id, html) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = html;
  el.classList.add('visible');
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? 'Loading...' : btn.dataset.label || 'Go';
}

// --- Theme toggle ---
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
  });
}

// --- Visitor IP ---
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

// --- Public settings ---
async function fetchPublicSettings() {
  try {
    const res = await fetchJSON('/api/settings/public');
    if (res.siteName) {
      const el = document.querySelector('.site-title');
      if (el) el.textContent = res.siteName;
      document.title = res.siteName + ' — Security Tools';
      const ghSpan = document.querySelector('.footer-github span');
      if (ghSpan) ghSpan.textContent = res.siteName + ' on GitHub';
    }
    if (res.logo) {
      const logoEl = document.querySelector('.logo');
      if (logoEl) logoEl.innerHTML = '<img src="' + escapeHtml(res.logo) + '" alt="Logo" style="width:100%;height:100%;object-fit:contain;border-radius:8px">';
    }
    if (res.hibpEnabled === false) {
      const card = document.getElementById('tool-email-breach');
      if (card) card.style.display = 'none';
    }
  } catch (e) {}
}

// =========================================================================
//  1. WEBSITE SECURITY HEADERS
// =========================================================================
function setupHeadersTool() {
  const btn = document.getElementById('headers-btn');
  const input = document.getElementById('headers-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Analyze';

  async function run() {
    let url = input.value.trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    setLoading('headers-btn', true);
    try {
      const data = await fetchJSON('/api/tools/headers?url=' + encodeURIComponent(url));
      let html = '<span class="label">Security Headers for ' + escapeHtml(url) + '</span>\n\n';
      if (data.headers && typeof data.headers === 'object') {
        const checks = [
          { key: 'strict-transport-security', name: 'Strict-Transport-Security (HSTS)' },
          { key: 'content-security-policy', name: 'Content-Security-Policy' },
          { key: 'x-content-type-options', name: 'X-Content-Type-Options' },
          { key: 'x-frame-options', name: 'X-Frame-Options' },
          { key: 'x-xss-protection', name: 'X-XSS-Protection' },
          { key: 'referrer-policy', name: 'Referrer-Policy' },
          { key: 'permissions-policy', name: 'Permissions-Policy' },
          { key: 'access-control-allow-origin', name: 'Access-Control-Allow-Origin' },
        ];
        for (const c of checks) {
          const val = data.headers[c.key];
          if (val) {
            html += '<span class="ok">✓</span> <span class="label">' + c.name + '</span>\n  ' + escapeHtml(val) + '\n';
          } else {
            html += '<span class="bad">✗</span> <span class="label">' + c.name + '</span>\n  <span class="muted">Not set</span>\n';
          }
        }
        // Show other notable headers
        const shown = new Set(checks.map(c => c.key));
        html += '\n<span class="label">Other headers:</span>\n';
        for (const [k, v] of Object.entries(data.headers)) {
          if (!shown.has(k)) {
            html += '  ' + escapeHtml(k) + ': ' + escapeHtml(String(v).substring(0, 200)) + '\n';
          }
        }
      }
      if (data.status) html += '\n<span class="label">HTTP Status:</span> ' + data.status;
      showResult('headers-result', html);
    } catch (e) {
      showResult('headers-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('headers-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// =========================================================================
//  2. DNS RECORD LOOKUP
// =========================================================================
function setupDnsTool() {
  const btn = document.getElementById('dns-btn');
  const input = document.getElementById('dns-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Lookup';

  async function run() {
    const domain = input.value.trim();
    if (!domain) return;
    setLoading('dns-btn', true);
    try {
      const data = await fetchJSON('/api/tools/dns?domain=' + encodeURIComponent(domain));
      let html = '<span class="label">DNS Records for ' + escapeHtml(domain) + '</span>\n\n';
      function renderRecords(label, records, formatter) {
        if (!records || !records.length) return;
        html += '<span class="label">' + label + ':</span>\n';
        records.forEach(r => { html += '  ' + (formatter ? formatter(r) : escapeHtml(String(r))) + '\n'; });
        html += '\n';
      }
      renderRecords('A Records', data.A);
      renderRecords('AAAA Records', data.AAAA);
      renderRecords('MX Records', data.MX, r => escapeHtml(r.exchange || String(r)) + ' (priority: ' + (r.priority || 0) + ')');
      renderRecords('TXT Records', data.TXT, r => escapeHtml(Array.isArray(r) ? r.join('') : String(r)));
      renderRecords('NS Records', data.NS);
      // Subdomain A records
      if (data.subdomains && Object.keys(data.subdomains).length) {
        html += '<span class="label">Subdomain A Records:</span>\n';
        for (const [sub, ips] of Object.entries(data.subdomains)) {
          html += '  <span class="ok">' + escapeHtml(sub) + '</span>  →  ' + ips.map(ip => escapeHtml(ip)).join(', ') + '\n';
        }
        html += '\n';
      }
      if (!data.A?.length && !data.AAAA?.length && !data.MX?.length && !data.TXT?.length && !data.NS?.length && !data.subdomains) html += '<span class="muted">No records found.</span>';
      showResult('dns-result', html);
    } catch (e) {
      showResult('dns-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('dns-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// =========================================================================
//  3. MALWARE HASH CHECKER
// =========================================================================
function setupHashTool() {
  const btn = document.getElementById('hash-btn');
  const input = document.getElementById('hash-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Check';

  async function run() {
    const hash = input.value.trim();
    if (!hash) return;
    if (!/^[a-fA-F0-9]{32,64}$/.test(hash)) {
      showResult('hash-result', '<span class="bad">Invalid hash format. Enter MD5 (32), SHA-1 (40), or SHA-256 (64) hex characters.</span>');
      return;
    }
    setLoading('hash-btn', true);
    try {
      const data = await fetchJSON('/api/tools/hash?hash=' + encodeURIComponent(hash));
      let html = '<span class="label">Hash Lookup: ' + escapeHtml(hash) + '</span>\n\n';
      if (data.found) {
        html += '<span class="bad">⚠ MALICIOUS</span>\n\n';
        if (data.malware) html += '<span class="label">Malware:</span> ' + escapeHtml(data.malware) + '\n';
        if (data.source) html += '<span class="label">Source:</span> ' + escapeHtml(data.source) + '\n';
        if (data.firstSeen) html += '<span class="label">First seen:</span> ' + escapeHtml(data.firstSeen) + '\n';
        if (data.lastSeen) html += '<span class="label">Last seen:</span> ' + escapeHtml(data.lastSeen) + '\n';
        if (data.signature) html += '<span class="label">Signature:</span> ' + escapeHtml(data.signature) + '\n';
        if (data.detections) html += '<span class="label">Detections:</span> ' + escapeHtml(String(data.detections)) + '\n';
      } else {
        html += '<span class="ok">✓ Not found in threat databases</span>\n';
        html += '<span class="muted">This hash was not found in Malware Bazaar or known threat feeds.</span>\n';
      }
      showResult('hash-result', html);
    } catch (e) {
      showResult('hash-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('hash-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// =========================================================================
//  4. IP SCOUT
// =========================================================================
function setupIpTool() {
  const btn = document.getElementById('ip-btn');
  const input = document.getElementById('ip-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Scout';

  async function run() {
    const ip = input.value.trim();
    if (!ip) return;
    setLoading('ip-btn', true);
    try {
      const data = await fetchJSON('/api/tools/ip?ip=' + encodeURIComponent(ip));
      let html = '<span class="label">IP Intelligence: ' + escapeHtml(ip) + '</span>\n\n';
      if (data.country) html += '<span class="label">Country:</span> ' + escapeHtml(data.country) + (data.countryCode ? ' (' + escapeHtml(data.countryCode) + ')' : '') + '\n';
      if (data.region) html += '<span class="label">Region:</span> ' + escapeHtml(data.region) + '\n';
      if (data.city) html += '<span class="label">City:</span> ' + escapeHtml(data.city) + '\n';
      if (data.isp) html += '<span class="label">ISP:</span> ' + escapeHtml(data.isp) + '\n';
      if (data.org) html += '<span class="label">Organization:</span> ' + escapeHtml(data.org) + '\n';
      if (data.as) html += '<span class="label">AS:</span> ' + escapeHtml(data.as) + '\n';
      if (data.lat != null && data.lon != null) html += '<span class="label">Location:</span> ' + data.lat + ', ' + data.lon + '\n';
      if (data.timezone) html += '<span class="label">Timezone:</span> ' + escapeHtml(data.timezone) + '\n';
      if (data.reverse) html += '<span class="label">Reverse DNS:</span> ' + escapeHtml(data.reverse) + '\n';
      showResult('ip-result', html);
    } catch (e) {
      showResult('ip-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('ip-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// =========================================================================
//  5. PORT & VULNERABILITY CHECK (Shodan)
// =========================================================================
function setupPortsTool() {
  const btn = document.getElementById('ports-btn');
  const input = document.getElementById('ports-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Scan';

  async function run() {
    const target = input.value.trim();
    if (!target) return;
    setLoading('ports-btn', true);
    try {
      const data = await fetchJSON('/api/tools/ports?target=' + encodeURIComponent(target));
      let html = '<span class="label">Shodan Results: ' + escapeHtml(data.ip || target) + '</span>\n\n';
      if (data.hostnames && data.hostnames.length) html += '<span class="label">Hostnames:</span> ' + data.hostnames.map(h => escapeHtml(h)).join(', ') + '\n';
      if (data.os) html += '<span class="label">OS:</span> ' + escapeHtml(data.os) + '\n';
      if (data.org) html += '<span class="label">Organization:</span> ' + escapeHtml(data.org) + '\n';
      if (data.isp) html += '<span class="label">ISP:</span> ' + escapeHtml(data.isp) + '\n';
      if (data.ports && data.ports.length) {
        html += '\n<span class="label">Open Ports:</span>\n';
        data.ports.forEach(p => {
          html += '  <span class="warn">' + escapeHtml(String(p.port)) + '/' + escapeHtml(p.transport || 'tcp') + '</span>';
          if (p.product) html += ' — ' + escapeHtml(p.product) + (p.version ? ' ' + escapeHtml(p.version) : '');
          html += '\n';
        });
      }
      if (data.vulns && data.vulns.length) {
        html += '\n<span class="label">Known Vulnerabilities:</span>\n';
        data.vulns.forEach(v => {
          html += '  <span class="bad">' + escapeHtml(v) + '</span>\n';
        });
      }
      if (!data.ports && !data.vulns && !data.error) html += '<span class="muted">No data found for this target.</span>\n';
      if (data.error) html += '<span class="bad">' + escapeHtml(data.error) + '</span>\n';
      showResult('ports-result', html);
    } catch (e) {
      showResult('ports-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('ports-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// =========================================================================
//  6. PASSWORD CHECK (k-anonymity HIBP — hash is computed client-side)
// =========================================================================
function setupPasswordTool() {
  const btn = document.getElementById('password-btn');
  const input = document.getElementById('password-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Check';

  async function sha1(str) {
    const buf = new TextEncoder().encode(str);
    const digest = await crypto.subtle.digest('SHA-1', buf);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  async function run() {
    const pw = input.value;
    if (!pw) return;
    setLoading('password-btn', true);
    try {
      const hash = await sha1(pw);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);
      // Use HIBP k-anonymity API directly from the browser (CORS allowed)
      const resp = await fetch('https://api.pwnedpasswords.com/range/' + prefix);
      if (!resp.ok) throw new Error('HIBP API error ' + resp.status);
      const text = await resp.text();
      const lines = text.split('\n');
      let count = 0;
      for (const line of lines) {
        const [h, c] = line.split(':');
        if (h.trim().toUpperCase() === suffix) { count = parseInt(c.trim(), 10); break; }
      }
      let html = '<span class="label">Password Check Result</span>\n\n';
      if (count > 0) {
        html += '<span class="bad">⚠ COMPROMISED</span>\n\n';
        html += 'This password has been seen <span class="bad">' + count.toLocaleString() + '</span> times in data breaches.\n';
        html += '<span class="muted">You should change this password immediately.</span>\n';
      } else {
        html += '<span class="ok">✓ Not found in breach databases</span>\n\n';
        html += '<span class="muted">This password was not found in the Have I Been Pwned database.\nThis does not guarantee it is safe — use a strong, unique password.</span>\n';
      }
      showResult('password-result', html);
    } catch (e) {
      showResult('password-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('password-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// =========================================================================
//  7. EMAIL BREACH CHECK (HIBP — proxied through server)
// =========================================================================
function setupEmailBreachTool() {
  const btn = document.getElementById('email-breach-btn');
  const input = document.getElementById('email-breach-input');
  if (!btn || !input) return;
  btn.dataset.label = 'Check';

  async function run() {
    const email = input.value.trim();
    if (!email) return;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showResult('email-breach-result', '<span class="bad">Please enter a valid email address.</span>');
      return;
    }
    setLoading('email-breach-btn', true);
    try {
      const data = await fetchJSON('/api/tools/email-breach?email=' + encodeURIComponent(email));
      let html = '<span class="label">Breach Check: ' + escapeHtml(email) + '</span>\n\n';
      if (data.error) {
        html += '<span class="bad">' + escapeHtml(data.error) + '</span>\n';
      } else if (data.breaches && data.breaches.length > 0) {
        html += '<span class="bad">⚠ Found in ' + data.breaches.length + ' breach(es)</span>\n\n';
        for (const b of data.breaches) {
          html += '<span class="label">' + escapeHtml(b.Name || b.name || 'Unknown') + '</span>';
          if (b.BreachDate || b.breachDate) html += '  <span class="muted">(' + escapeHtml(b.BreachDate || b.breachDate) + ')</span>';
          html += '\n';
          if (b.Domain || b.domain) html += '  Domain: ' + escapeHtml(b.Domain || b.domain) + '\n';
          if (b.DataClasses || b.dataClasses) html += '  Data: ' + (b.DataClasses || b.dataClasses).map(d => escapeHtml(d)).join(', ') + '\n';
          html += '\n';
        }
      } else {
        html += '<span class="ok">✓ Not found in any known breaches</span>\n\n';
        html += '<span class="muted">This email was not found in the Have I Been Pwned database.</span>\n';
      }
      showResult('email-breach-result', html);
    } catch (e) {
      showResult('email-breach-result', '<span class="bad">Error: ' + escapeHtml(e.message) + '</span>');
    }
    setLoading('email-breach-btn', false);
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();
  fetchPublicSettings();
  fetchVisitorIp();
  setupHeadersTool();
  setupDnsTool();
  setupHashTool();
  setupIpTool();
  setupPortsTool();
  setupPasswordTool();
  setupEmailBreachTool();
});
