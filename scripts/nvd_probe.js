const fetch = require('node-fetch');
(async () => {
  const key = process.env.NVD_API_KEY || '<no-key-set>';
  const headers = { 'User-Agent': 'CVE-dashboard-probe/1.0' };
  if (key && key !== '<no-key-set>') headers.apiKey = key;
  const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1';
  console.log('Probing NVD v2 URL:', url);
  try {
    const r = await fetch(url, { headers, timeout: 15000 });
    console.log('Status:', r.status);
    const txt = await r.text();
    console.log('Body (truncated 200 chars):', txt.slice(0,200));
  } catch (e) {
    console.error('Probe error:', e && e.message);
    process.exit(2);
  }
})();
