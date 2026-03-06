const fetch = require('node-fetch');
async function one(url, headers) {
  try {
    console.log('\nRequest:', url);
    console.log('Headers:', headers);
    const r = await fetch(url, { headers, timeout: 20000 });
    console.log('Status:', r.status);
    const txt = await r.text();
    console.log('Body (first 800 chars):\n', txt.slice(0,800));
  } catch (e) {
    console.error('Error:', e && e.message);
  }
}

(async () => {
  const base = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1';
  await one(base, { 'User-Agent': 'CVE-direct-probe/1.0' });
  const key = process.env.NVD_API_KEY || '<no-key-set>';
  await one(base, { 'User-Agent': 'CVE-direct-probe/1.0', 'apiKey': key });
  // also try a simpler URL variant
  const simple = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  await one(simple, { 'User-Agent': 'CVE-direct-probe/1.0', 'apiKey': key });
})();
