// helper to run updateCveHistoryFromSource with an env-set API key
// usage: set NVD_API_KEY env var or edit below, then `node scripts/run_update.js`
if (!process.env.NVD_API_KEY) {
  console.error('ERR: NVD_API_KEY not set in environment');
  process.exit(2);
}
const s = require('../server.js');
(async () => {
  try {
    const res = await s.updateCveHistoryFromSource();
    console.log('OK', JSON.stringify(res || [], null, 2));
    process.exit(0);
  } catch (e) {
    console.error('ERR', e && e.message);
    process.exit(1);
  }
})();
