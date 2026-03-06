const path = require('path');
const srv = require(path.join('..', 'server.js'));

(async () => {
  try {
    console.log('Triggering CVE history update...');
    const res = await srv.updateCveHistoryFromSource();
    if (res && res.length) console.log('Updated CVE history entries:', res.length);
    else console.log('Update returned no data.');
    process.exit(0);
  } catch (e) {
    console.error('Update failed', e && e.message);
    process.exit(2);
  }
})();
