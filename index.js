const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const CIRCL_LAST = 'https://cve.circl.lu/api/last';

app.get('/api/cves', async (req, res) => {
  const count = parseInt(req.query.count || '50', 10);
  try {
    const r = await fetch(CIRCL_LAST);
    const data = await r.json();
    if (!Array.isArray(data)) return res.status(502).json({ error: 'unexpected response' });
    res.json(data.slice(0, count));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/zero-days', async (req, res) => {
  const count = parseInt(req.query.count || '200', 10);
  try {
    const r = await fetch(CIRCL_LAST);
    const data = await r.json();
    if (!Array.isArray(data)) return res.status(502).json({ error: 'unexpected response' });

    function extractSummary(item) {
      if (!item) return '';
      if (item.summary) return item.summary;
      if (item.description) return item.description;
      if (item.cveMetadata && (item.cveMetadata.description || item.cveMetadata.summary)) return item.cveMetadata.description || item.cveMetadata.summary || '';
      if (item.containers && item.containers.cna) {
        const cna = item.containers.cna;
        if (cna.descriptions && cna.descriptions.length) {
          const d = cna.descriptions[0];
          return d.value || d.description || d.text || '';
        }
        if (cna.descriptions && typeof cna.descriptions === 'string') return cna.descriptions;
        if (cna.title) return cna.title;
      }
      if (item.document && item.document.notes && item.document.notes.length) {
        const note = item.document.notes.find(n => n.category === 'summary') || item.document.notes[0];
        return (note && (note.text || note.title || note.summary)) || '';
      }
      return '';
    }

    const zeroDayRegex = /\bzero[- ]?day\b|\b0[- ]?day\b|zero\sday/i;
    const filtered = data.slice(0, count).filter(item => {
      const s = extractSummary(item) || '';
      return zeroDayRegex.test(s);
    });
    res.json(filtered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Simple RSS/Atom aggregator for IT/security news (same as in server.js)
app.get('/api/rss', async (req, res) => {
  const feeds = [
    'https://www.reddit.com/r/netsec/.rss',
    'https://www.schneier.com/blog/atom.xml',
    'https://www.zdnet.com/topic/security/rss.xml'
  ];
  const maxItems = parseInt(req.query.count || '30', 10);

  function parseFeedXml(xml) {
    const items = [];
    const itemMatches = xml.match(/<item[\s\S]*?<\/item>/gi);
    if (itemMatches) {
      itemMatches.forEach(block => {
        const title = (block.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '';
        const link = (block.match(/<link[^>]*>([\s\S]*?)<\/link>/i) || [])[1] || ((block.match(/<link[^>]*href="([^\"]+)"/i)||[])[1]||'');
        const pub = (block.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i) || [])[1] || (block.match(/<dc:date[^>]*>([\s\S]*?)<\/dc:date>/i)||[])[1] || '';
        items.push({ title: (title||'').trim(), link: (link||'').trim(), pubDate: (pub||'').trim() });
      });
    }
    const entryMatches = xml.match(/<entry[\s\S]*?<\/entry>/gi);
    if (entryMatches) {
      entryMatches.forEach(block => {
        const title = (block.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '';
        let link = '';
        const linkMatch = block.match(/<link[^>]*href=\"([^\"]+)\"/i);
        if (linkMatch) link = linkMatch[1];
        const updated = (block.match(/<updated[^>]*>([\s\S]*?)<\/updated>/i) || [])[1] || '';
        items.push({ title: (title||'').trim(), link: (link||'').trim(), updated: (updated||'').trim() });
      });
    }
    return items;
  }

  try {
    const all = [];
    for (const url of feeds) {
      try {
        const r = await fetch(url, { timeout: 10000 });
        const txt = await r.text();
        const parsed = parseFeedXml(txt);
        parsed.forEach(it => it.source = url);
        all.push(...parsed);
      } catch (e) {
        // ignore
      }
    }
    all.sort((a, b) => {
      const da = new Date(a.pubDate || a.updated || 0).getTime();
      const db = new Date(b.pubDate || b.updated || 0).getTime();
      return db - da;
    });
    res.json(all.slice(0, maxItems));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
