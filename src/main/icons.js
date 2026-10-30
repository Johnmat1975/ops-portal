// Inspector icons, as Liongard's Asset Inventory shows them. The inspector catalogue gives each inspector's icon URL on
// Liongard's static image host; each is downloaded once, kept in the app's data folder and handed to the pages as a
// data: URI (the pages may not load images from the internet). Only that host, only images, only small files.
const fs = require('node:fs');

const HOST = 'resources.static.liongard.com';
const MAX = 200 * 1024;

function okUrl(u) {
  try { const x = new URL(u); return x.protocol === 'https:' && x.host === HOST && /\.(png|svg|jpe?g|webp)$/i.test(x.pathname); } catch { return false; }
}

// Liongard's current icons (as in Asset Inventory) live at images/lightmode/inspector-icons/<alias-slug>.png; the catalogue's
// own Icon/Logo URLs are older and some are missing or wrong (Huntress 404s; Automate points at ConnectWise Manage's icon).
const slugUrl = alias => `https://${HOST}/images/lightmode/inspector-icons/${String(alias).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}.png`;

// catalogue: [{ alias, url }]. Tries the current icon first, then the catalogue's. Downloads what's missing; never throws.
async function ensureIcons(file, catalogue) {
  let store = {};
  try { store = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
  const want = catalogue.filter(c => c.alias).map(c => ({ alias: c.alias, urls: [slugUrl(c.alias), c.url].filter(okUrl) }));
  const todo = want.filter(c => c.urls.length && (!store[c.alias] || !c.urls.includes(store[c.alias].url)));
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(6, todo.length) }, async () => {
    while (i < todo.length) {
      const c = todo[i++];
      for (const url of c.urls) {
        try {
          const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
          const type = (res.headers.get('content-type') || '').split(';')[0];
          if (!res.ok || !/^image\/(png|svg\+xml|jpeg|webp)$/.test(type)) continue;
          const buf = Buffer.from(await res.arrayBuffer());
          if (buf.length > MAX) continue;
          store[c.alias] = { url, data: `data:${type};base64,${buf.toString('base64')}` };
          break;
        } catch { /* offline or blocked: try the next, or the page just shows the name */ }
      }
    }
  }));
  if (todo.length) { const t = `${file}.tmp`; fs.writeFileSync(t, JSON.stringify(store), { mode: 0o600 }); fs.renameSync(t, file); }
  return store;
}

// { "lower-case alias": data URI } for the pages.
function iconMap(file) {
  try { return Object.fromEntries(Object.entries(JSON.parse(fs.readFileSync(file, 'utf8'))).map(([a, v]) => [a.toLowerCase(), v.data])); } catch { return {}; }
}

module.exports = { ensureIcons, iconMap, okUrl, slugUrl };
