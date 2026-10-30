// Input checks for IPC handlers. Pure functions, so they're testable without Electron.

// A client picked in the renderer (switcher, Settings › Clients): a positive integer ID and a bounded name.
function envChoice(env) {
  const id = +(env && env.ID);
  if (!Number.isInteger(id) || id <= 0 || id > 1e9) throw new Error('Bad request.');
  return { ID: id, Name: String((env && env.Name) ?? '').slice(0, 200) };
}

// A seat price as typed: "12.50", "12,50", "1 234,50", "1,234.50", "€18". Returns a number, or null if it isn't one.
// Keep in step with parsePrice in src/renderer/shared.js.
function parsePrice(v) {
  if (typeof v === 'number') return Number.isFinite(v) && v >= 0 ? v : null;
  let s = String(v ?? '').replace(/[\s £€$]/g, '');
  if (!s) return null;
  s = s.replace(/,(?=\d{1,2}$)/, '.');               // decimal comma: 12,50
  s = s.replace(/[.,](?=\d{3}(\D|$))/g, '');          // thousands separators: 1.234 / 1,234
  return /^\d+(\.\d{1,4})?$/.test(s) ? +s : null;
}

// The MSP-wide price list: product name → number. Rejects bad entries instead of silently dropping or truncating them.
const MAX_PRICES = 1000;
function priceList(p) {
  const out = {};
  const entries = Object.entries(p || {});
  if (entries.length > MAX_PRICES) throw new Error(`Too many prices (${entries.length}); the limit is ${MAX_PRICES}.`);
  for (const [k0, v] of entries) {
    const k = String(k0).trim();
    if (!k) continue;
    if (k.length > 120) throw new Error('A product name is too long for the price list.');
    if (v === '' || v == null) continue;
    const n = parsePrice(v);
    if (n == null) throw new Error(`The price for ${k} isn’t a number. Use a number like 12.50.`);
    out[k] = n;
  }
  return out;
}

module.exports = { envChoice, parsePrice, priceList, MAX_PRICES };
