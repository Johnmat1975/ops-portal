// Seats per product, for every inspector a client runs. The catalogue (seat-catalog.json) says, for each Liongard
// inspector, what the vendor bills on (user, device, mailbox…) and which query on the inspector's latest dataprint
// counts the units in use and, where the data has it, the units purchased. Each query is the one behind a Liongard
// metric, reviewed and tested per inspector, so it works whether or not the MSP has that metric switched on.
// Rows appear by themselves when a client adds a tool and go when it's removed: nothing to set up per client.
const CATALOG = require('../seat-catalog.json');

// Inspectors the licence rules already reconcile in detail (their rows come from licences-rules.js).
const DETAILED = new Set(['Microsoft 365', 'KnowBe4', 'Duo Security', 'ThreatLocker', 'NinjaOne', 'CrowdStrike EDR', 'Anthropic', 'Active Directory']);

const billable = def => def && def.unit && def.unit !== 'none' && def.used && def.used.q;
const queryFor = def => `{u: ${def.used.q}${def.purchased && def.purchased.q ? `, p: ${def.purchased.q}` : ''}}`;

// One read-only query per system of an inspector in the catalogue; a system that can't be read is skipped (the row says so).
async function collect(api, systems) {
  const out = {};
  const todo = systems.filter(s => s.enabled && s.systemDetailId && !DETAILED.has(s.inspector) && billable(CATALOG[s.inspector]));
  await Promise.all(todo.map(async s => {
    try { out[s.systemId] = { inspector: s.inspector, name: s.name, systemDetailId: s.systemDetailId, inspectedOn: s.inspectedOn, r: await api.evaluate(s.systemDetailId, queryFor(CATALOG[s.inspector])) }; }
    catch (e) { out[s.systemId] = { inspector: s.inspector, name: s.name, systemDetailId: s.systemDetailId, error: String(e.message || e).slice(0, 160) }; }
  }));
  return out;
}

// A count from a query result: a number, a numeric string, or a list (its length).
function count(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number') return Number.isFinite(v) && v >= 0 ? Math.round(v) : null;
  if (Array.isArray(v)) return v.filter(x => x != null && x !== '').length;
  if (typeof v === 'string' && /^\s*\d+(\.\d+)?\s*$/.test(v)) return Math.round(+v);
  return null;
}

// Subscriptions rows: one per inspector (systems of the same inspector are added up), in the same shape licences-rules.js uses.
function rows(seatData = {}) {
  const by = new Map();
  for (const [systemId, x] of Object.entries(seatData)) {
    const def = CATALOG[x.inspector]; if (!billable(def)) continue;
    const g = by.get(x.inspector) || by.set(x.inspector, { def, systems: [], use: 0, buy: 0, buyKnown: 0, read: 0, failed: [] }).get(x.inspector);
    g.systems.push({ systemId: +systemId, name: x.name });
    if (x.error || !x.r) { g.failed.push(x.name); continue; }
    const u = count(x.r.u), p = count(x.r.p);
    if (u != null) { g.use += u; g.read++; }
    if (p != null) { g.buy += p; g.buyKnown++; }
  }
  return [...by.entries()].map(([inspector, g]) => {
    const { def } = g, unit = def.unit;
    const buy = g.buyKnown ? g.buy : null, use = g.read ? g.use : null;
    const units = n => `${n} ${unit}${n === 1 ? '' : 's'}`;
    const bits = [];
    if (use == null) bits.push(g.failed.length ? 'Couldn’t read it from Liongard' : 'No count in the latest data');
    else if (buy == null) bits.push(`${units(use)} in use. Purchased isn’t in Liongard’s data`);
    else if (buy > use) bits.push(`${buy - use} spare`);
    else if (buy < use) bits.push(`Over by ${use - buy}`);
    else bits.push('Fully used');
    if (g.systems.length > 1) bits.push(`Added up across ${g.systems.length} systems`);
    if (g.failed.length && use != null) bits.push(`${g.failed.join(', ')} couldn’t be read`);
    if (def.caveat) bits.push(def.caveat);   // the short note for MSPs (the reviewer's research note stays in the catalogue)
    const sev = use == null ? 'warn' : buy == null ? 'none' : buy < use ? 'bad' : buy > use ? 'warn' : 'ok';
    return { product: def.product || inspector, source: inspector, buy, use: use ?? '–', unit, sev, note: bits.join('. '), auto: true,
      systemId: g.systems[0].systemId, how: def.used.metric || null };
  }).sort((a, b) => a.product.localeCompare(b.product));
}

module.exports = { CATALOG, DETAILED, collect, rows, count, queryFor };
