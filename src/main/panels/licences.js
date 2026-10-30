// Licence reconciliation panel: collect from the API, then apply licences-rules.js.
// Devices come from Stack coverage's rules (any RMM, EDR and backup vendor), so "not managed" means the same on both pages.
const QUERIES = require('./licences-queries');
const rules = require('./licences-rules');
const coverage = require('./coverage');
const identity = require('./identity');
const perPerson = require('./licences-people');
const seats = require('./licences-seats');

async function collect(api, env, have = {}) {
  const cov = have.cov ? Promise.resolve(have.cov) : coverage.collect(api, env).catch(e => ({ error: e.message }));
  // Identity: who each person is and which devices they use, for the per-person view.
  const id = have.id ? Promise.resolve(have.id) : identity.collect(api, env).catch(e => ({ error: e.message }));
  const sys = await api.systems(env.ID);
  const systems = {}, data = {}, missing = [];
  for (const [alias, q] of Object.entries(QUERIES)) {
    const s = sys.find(x => x.enabled && x.inspector === alias && x.systemDetailId);
    if (!s) { missing.push(alias); continue; }
    systems[alias] = { systemId: s.systemId, systemDetailId: s.systemDetailId, inspectedOn: s.inspectedOn };
    data[q.key] = await api.evaluate(s.systemDetailId, q.query);
  }
  // Seats in use (and purchased, where the data has it) for every other inspector this client runs (licences-seats.js).
  const seatData = await seats.collect(api, sys).catch(() => ({}));
  const dates = Object.values(systems).map(s => s.inspectedOn).filter(Boolean).sort();
  return { environment: env, inspectedOn: dates[dates.length - 1] || null, systems, data, missing, cov: await cov, id: await id, seatData };
}

function compute(input) {
  const base = withSeats(rules.compute(input), input);
  const m = withPeople(base, input, null);
  const cv = input.cov && !input.cov.error ? (() => { try { return coverage.compute({ ...input.cov, pulledOn: input.pulledOn, stack: input.stack, policy: input.coveragePolicy, thresholds: input.thresholds }); } catch { return null; } })() : null;
  if (!cv) return m;
  const mp = withPeople(base, input, cv);
  const names = list => (list || []).map(x => x.name || x).filter(Boolean);
  const cell = (k, list) => ({ k: k === 'warn' ? 'warn' : k === 'ok' ? 'ok' : k === 'bad' ? 'bad' : 'none', last: names(list).join(', ') });
  const endpoints = cv.rows.filter(r => (r.kind === 'Server' || r.kind === 'Workstation') && !r.stale);
  const unmanaged = new Set(cv.unmanaged.map(r => r.id));
  const devices = endpoints.map(r => ({ name: r.host, id: r.id, os: r.os, eos: r.eos, unmanaged: unmanaged.has(r.id),
    cells: { rmm: cell(r.tools.rmm, r.rmm), edr: cell(r.tools.edr, r.products), backup: cell(r.tools.backup, r.backups), tl: { k: 'none' } },
    note: unmanaged.has(r.id) ? 'No RMM or EDR manages it' : (r.notes || []).filter(n => /edr|av|rmm|backup|agent/i.test(n))[0] || '' }))
    .sort((a, b) => (b.unmanaged - a.unmanaged) || (a.note ? 0 : 1) - (b.note ? 0 : 1) || a.name.localeCompare(b.name));
  // Phones billed in ThreatLocker stay, from the licence rules.
  const phones = m.devices.filter(d => d.mobile).map(d => ({ ...d, cells: { rmm: { k: 'none' }, edr: { k: 'none' }, backup: { k: 'none' }, tl: d.cells.tl } }));
  const notManaged = cv.unmanaged.filter(r => !r.stale);
  const kpis = m.kpis.map(k => k.k !== 'Devices outside RMM and EDR' ? k
    : { k: 'Devices not managed', v: notManaged.length, s: notManaged.length ? 'No RMM or EDR. Same devices as “Not managed” on Stack coverage' : 'Every device has RMM or EDR', sev: notManaged.length ? 'bad' : 'ok' });   // same severity as Coverage's "Not managed"
  const actions = m.actions.filter(a => !/no RMM or EDR/.test(a.b));
  if (notManaged.length) actions.push({ sev: 'warn', a: `Decide what to do with ${notManaged.slice(0, 6).map(r => r.host).join(', ')}${notManaged.length > 6 ? ` and ${notManaged.length - 6} more` : ''}.`, b: 'Liongard sees them, but no RMM or EDR manages them: enrol them or retire them.' });
  return { ...mp, kpis, actions, devices: [...devices, ...phones], unmanaged: notManaged.map(r => ({ name: r.host, id: r.id, os: r.os, seenBy: r.seenBy })), deviceSource: 'coverage' };
}

// Rows for the client's other inspectors, found automatically, after the ones the licence rules reconcile in detail.
function withSeats(m, input) {
  const auto = seats.rows(input.seatData);
  if (!auto.length) return m;
  const systems = { ...m.systems };
  for (const r of auto) if (!systems[r.source]) { const x = (input.seatData || {})[r.systemId] || {}; systems[r.source] = { systemId: r.systemId, systemDetailId: x.systemDetailId, inspectedOn: x.inspectedOn }; }
  return { ...m, subs: [...m.subs, ...auto], systems };
}

// Every seat and device product tied to each person (the per-person view). Identity is computed with the same settings
// as the Identity page, so the people and their devices match it.
function withPeople(m, input, cv) {
  // idState: whether Identity (people and their devices) is loaded. A 0.5 cache has no id; say so rather than guess.
  const idState = !input.id ? 'missing' : input.id.error ? 'error' : 'ok';
  let id = null;
  if (idState === 'ok') { try { id = identity.compute({ ...input.id, pulledOn: input.pulledOn, stack: input.stack, msp: input.msp, thresholds: input.thresholds }); } catch { id = null; } }
  const pp = perPerson.build({ data: input.data, subs: m.subs, id, cov: cv, idState: idState === 'ok' && !id ? 'error' : idState });
  if (input.id && input.id.error) pp.idError = String(input.id.error).slice(0, 200);
  return { ...m, perPerson: pp };
}

module.exports = { id: 'licences', usesStack: true, collect, compute };
