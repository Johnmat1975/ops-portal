// Change pulse: 90 days of configuration changes Liongard detected, by source, with before/after values.
// Routine churn (the same change on the same system most days, e.g. certificate SAN lists on a CDN) is flagged so it can be hidden.
const WINDOW_DAYS = 90;

async function collect(api, env) {
  const since = new Date(Date.now() - WINDOW_DAYS * 864e5).toISOString();
  const rows = await api.detections(env.ID, since);
  return {
    environment: env, since,
    detections: rows.map(d => ({ id: d.ID, at: d.CreatedOn, name: d.Name, inspector: d.Inspector && d.Inspector.Alias,
      system: d.System && d.System.Name, systemId: d.System && d.System.ID, systemDetailId: d.SystemDetail && d.SystemDetail.ID, patch: d.Patch || [] })),
  };
}

// Repeated items once with a count ("Workstation ×6"); bare punctuation dropped.
function counted(arr) {
  const m = new Map(); for (const x of arr) { const k = String(x).trim(); if (!k || /^[\s:;,.|-]+$/.test(k)) continue; m.set(k, (m.get(k) || 0) + 1); }
  return [...m].map(([k, n]) => n > 1 ? `${k} ×${n}` : k);
}

// jsdiff-style patch -> short before/after strings.
function diffText(patch, full = false) {
  const pick = f => patch.filter(f).map(p => String(p.value || '').replace(/[\s\[\]{}",]+/g, ' ').trim()).filter(Boolean).join(' · ');
  const cut = s => !full && s.length > 160 ? s.slice(0, 157) + '…' : s;
  return { before: cut(pick(p => p.removed)), after: cut(pick(p => p.added)) };
}

// A one-line, plain-English summary of what a change did, and whether it looks worse, better or neutral for security.
// Lists whose name describes a problem (no MFA, stale, expired…) are bad when they grow; admin lists are bad when they grow.
const PROBLEM_LIST = /\b(no|without|not|non|disabled|stale|inactive|missing|expired|expiring|risky|failed|failing|unprotected|unencrypted|guest|bypass|forward(ing)?|vulnerab\w*|outdated|unsupported|weak|exposed|blocked|locked)\b/i;
const ADMIN_LIST = /admin|privileg|owner|global|domain admins|enterprise admins|super ?user/i;
// What an item is, without the value that changed: "Policy - Last Modified Time - 2026-10-04T21:24:12" → "Policy";
// "Name: X, ID: 30, Subnet: …" → "Name: X".
const tail = x => {
  let t = String(x).replace(/\s*[-:|]\s*\d{4}-\d{2}-\d{2}([T ][\d:.]+Z?)?\s*$/, '').replace(/\s+[-:|]\s+last (modified|changed|updated)( time| date| on)?$/i, '');
  if (t === String(x) && t.includes(', ')) t = t.split(', ')[0];
  return t.trim();
};
const short = v => { const t = String(v); return t.length > 40 ? `${t.slice(0, 39)}…` : t; };
function summarize(name, dl, weakenings) {
  const plain = String(name).replace(/^[^|:]+[|:]\s*/, '');
  const parts = []; let tone = '';
  const weak = weakenings(dl.changed);
  if (weak.length) { parts.push(weak.map(w => `${w.label} (${w.text})`).join('; ')); tone = 'risk'; }
  // Items that appear on both sides once their last segment (a date or value) is dropped were edited, not added or removed.
  const rk = new Set(dl.removed.map(tail)), ak = new Set(dl.added.map(tail));
  const edited = [...ak].filter(k => rk.has(k) && k);
  const added = dl.added.filter(x => !edited.includes(tail(x))), removed = dl.removed.filter(x => !edited.includes(tail(x)));
  if (edited.length) parts.push(`${/gpo|group policy/i.test(plain) ? 'Group Policy edited' : 'Edited'}: ${edited.length <= 3 ? edited.join(', ') : `${edited.length} items`}`);
  if (added.length === 1 && removed.length === 1 && !edited.length) parts.push(`${short(removed[0])} → ${short(added[0])}`);   // one value swapped for another
  else if (added.length || removed.length) {
    const list = PROBLEM_LIST.test(plain) ? 'problem list' : ADMIN_LIST.test(plain) ? 'admin list' : '';
    const what = [added.length && `${added.length} added`, removed.length && `${removed.length} removed`].filter(Boolean).join(', ');
    if (list && added.length > removed.length) { parts.push(`${what} (this ${list} grew)`); tone = 'risk'; }
    else if (list && removed.length > added.length) { parts.push(`${what} (this ${list} shrank)`); tone = tone || 'better'; }
    else parts.push(what);
  }
  // Internal keys (_UniqueCompositeKey…) are counted but not named.
  const other = dl.changed.filter(c => !weak.some(w => w.text.startsWith(`${c.key} `)));
  const named = other.filter(c => !/^_/.test(c.key));
  if (other.length) parts.push(weak.length ? `${other.length} other setting${other.length === 1 ? '' : 's'} changed`
    : named.length && other.length <= 2 ? named.map(c => `${c.key} ${short(c.from)} → ${short(c.to)}`).join('; ') : `${other.length} setting${other.length === 1 ? '' : 's'} changed${named.length ? `: ${named.slice(0, 3).map(c => c.key).join(', ')}${named.length > 3 ? '…' : ''}` : ''}`);
  return { text: parts.join('. ') || 'Value changed', tone };
}

function compute(input) {
  const day = iso => String(iso).slice(0, 10);
  const dets = input.detections.map(d => ({ ...d, day: day(d.at), source: d.system || d.inspector || 'Unknown', ...diffText(d.patch || []) }));
  const days = new Set(dets.map(d => d.day)).size || 1;

  // Routine: one system + change name seen on at least 30% of active days and at least 10 times.
  const pairs = new Map();
  for (const d of dets) { const k = `${d.source}\u0000${d.name}`; const p = pairs.get(k) || { n: 0, days: new Set() }; p.n++; p.days.add(d.day); pairs.set(k, p); }
  const routineKeys = new Set([...pairs].filter(([, p]) => p.n >= 10 && p.days.size / days >= 0.3).map(([k]) => k));
  for (const d of dets) d.routine = routineKeys.has(`${d.source}\u0000${d.name}`);

  const sources = [...new Set(dets.map(d => d.source))].map(s => {
    const g = dets.filter(d => d.source === s);
    // The system's Liongard IDs (newest change's), so its name can open the system in Liongard.
    const latest = [...g].sort((a, b) => String(b.at).localeCompare(String(a.at)))[0];
    return { source: s, inspector: g[0].inspector, systemId: latest.systemId, systemDetailId: latest.systemDetailId, total: g.length, routine: g.filter(d => d.routine).length,
      byDay: Object.entries(g.reduce((a, d) => (a[d.day] = (a[d.day] || 0) + 1, a), {})).map(([dd, n]) => ({ day: dd, n, routine: g.filter(x => x.day === dd).every(x => x.routine) })) };
  }).sort((a, b) => (b.total - b.routine) - (a.total - a.routine) || b.total - a.total);

  // What each change did (shared with Cyber security); countdowns and counters are routine too.
  const { delta, weakenings } = require('./cyber');   // required here, not at the top: cyber.js requires this file
  for (const d of dets) { d.delta = delta(d.patch || []); d.summary = summarize(d.name, d.delta, weakenings); if (d.delta.counterOnly && !/gpo|group policy/i.test(d.name) && !weakenings(d.delta.changed).length) d.routine = true; }
  // Recount each system now that counter-only changes are marked routine too, so "Busiest system" matches its list.
  for (const x of sources) {
    const g = dets.filter(d => d.source === x.source);
    x.routine = g.filter(d => d.routine).length;
    // Per day: all changes (n) and the real ones (real), so a day with both isn't counted all-routine or all-real.
    const by = {};
    for (const d of g) { const b = by[d.day] || (by[d.day] = { day: d.day, n: 0, real: 0 }); b.n++; if (!d.routine) b.real++; }
    x.byDay = Object.values(by).map(b => ({ ...b, routine: !b.real })).sort((a, b) => a.day.localeCompare(b.day));
  }
  sources.sort((a, b) => (b.total - b.routine) - (a.total - a.routine) || b.total - a.total);
  const real = dets.filter(d => !d.routine).sort((a, b) => b.at.localeCompare(a.at));
  // Only whole change types that recur count as routine sources (Cyber security filters on these); a single counter-only
  // change is hidden here without hiding real changes of the same type.
  const routineSources = [...new Set(dets.filter(d => routineKeys.has(`${d.source}\u0000${d.name}`)).map(d => `${d.source}: ${d.name}`))];
  const last7 = real.filter(d => (new Date(input.pulledOn || Date.now()) - new Date(d.at)) / 864e5 <= 7).length;
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, since: input.since, windowDays: WINDOW_DAYS,
    kpis: [
      { k: `Changes in ${WINDOW_DAYS} days`, v: dets.length, s: `Across ${sources.length} systems`, sev: 'info' },
      { k: 'Excluding routine churn', v: real.length, s: routineSources.length ? `${dets.length - real.length} routine changes hidden` : 'No routine churn found', sev: 'info' },
      { k: 'Last 7 days', v: last7, s: last7 ? 'Non-routine changes this week' : 'Quiet week', sev: 'info' },
      { k: 'Busiest system', v: sources[0] ? sources[0].total - sources[0].routine : 0, s: sources[0] ? sources[0].source : '—', sev: 'info' },
    ],
    sources, routineSources,
    // Every change behind the first tile (routine ones marked), so its drill-down lists exactly what it counts.
    all: dets.map(d => ({ at: d.at, day: d.day, source: d.source, name: d.name, routine: !!d.routine, summary: d.summary, systemId: d.systemId, systemDetailId: d.systemDetailId })).sort((a, b) => String(b.at).localeCompare(String(a.at))),
    feed: real.slice(0, 500).map(d => ({ at: d.at, source: d.source, inspector: d.inspector, name: d.name, summary: d.summary, before: d.before, after: d.after, systemId: d.systemId, systemDetailId: d.systemDetailId,
      added: counted(d.delta.added).slice(0, 10), removed: counted(d.delta.removed).slice(0, 10), changed: d.delta.changed.slice(0, 8), more: Math.max(0, d.delta.added.length - 10) + Math.max(0, d.delta.removed.length - 10) })),
    summary: [
      `${real.length} real change${real.length === 1 ? '' : 's'} in ${WINDOW_DAYS} days across ${new Set(real.map(d => d.source)).size} systems${dets.length - real.length ? `, plus ${dets.length - real.length} routine ones hidden (counters, countdowns and daily churn)` : ''}.`,
      last7 ? `${last7} in the last 7 days; busiest system ${sources[0] ? sources[0].source : '—'}.` : 'A quiet week: no real changes in the last 7 days.',
      'Security-relevant changes, mapped to MITRE ATT&CK, are on the Cyber security page.',
    ],
  };
}

module.exports = { id: 'changes', collect, compute, diffText, summarize, WINDOW_DAYS };
