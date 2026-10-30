// Wallboard: open alerts grouped by type, inspector health and external exposure, for a service-desk screen.
// Reuses the Inspector health and Email panels' rules so the numbers always agree with those pages.
const inspectors = require('./inspectors');
const email = require('./email');

// One failed call no longer takes the whole wallboard down: each part becomes { error } and shows as "no data".
async function collect(api, env, have = {}) {
  const safe = p => p.catch(e => ({ error: e.message }));
  const [alerts, insp, mail] = await Promise.all([safe(api.alerts(env.ID)), have.insp || safe(inspectors.collect(api, env)), have.mail || safe(email.collect(api, env))]);
  return {
    environment: env, insp, mail,
    alerts: !Array.isArray(alerts) ? alerts : alerts.map(a => ({ id: a.ID, name: a.Name, priority: a.Priority && a.Priority.Name, status: a.Status && a.Status.Name, inspector: a.Inspector && a.Inspector.Alias, created: a.CreatedOn })),
  };
}

const PRI = ['Critical', 'High', 'Medium', 'Low'];

function compute(input) {
  // A part that couldn't be read shows as unknown (—), never as a reassuring zero.
  const alertsOk = Array.isArray(input.alerts);
  const open = (alertsOk ? input.alerts : []).filter(a => !/clos|resolv|complete|silenc/i.test(a.status || ''));
  // "Rule | detail | "target"" -> group by everything except the quoted target.
  const groups = new Map();
  for (const a of open) {
    const target = (/"([^"]+)"\s*$/.exec(a.name || '') || [])[1] || '';
    const title = String(a.name || '').replace(/\s*\|\s*"[^"]*"\s*$/, '').replace(/^[^|]+\|\s*/, '') || a.name;
    const k = `${a.priority}|${title}`;
    const g = groups.get(k) || { title, priority: a.priority || 'Medium', inspector: a.inspector, targets: [], newest: a.created, oldest: a.created, ids: [] };
    if (target) g.targets.push(target); g.newest = g.newest > a.created ? g.newest : a.created; g.oldest = g.oldest < a.created ? g.oldest : a.created; g.ids.push(a.id);
    groups.set(k, g);
  }
  const alertGroups = [...groups.values()].map(g => ({ ...g, count: Math.max(1, g.targets.length), targets: [...new Set(g.targets)] }))
    .sort((a, b) => PRI.indexOf(a.priority) - PRI.indexOf(b.priority) || b.count - a.count);
  const byPri = Object.fromEntries(PRI.map(p => [p, open.filter(a => a.priority === p).length]));

  const tryCompute = (fn, part) => { if (!part || part.error) return null; try { return fn({ ...part, pulledOn: input.pulledOn }); } catch { return null; } };
  const ih = tryCompute(inspectors.compute, input.insp) || { rows: [] }, ihOk = !!(input.insp && !input.insp.error && ih.rows.length);
  const em = tryCompute(email.compute, input.mail) || { domains: [] }, emOk = !!(input.mail && !input.mail.error);
  const unknown = (k, why) => ({ k, v: '—', s: why, sev: 'info' });
  const live = ih.rows.filter(r => r.health !== 'Inactive');
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source,
    kpis: [
      alertsOk ? { k: 'Open alerts', v: open.length, s: PRI.filter(p => byPri[p]).length ? `Liongard priority: ${PRI.filter(p => byPri[p]).map(p => `${byPri[p]} ${p.toLowerCase()}`).join(' · ')}` : 'None', sev: byPri.Critical ? 'bad' : open.length ? 'warn' : 'ok' } : unknown('Open alerts', 'Couldn’t read alerts from Liongard'),
      ihOk ? { k: 'Systems failing', v: live.filter(r => r.health === 'Failing').length, s: `of ${live.length} monitored`, sev: live.some(r => r.health === 'Failing') ? 'bad' : 'ok' } : unknown('Systems failing', 'Couldn’t read inspector health'),
      ihOk ? { k: 'Systems stale', v: live.filter(r => r.health === 'Stale' || r.health === 'Due').length, s: `${live.filter(r => r.unscheduled).length} not on a schedule`, sev: live.some(r => r.health === 'Stale') ? 'warn' : 'ok' } : unknown('Systems stale', 'Couldn’t read inspector health'),
      emOk ? { k: 'Domains that can be spoofed', v: em.domains.filter(d => d.spoofable).length, s: `of ${em.domains.length} domains`, sev: em.domains.some(d => d.spoofable) ? 'bad' : 'ok' } : unknown('Domains that can be spoofed', 'Couldn’t read domain data'),
    ],
    alertGroups,
    // Every open alert, so the Open alerts drill-down lists exactly what the tile counts.
    openAlerts: open.map(a => ({ id: a.id, name: a.name, priority: a.priority, inspector: a.inspector, created: a.created })).sort((a, b) => PRI.indexOf(a.priority) - PRI.indexOf(b.priority) || String(b.created).localeCompare(String(a.created))),
    // Problems reported by every other inspector (Liongard metrics), worst first.
    problems: (input.stack ? input.stack.findings.filter(f => f.sev === 'bad' && !f.old) : []).slice(0, 30).map(f => ({ label: f.label, value: f.value, system: f.system, inspector: f.inspector, systemId: f.systemId, systemDetailId: f.systemDetailId })),
    health: ['Fresh', 'Due', 'Stale', 'Failing'].map(h => ({ h, n: live.filter(r => r.health === h).length })),
    failing: live.filter(r => r.health === 'Failing').map(r => ({ name: r.name, why: r.why, inspector: r.inspector })),
    stale: live.filter(r => r.health === 'Stale' || r.health === 'Due').map(r => ({ name: r.name, why: r.why, health: r.health, inspector: r.inspector })),
    domains: em.domains.filter(d => d.spoofable || d.cert[0] !== 'pass' || (d.regDays != null && d.regDays <= 60) || /[CDF]/.test(d.grade)).map(d => ({ name: d.name, grade: d.grade, sys: d.sys, spoofable: d.spoofable, dmarc: d.dmarc[2], sends: d.sends, cert: d.cert[1], certState: d.cert[0], regExpires: d.regExpires, registrar: d.registrar })),
  };
}

module.exports = { id: 'wallboard', usesStack: true, collect, compute };
