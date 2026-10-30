// Inspector health: every launchpoint, when it last produced a dataprint, and whether its last attempt failed.
// Freshness is judged against each launchpoint's own schedule, so a weekly inspector isn't "stale" after 2 days.
const DAY = 864e5;
const { profileOf, capLabel } = require('../stack-catalog');
const FAIL = /fail|timeout|issue|error|not triggered/i;
const CATS = { cloud: 'Cloud', network: 'Network', appservices: 'App services', endpoint: 'Endpoint', endpoints: 'Endpoint', identity: 'Cloud' };

async function collect(api, env) {
  return { environment: env, rows: await api.systems(env.ID) };
}

function everyDays(f) {
  const n = +f.interval || 1;
  switch (String(f.type || '').toLowerCase()) {
    case 'minutes': return n / 1440;
    case 'hours': return n / 24;
    case 'weeks': return n * 7;
    case 'months': return n * 30;
    default: return n;
  }
}

function compute(input) {
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const age = iso => iso ? (now - new Date(iso)) / DAY : null;
  const rows = input.rows.map(r => {
    const unscheduled = r.scheduled === false || String((r.freq || {}).type).toLowerCase() === 'once';
    const every = unscheduled ? 1 : everyDays(r.freq || {});   // unscheduled: judge against Liongard's daily default
    const a = age(r.inspectedOn);
    const att = r.lastAttempt;
    const attemptFailed = att && FAIL.test(att.status || '') && (!r.inspectedOn || new Date(att.at) > new Date(r.inspectedOn));
    let health;
    const notActivated = /discovered|archived/i.test(r.status || '');
    const queued = !r.inspectedOn && att && /scheduled|running|processing/i.test(att.status || '');
    if (!r.enabled || notActivated) health = 'Inactive';
    else if (queued) health = 'Due';
    else if (!r.inspectedOn) health = 'Failing';   // ran but never produced a dataprint, or never ran
    else if (attemptFailed || FAIL.test(r.status || '')) health = 'Failing';
    else if (a > 2 * every + 1) health = 'Stale';
    else if (a > every + 1) health = 'Due';
    else health = 'Fresh';
    const why = !r.enabled ? 'Monitoring switched off; data is frozen at the last inspection'
      : notActivated ? 'Found by discovery but never activated'
      : queued ? `First run is queued (${att.status.toLowerCase()})`
      : !r.inspectedOn ? (att ? `Ran but never produced a dataprint (last attempt: ${att.status})` : 'Has never run')
      : health === 'Failing' ? `Last attempt ${att ? `${fmt(att.at)}: ${att.status}${att.message ? ` (${att.message.slice(0, 80)})` : ''}` : `status ${r.status}`}`
      : health === 'Stale' || health === 'Due' ? `${unscheduled ? 'Not on a schedule' : `Runs every ${label(r.freq)}`}, last good data ${Math.floor(a)} days ago` : unscheduled ? 'Not on a schedule. Only updates when someone runs it' : '';
    return {
      lpId: r.lpId, inspectorId: r.inspectorId, systemId: r.systemId, systemDetailId: r.systemDetailId, name: r.name, inspector: r.inspector,
      category: capLabel(profileOf(r.inspector, r.category).caps[0]) || CATS[String(r.category || '').toLowerCase()] || cap(r.category) || 'Other',
      every: unscheduled ? 'Not scheduled' : label(r.freq), unscheduled, lastGood: r.inspectedOn, days: a == null ? null : Math.floor(a), lastStatus: att ? att.status : r.status, health, why,
    };
  });

  const order = { Failing: 0, Stale: 1, Due: 2, Fresh: 3, Inactive: 4 };
  rows.sort((x, y) => order[x.health] - order[y.health] || (y.days ?? 1e9) - (x.days ?? 1e9) || x.name.localeCompare(y.name));
  const n = h => rows.filter(r => r.health === h).length;
  const live = rows.filter(r => r.health !== 'Inactive');
  const unschedCount = live.filter(r => r.unscheduled).length;

  // Attention list: failing first, then groups of stale inspectors that stopped at the same moment (a shared agent or schedule).
  const attention = rows.filter(r => r.health === 'Failing').map(r => ({ sev: 'bad', t: `${r.name} is failing.`, d: r.why }));
  const staleGroups = new Map();
  for (const r of rows.filter(r => r.health === 'Stale' && r.lastGood)) { const k = r.lastGood.slice(0, 13); staleGroups.set(k, [...(staleGroups.get(k) || []), r]); }
  for (const [, g] of [...staleGroups].sort((a, b) => b[1].length - a[1].length)) {
    if (g.length >= 3) attention.push({ sev: 'warn', t: `${g.length} inspectors all stopped at ${fmt(g[0].lastGood, true)}.`, d: `They share a schedule or agent, so check that first. ${g.slice(0, 4).map(r => r.name).join(', ')}${g.length > 4 ? ` and ${g.length - 4} more` : ''}.` });
    else for (const r of g) attention.push({ sev: 'warn', t: `${r.name} is stale.`, d: r.why });
  }
  const unsched = rows.filter(r => r.unscheduled && r.health !== 'Inactive');
  if (unsched.length) attention.splice(attention.filter(a => a.sev === 'bad').length, 0, { sev: unsched.length >= live.length / 2 ? 'bad' : 'warn',
    t: `${unsched.length} of ${live.length} launchpoints aren\u2019t on a schedule.`, d: 'They only update when someone runs them by hand, so their data goes stale without any alert. Set them to run daily.' });
  const dis = rows.filter(r => r.health === 'Inactive');
  if (dis.length) attention.push({ sev: 'warn', t: `${dis.length} launchpoint${dis.length > 1 ? 's are' : ' is'} disabled or not activated.`, d: `${dis.slice(0, 4).map(r => r.name).join(', ')}${dis.length > 4 ? ' and more' : ''}. Their data won't update.` });

  const cats = [...new Set(live.map(r => r.category))].sort().map(c => {
    const g = live.filter(r => r.category === c);
    return { c, n: g.length, fresh: g.filter(r => r.health === 'Fresh').length, due: g.filter(r => r.health === 'Due' || r.health === 'Stale').length, fail: g.filter(r => r.health === 'Failing').length };
  });

  const fail = rows.filter(r => r.health === 'Failing'), staleR = rows.filter(r => r.health === 'Stale');
  const summary = [
    `${live.length} launchpoints across ${new Set(live.map(r => r.inspector)).size} inspector types; ${n('Fresh')} have fresh data.`,
    fail.length ? `${fail.length} failing: ${fail.slice(0, 4).map(r => r.name).join(', ')}${fail.length > 4 ? ' and more' : ''}. Every page built on their data is out of date.` : 'Nothing is failing.',
    staleR.length ? `${staleR.length} stale (no good data for over two scheduled runs).` : '',
    unschedCount ? `${unschedCount} aren\u2019t on a schedule, so they only update when someone runs them.` : '',
  ].filter(Boolean);
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, summary,
    kpis: [
      { k: 'Systems monitored', v: live.length, s: `by ${new Set(live.map(r => r.inspector)).size} inspectors${dis.length ? `, plus ${dis.length} inactive` : ''}`, sev: 'info' },
      { k: 'Fresh', v: n('Fresh'), s: 'Good data within the expected interval', sev: 'ok' },
      { k: 'Due or stale', v: n('Due') + n('Stale'), s: 'Last good data is older than expected', sev: n('Due') + n('Stale') ? 'warn' : 'ok' },
      { k: 'Failing', v: n('Failing'), s: n('Failing') ? 'Last attempt failed or never inspected' : 'None', sev: n('Failing') ? 'bad' : 'ok' },
      { k: 'Not scheduled', v: unschedCount, s: unschedCount ? 'Only update when run by hand' : 'All on a schedule', sev: unschedCount ? 'warn' : 'ok' },
    ],
    attention, cats, rows,
  };
}

function label(f) { const n = +f.interval || 1, t = String(f.type || 'days').replace(/s$/, ''); return n === 1 ? t : `${n} ${t}s`; }
function fmt(iso, time) { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleString('en-GB', { day: 'numeric', month: 'short', ...(time ? { hour: '2-digit', minute: '2-digit' } : {}), timeZone: 'UTC' }) + (time ? ' UTC' : ''); }
function cap(s) { s = String(s || ''); return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }

module.exports = { id: 'inspectors', collect, compute };
