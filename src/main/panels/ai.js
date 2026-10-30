// AI usage: who uses Claude (and ChatGPT where an OpenAI inspector exists), API keys and their age, daily cost,
// and whether those people have MFA (Microsoft 365 / identity inventory) and Duo.
const ANTH_Q = '{users: Users[].{id: id, e: email, n: name, r: role, added: added_at}, ' +
  'keys: APIKeys[].{n: name, status: status, created: created_at, by: created_by.id, ws: workspace_id, expires: expires_at}, ' +
  'ws: Workspaces[].{id: id, n: name}, wsm: WorkspaceMembers[].{u: user_id, ws: workspace_id, r: workspace_role}, cost: OrgCostReport[].{d: starting_at, r: results[].AmountUSD}, ' +
  // Token usage per day (organisation totals: Liongard doesn't group it by key or user).
  'usage: MessagesUsage[].{d: starting_at, in: results[].uncached_input_tokens, cr: results[].cache_read_input_tokens, out: results[].output_tokens}, ' +
  // Claude Code analytics: one row per user per day, with an estimated cost.
  'code: ClaudeCodeUsage[].{d: date, e: actor.email_address || actor.api_key_name, s: core_metrics.num_sessions, la: core_metrics.lines_of_code.added, lr: core_metrics.lines_of_code.removed, ' +
  'c: core_metrics.commits_by_claude_code, pr: core_metrics.pull_requests_by_claude_code, cost: model_breakdown[].estimated_cost.amount, cur: model_breakdown[0].estimated_cost.currency, tin: model_breakdown[].tokens.input, tout: model_breakdown[].tokens.output, models: model_breakdown[].model}, ' +
  'invites: Invites[?status==\'pending\'].{e: email, r: role, sent: invited_at}}';
// OpenAI inspector shape is checked defensively; any missing list just comes back null.
const OAI_Q = '{users: (Users || OrganizationUsers)[].{id: id, e: email, n: name, r: role}, keys: (APIKeys || ProjectAPIKeys || AdminAPIKeys)[].{n: name, created: created_at, by: owner.user.id || owner.id, status: status}, ' +
  'orgs: organizations[].{n: title || name, role: role, admin: adminAccessVerified}}';   // the parent OpenAI inspector reports organisations only
const DUO_Q = 'Users[].{u: username, e: email, enr: is_enrolled}';

async function collect(api, env) {
  const [sys, ids] = await Promise.all([api.systems(env.ID), api.inventory('identities', env.ID)]);
  const pick = alias => sys.find(s => s.enabled && s.inspector === alias && s.systemDetailId);
  const a = pick('Anthropic'), o = pick('OpenAI'), duo = pick('Duo Security');
  return {
    environment: env,
    anthropic: a ? { ...(await api.evaluate(a.systemDetailId, ANTH_Q).catch(err => ({ _error: String(err.message || err) }))), systemId: a.systemId, systemDetailId: a.systemDetailId, inspectedOn: a.inspectedOn } : null,
    openai: o ? { ...(await api.evaluate(o.systemDetailId, OAI_Q).catch(err => ({ _error: String(err.message || err) }))), systemId: o.systemId, systemDetailId: o.systemDetailId, inspectedOn: o.inspectedOn } : null,
    duo: duo ? await api.evaluate(duo.systemDetailId, DUO_Q).catch(err => ({ _error: String(err.message || err) })) : null,
    identities: ids.map(i => ({ email: String(i.Email || '').toLowerCase(), name: i.DisplayName, mfa: i.MfaStatus, privileged: i.Privileged })),
  };
}

const lc = s => String(s || '').toLowerCase();

function compute(input) {
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const age = iso => iso ? Math.floor((now - new Date(iso)) / 864e5) : null;
  const idBy = new Map(input.identities.map(i => [i.email, i]));
  const duo = (Array.isArray(input.duo) ? input.duo : []).filter(u => u.e || u.u);
  const duoFor = e => duo.find(u => lc(u.e) === lc(e));
  const people = new Map();
  const platforms = [];
  for (const [key, label, d] of [['anthropic', 'Claude (Anthropic)', input.anthropic], ['openai', 'ChatGPT (OpenAI)', input.openai]]) {
    if (!d) continue;
    const orgs = (d.orgs || []).filter(Boolean);
    platforms.push({ key, label, systemId: d.systemId, systemDetailId: d.systemDetailId, inspectedOn: d.inspectedOn, unread: !!d._error,
      note: d._error ? `Couldn\u2019t read this inspector from Liongard, so its users, keys and spend are unknown (not zero). Refresh to try again.` : !(d.users || []).length && orgs.length ? `Connected to ${orgs.length} organisation${orgs.length > 1 ? 's' : ''} (${orgs.map(o => o.n).join(', ')}), but this inspector doesn\u2019t report individual users or keys` : '' });
    const users = d.users || [];
    const keys = (d.keys || []).filter(k => !k.status || lc(k.status) === 'active');
    for (const u of users) {
      const p = people.get(lc(u.e)) || { email: lc(u.e), name: u.n || u.e, platforms: {} };
      const mine = keys.filter(k => k.by && k.by === u.id);
      p.platforms[key] = { role: u.r, keys: mine.length, oldestKey: mine.length ? Math.max(...mine.map(k => age(k.created) || 0)) : null };
      people.set(lc(u.e), p);
    }
  }
  // Per-user Claude usage: workspaces and Claude Code analytics (sessions, lines, estimated cost per person).
  const an0 = input.anthropic || {};
  const sum = a => (Array.isArray(a) ? a : [a]).reduce((t, v) => t + (+v || 0), 0);
  const userById = new Map((an0.users || []).map(u => [u.id, lc(u.e)]));
  const wsNames = new Map((an0.ws || []).map(w => [w.id, w.n]));
  const code = new Map();
  for (const r of an0.code || []) {
    const k = lc(r.e); if (!k) continue;
    const c = code.get(k) || { sessions: 0, added: 0, removed: 0, commits: 0, prs: 0, cost: 0, tin: 0, tout: 0, days: new Set(), models: new Set(), currency: r.cur || 'USD' };
    c.sessions += +r.s || 0; c.added += +r.la || 0; c.removed += +r.lr || 0; c.commits += +r.c || 0; c.prs += +r.pr || 0;
    c.cost += sum(r.cost) / 100;   // estimated_cost.amount is in cents
    c.tin += sum(r.tin); c.tout += sum(r.tout); if (r.d) c.days.add(String(r.d).slice(0, 10)); (r.models || []).forEach(x => x && c.models.add(x));
    code.set(k, c);
    if (!people.has(k) && /@/.test(k)) people.set(k, { email: k, name: r.e, platforms: {} });   // Claude Code users who aren't org members in the list
  }
  for (const m of an0.wsm || []) { const e = userById.get(m.u); const p = e && people.get(e); if (p) (p.workspaces = p.workspaces || []).push({ n: wsNames.get(m.ws) || m.ws, r: m.r }); }

  const rows = [...people.values()].map(p => {
    const id = idBy.get(p.email); const du = duoFor(p.email);
    const mfa = id ? id.mfa : null; const duoState = du ? (du.enr === false ? 'not-enrolled' : 'enrolled') : null;
    const notes = [];
    if (!id) notes.push('Not in the client’s directory');
    if (mfa === 'NO') notes.push('No MFA in Microsoft 365');
    if (duoState === 'not-enrolled') notes.push('Not enrolled in Duo');
    const a = p.platforms.anthropic;
    if (a && /admin|owner/i.test(a.role || '')) notes.push('Can manage the organisation');
    if (a && a.keys === 0) notes.push('Member with no API key');
    if (a && a.oldestKey > 90) notes.push(`Oldest API key is ${a.oldestKey} days old`);
    const cc = code.get(p.email);
    // Protected by Microsoft 365 MFA, Duo, or both? Only someone with neither is unprotected; one of the two missing is
    // partial; someone Liongard has no MFA data for at all is unknown (never counted as protected or unprotected).
    const m365 = mfa === 'YES' ? 1 : mfa === 'PARTIAL' ? 0.5 : mfa === 'NO' ? 0 : null;
    const duoOn = duoState === 'enrolled' ? 1 : duoState === 'not-enrolled' ? 0 : null;
    const known = [m365, duoOn].filter(x => x != null);
    const protect = !known.length ? 'unknown' : known.every(x => x === 0) ? 'unprotected' : known.every(x => x === 1) ? 'protected' : 'partial';
    return { ...p, mfa, duo: duoState, privileged: id ? !!id.privileged : false, notes, protect, risk: protect === 'unprotected',
      workspaces: p.workspaces || [], code: cc ? { sessions: cc.sessions, added: cc.added, removed: cc.removed, commits: cc.commits, prs: cc.prs, cost: Math.round(cc.cost * 100) / 100, currency: cc.currency, tokens: cc.tin + cc.tout, days: cc.days.size, models: [...cc.models] } : null };
  }).sort((x, y) => (y.risk - x.risk) || x.name.localeCompare(y.name));

  const an = input.anthropic || {};
  // cost_report amounts are USD in cents, as decimal strings (Anthropic Admin API), like Claude Code's estimated_cost.
  const cost = (an.cost || []).map(c => ({ d: String(c.d).slice(0, 10), usd: (c.r || []).reduce((s, v) => s + (+v || 0), 0) / 100 }));
  const total = cost.reduce((s, c) => s + c.usd, 0);
  const wsName = new Map((an.ws || []).map(w => [w.id, w.n]));
  const userName = new Map((an.users || []).map(u => [u.id, u.n || u.e]));
  const keys = (an.keys || []).filter(k => !k.status || lc(k.status) === 'active').map(k => ({ name: k.n, owner: userName.get(k.by) || (k.by ? 'Unknown user' : 'Unknown'), workspace: wsName.get(k.ws) || '', age: age(k.created), expires: k.expires }))   // key hints deliberately not carried into the page
    .sort((a, b) => (b.age || 0) - (a.age || 0));
  const oldKeys = keys.filter(k => k.age > 90 && !k.expires);
  const atRisk = rows.filter(r => r.risk), partial = rows.filter(r => r.protect === 'partial'), unknownMfa = rows.filter(r => r.protect === 'unknown');
  const perDay = cost.length ? total / cost.length : 0;
  // How old the newest cost report is, against the data pull. Over a week old: say so, and don't
  // project a monthly figure from it (an account manager would quote that number to the client).
  const newest = cost.length ? cost[cost.length - 1].d : null;
  const reportAge = newest ? Math.max(0, Math.floor((new Date(input.pulledOn || Date.now()) - new Date(`${newest}T00:00:00Z`)) / 864e5)) : null;
  const staleReport = reportAge != null && reportAge > 7;
  const usd = v => `US$${(+v || 0).toFixed(2)}`;   // Anthropic bills in US dollars: shown as such, whatever the MSP's own currency
  const usage = (an.usage || []).map(u => ({ d: String(u.d).slice(0, 10), inTok: sum(u.in) + sum(u.cr), outTok: sum(u.out) }));
  const codeRows = rows.filter(r => r.code);
  const codeCost = codeRows.reduce((t, r) => t + r.code.cost, 0);
  const codeDays = new Set((an.code || []).map(r => String(r.d).slice(0, 10))).size;
  const summary = platforms.length ? [
    `${rows.length} ${rows.length === 1 ? 'person uses' : 'people use'} ${platforms.map(p => p.label).join(' and ')}${(input.anthropic && input.anthropic.users) ? '' : ''}.`,
    cost.length ? (staleReport
      ? `Claude spend averaged ${usd(perDay)} a day over the ${cost.length} days reported. The latest report is from ${fmt(newest)}, ${reportAge} days before this data pull, so no monthly figure is projected from it.`
      : `Claude spend averages ${usd(perDay)} a day, about US$${(perDay * 30).toFixed(0)} a month at the current rate (latest report ${fmt(newest)}).`) : '',
    keys.length ? `${keys.length} active API key${keys.length === 1 ? '' : 's'}; ${oldKeys.length} older than 90 days with no expiry, which should be rotated.` : '',
    (an.code || []).length ? `Claude Code: ${codeRows.length} ${codeRows.length === 1 ? 'person' : 'people'}, about ${usd(codeCost)} estimated over ${codeDays} day${codeDays === 1 ? '' : 's'}${codeRows.length ? `; highest ${[...codeRows].sort((a, b) => b.code.cost - a.code.cost)[0].name}` : ''}.` : (cost.length ? 'API spend is reported for the whole organisation, not per person, so it can\u2019t be split by user.' : ''),
    atRisk.length ? `${atRisk.length} AI user${atRisk.length === 1 ? ' has' : 's have'} neither MFA nor Duo: ${atRisk.slice(0, 4).map(r => r.name).join(', ')}.` : '',
    partial.length ? `${partial.length} AI user${partial.length === 1 ? ' has' : 's have'} MFA in one place but not the other (Microsoft 365 or Duo): ${partial.slice(0, 4).map(r => r.name).join(', ')}.` : '',
    unknownMfa.length ? `${unknownMfa.length} AI user${unknownMfa.length === 1 ? ' isn’t' : 's aren’t'} in the client’s directory or Duo, so their MFA is unknown.` : '',
    !atRisk.length && !partial.length && !unknownMfa.length && rows.length ? 'Every AI user has MFA in Microsoft 365 and Duo, where the client uses them.' : '',
  ].filter(Boolean) : [];
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, platforms, summary, perDay, usage, reportAge, staleReport, codeCost, codeDays, hasCode: (an.code || []).length > 0,
    kpis: [
      { k: 'AI users', v: platforms.some(p => p.unread) && !rows.length ? '—' : rows.length, s: platforms.map(p => p.label).join(' · ') || 'No AI inspectors', sev: 'info' },
      { k: 'Active API keys', v: keys.length, s: [`${keys.filter(k => !k.expires).length} with no expiry date`, oldKeys.length ? `${oldKeys.length} over 90 days old` : ''].filter(Boolean).join(', '), sev: oldKeys.length ? 'warn' : 'info' },
      // Say when the latest cost report is from, and flag it when it's more than a week behind the data pull.
      { k: `Spend (${cost.length} days reported)`, v: an._error ? '—' : usd(total), s: an._error ? 'Couldn’t read Claude spend from Liongard' : cost.length ? `${fmt(cost[0].d)} to ${fmt(newest)}. Latest report ${fmt(newest)}, ${reportAge === 0 ? 'the day of the pull' : `${reportAge} day${reportAge === 1 ? '' : 's'} old`}` : 'No cost data', sev: cost.length && (new Date(input.pulledOn || Date.now()) - new Date(cost[cost.length - 1].d)) / 864e5 > 7 ? 'warn' : 'info' },
      { k: 'Users without MFA or Duo', v: atRisk.length, s: [atRisk.length ? atRisk.map(r => r.name).join(', ') : '', partial.length ? `${partial.length} partly protected` : '', unknownMfa.length ? `${unknownMfa.length} unknown` : ''].filter(Boolean).join('. ') || 'Everyone has MFA', sev: atRisk.length ? 'bad' : partial.length ? 'warn' : unknownMfa.length ? 'info' : 'ok' },
    ],
    rows, keys, oldKeys: oldKeys.length, cost, total,
    pendingInvites: (an.invites || []).map(i => ({ email: i.e, role: i.r, sent: i.sent })),
  };
}

function fmt(d) { return new Date(d + 'T00:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }); }

module.exports = { id: 'ai', collect, compute };
