// The MSP's stack: which inspectors it uses (instance-wide and per client), and the findings, expiry dates and
// versions that Liongard's own metrics give for every one of them. Panels with detailed rules for specific vendors
// add these signals for every other inspector that feeds them, so each page works whatever the client runs.
const { profileOf, CAPABILITIES, capLabel } = require('./stack-catalog');
const { classify, display, shortName, plain, isEmpty } = require('./metric-signals');
const inspectorHealth = require('./panels/inspectors');

const ALL = CAPABILITIES.map(c => c.id);
// Bump when the instance profile's shape changes, so a profile saved by an older build is discovered again.
const PROFILE_V = 2;   // v2: enabledEnvs (which clients each inspector is enabled for)
const uniq = rows => [...new Map(rows.map(r => [`${r.n.toLowerCase()}|${r.v}`, r])).values()];
const CORE = ['identity', 'email', 'security', 'management', 'backup', 'network'];
const AGENTS = ['Windows Workstation', 'Windows Server', 'macOS', 'Linux'];
const EDR_ROLES = /EDR|MDR|Antivirus|Backup & protection/;
// What an inspector's metrics talk about, from their names. Used to decide which pages an inspector feeds.
const THEMES = { licences: /licen[cs]|seat|subscription|unassigned/i, expiry: /expir|renew|warranty|end of (life|support)/i, mfa: /\bmfa\b|2fa|two.?factor|multi.?factor/i,
  firmware: /firmware|software version/i, threats: /threat|infect|malware|incident|detection/i, backup: /backup|restore|snapshot|job/i, patching: /patch|update/i };
const themesOf = names => Object.entries(THEMES).filter(([, re]) => names.some(n => re.test(n))).map(([k]) => k);

// What feeds each page. caps = capabilities whose inspectors are relevant; deep = inspectors the page already reads
// with its own rules (their metric findings are left out to avoid saying the same thing twice).
const FEEDS = {
  cyber: { caps: ['security', 'identity', 'network', 'email', 'backup', 'monitoring'], none: true },   // the page's posture section reads every inspector itself
  coverage: { caps: ['security', 'management', 'backup'], deep: AGENTS, match: /device|endpoint|agent|machine|computer|server|workstation|threat|infect|quarantin|offline|stale|check.?in|patch|update|protect|antivirus|edr|backup|restore/i, exclude: /\buser|mfa|2fa|admin|password|polic/i, title: 'Device problems reported by this client’s tools' },
  identity: { caps: ['identity', 'awareness'], deep: ['Duo Security'], title: 'From this client’s identity, MFA and dark-web tools' },
  email: { caps: ['email'], deep: ['Internet Domain/DNS', 'TLS/SSL'], title: 'From this client’s other email and domain tools' },
  compliance: { caps: CORE.concat('awareness'), sev: 'bad', title: 'Control failures reported by this client’s inspectors' },
  licences: { caps: ALL, facts: /licen[cs]|seat|subscription|unassigned|purchased|consumed|assigned/i, match: /licen[cs]|seat|unassigned|subscription|stale and licen/i, deep: ['Microsoft 365', 'KnowBe4', 'Duo Security', 'ThreatLocker', 'NinjaOne', 'CrowdStrike EDR', 'Anthropic', 'Active Directory'], expiries: true, title: 'Licence signals from this client’s other tools' },
  ai: { caps: ['ai'], deep: ['Anthropic', 'OpenAI'], title: 'From this client’s other AI services' },
  network: { caps: ['network', 'monitoring'], none: true },   // the page builds a card for every network device itself
  lifecycle: { caps: ALL, none: true },   // the page merges every inspector's renewal dates itself
  wallboard: { caps: ALL, none: true },   // the wallboard shows problems in its own column
  inspectors: { caps: ALL, none: true }, changes: { caps: ALL, none: true }, lookup: { caps: ALL, none: true }, stack: { caps: ALL, none: true },
  register: { caps: [], none: true },
  actions: { caps: ALL, none: true },
  overview: { caps: ALL, none: true },
};

// ---------- Instance discovery (runs when the app connects) ----------
async function discoverInstance(api) {
  const [catalog, lps, envs, metrics] = await Promise.all([api.inspectorCatalog(), api.allLaunchpoints(), api.environments(), api.metricCatalog().catch(() => [])]);
  const metricNames = new Map();
  for (const m of metrics) if (m.enabled && m.inspectorId) (metricNames.get(m.inspectorId) || metricNames.set(m.inspectorId, []).get(m.inspectorId)).push(m.name);
  const visible = new Set(envs.map(e => e.ID));
  const byId = new Map();
  for (const l of lps) {
    const envId = (l.Environment && l.Environment.ID) || l.EnvironmentID;
    if (!visible.has(envId) || !l.Inspector) continue;
    const k = l.Inspector.ID;
    const r = byId.get(k) || { id: k, alias: l.Inspector.Alias, envs: new Set(), enabledEnvs: new Set(), launchpoints: 0, enabled: 0 };
    r.envs.add(envId); r.launchpoints++; if (l.Enabled !== false) { r.enabled++; r.enabledEnvs.add(envId); }
    byId.set(k, r);
  }
  const cat = new Map(catalog.map(i => [i.ID, i]));
  const inUse = [...byId.values()].map(r => {
    const c = cat.get(r.id) || {};
    const p = profileOf(r.alias, c.InspectorCategory);
    const names = metricNames.get(r.id) || [];
    return { id: r.id, alias: r.alias, category: c.InspectorCategory || '', status: c.PublishedStatus || '', caps: p.caps, role: p.role, known: p.known,
      envs: [...r.envs], enabledEnvs: [...r.enabledEnvs], launchpoints: r.launchpoints, enabled: r.enabled, metrics: names.length, themes: themesOf(names) };
  }).sort((a, b) => b.envs.length - a.envs.length || a.alias.localeCompare(b.alias));
  return { v: PROFILE_V, pulledOn: new Date().toISOString(), environments: envs.length, catalogue: catalog.length, metricCatalogue: metrics.length, inUse,
    // Each inspector's icon (Liongard's static image host), for the pages to show next to tool names.
    icons: catalog.map(i => ({ alias: i.Alias, url: i.Icon || i.Logo })).filter(x => x.alias && x.url),
    notUsed: catalog.filter(i => !byId.has(i.ID) && !i.RetiredOn).map(i => ({ id: i.ID, alias: i.Alias, status: i.PublishedStatus, caps: profileOf(i.Alias, i.InspectorCategory).caps })) };
}

// Which of a client's inspectors feed each page (for the launcher cards). Only inspectors with an enabled launchpoint
// for THIS client count.
// Order is by relevance to the page: the inspectors it reads with its own rules first, then by its capability order.
function pageFeeds(profile, envId) {
  const here = (profile.inUse || []).filter(i => Array.isArray(i.enabledEnvs) ? i.enabledEnvs.includes(+envId) : i.envs.includes(+envId) && i.enabled);
  const out = {};
  const rank = (f, i) => {
    const d = (f.deep || []).indexOf(i.alias);
    if (d >= 0) return d;
    const c = Math.min(...(i.caps || []).map(x => f.caps.indexOf(x)).filter(x => x >= 0));
    return 100 + (Number.isFinite(c) ? c : 50);
  };
  const order = (f, list) => list.map((i, n) => [i, rank(f, i), n]).sort((a, b) => a[1] - b[1] || a[2] - b[2]).map(([i]) => i.alias);
  for (const [id, f] of Object.entries(FEEDS)) {
    if (id === 'register') continue;
    const set = new Set(f.caps);
    out[id] = order(f, here.filter(i => (i.caps || []).some(c => set.has(c)) || (f.deep || []).includes(i.alias)));
  }
  // Licences and renewals come from any capability, so only count inspectors whose metrics carry that data.
  const withTheme = (t, deep = []) => order({ ...FEEDS[t === 'licences' ? 'licences' : 'lifecycle'], deep }, here.filter(i => deep.includes(i.alias) || (i.themes || []).includes(t)));
  out.licences = withTheme('licences', FEEDS.licences.deep);
  out.lifecycle = withTheme('expiry', ['TLS/SSL', 'Internet Domain/DNS', 'SonicWall', 'Barracuda Firewall', 'Cisco Meraki', 'KnowBe4']);
  return { inspectors: here.map(i => ({ alias: i.alias, caps: i.caps, role: i.role })), pages: out };
}

// A hostname from a metric list item: "Device Name: PC-1.contoso.com, …", ["PC-1", 4295], {hostname: …} or a plain name.
function hostOf(x) {
  let h = null;
  if (typeof x === 'string') h = (/(?:device name|hostname|computer ?name|machine|server)\s*:\s*([^,|]+)/i.exec(x) || [])[1] || (x.includes(':') ? null : x.split(/[|,]/)[0]);
  else if (Array.isArray(x)) h = typeof x[0] === 'string' ? x[0] : null;
  else if (x && typeof x === 'object') h = x.hostname || x.Hostname || x.name || x.Name || x.server || x.Device || x.device || x.ComputerName || null;
  h = h && String(h).trim();
  if (!h || h.length > 63 || /\s{2,}|^\d+(\.\d+){3}$/.test(h) || h.split(' ').length > 3) return null;
  return h.split('.')[0].toUpperCase();
}

// ---------- Per-client data ----------
// Metrics that list the devices a tool knows about (kept in full so coverage can match them to inventory hostnames).
const DEVICE_LIST = /(device|endpoint|machine|server|workstation|computer|agent)s? (list|inventory|summary)|list of (devices|machines|endpoints|computers)|total endpoints|per-(device|server)|by device|agent inventory/i;
const compact = (v, name) => {
  if (Array.isArray(v)) { const max = DEVICE_LIST.test(name || '') ? 500 : 25; return v.length > max ? { v: v.slice(0, max), len: v.length } : { v }; }
  if (typeof v === 'string' && v.length > 600) return { v: v.slice(0, 600) + '…' };
  if (v && typeof v === 'object') { const j = JSON.stringify(v); return j.length > 3000 ? { v: Object.fromEntries(Object.entries(v).slice(0, 30)) } : { v }; }
  return { v };
};

async function collectEnv(api, env) {
  const systems = await api.systems(env.ID);
  const ids = systems.filter(s => s.enabled && s.systemId && s.systemDetailId).map(s => s.systemId);
  const values = await api.metricValues(ids);
  const metrics = values.filter(m => !isEmpty(m.Value)).map(m => ({ s: m.SystemID, id: m.MetricID, n: m.MetricName, at: m.TimelineDate, ...compact(m.Value, m.MetricName) }));
  return { environment: env, rows: systems, metrics, metricCount: values.length };
}

// Evidence older than this (or from an inspector that is failing or stale) is shown as "older evidence", not as a current exposure.
const EVIDENCE_DAYS = 14;
// Findings that several pages count, defined once so Cyber security, Compliance and the rest agree.
const SIGNALS = {
  encrypt: /(drive|disk|volume|device).*encrypt|encrypt.*(drive|disk|volume)|bitlocker|filevault/i,
  backupFail: /fail|error|missed|unprotected|not (backed|protected)|stale|warning/i,
};
// Current evidence only (see EVIDENCE_DAYS).
const current = (st, re, caps) => st ? st.findings.filter(f => !f.old && re.test(f.label) && (!caps || f.caps.includes(caps))) : [];

function computeEnv(raw) {
  const now = raw.pulledOn ? new Date(raw.pulledOn) : new Date();
  const health = new Map(inspectorHealth.compute({ environment: raw.environment, pulledOn: raw.pulledOn, rows: raw.rows }).rows.map(r => [r.lpId, r]));
  const systems = raw.rows.map(r => {
    const h = health.get(r.lpId) || {};
    const p = profileOf(r.inspector, r.category);
    return { lpId: r.lpId, systemId: r.systemId, systemDetailId: r.systemDetailId, inspectorId: r.inspectorId, name: r.name, inspector: r.inspector, caps: p.caps, role: p.role, known: p.known,
      health: h.health || 'Inactive', why: h.why || '', lastGood: r.inspectedOn };
  });
  const bySys = new Map(); for (const s of systems) if (s.systemId && !bySys.has(s.systemId)) bySys.set(s.systemId, s);
  const live = systems.filter(s => s.health !== 'Inactive');
  const hasEdr = live.some(s => s.caps.includes('security') && EDR_ROLES.test(s.role));

  const findings = [], expiries = [], versions = [], metricsBySys = new Map();
  const seenF = new Set(), seenE = new Set();
  for (const m of raw.metrics) {
    const s = bySys.get(m.s); if (!s) continue;
    (metricsBySys.get(m.s) || metricsBySys.set(m.s, []).get(m.s)).push(m);
    for (const sig of classify(m, now)) {
      // How old the evidence is: a fresh-looking finding from an inspector that stopped reporting months ago isn't "now".
      const age = m.at ? Math.floor((now - new Date(m.at)) / 864e5) : null;
      const old = (age != null && age > EVIDENCE_DAYS) || s.health === 'Failing' || s.health === 'Stale';
      const base = { inspector: s.inspector, system: s.name, systemId: s.systemId, systemDetailId: s.systemDetailId, lpId: s.lpId, inspectorId: s.inspectorId, caps: s.caps, at: m.at, metric: m.n, age, old, health: s.health };
      if (sig.kind === 'finding') {
        if (s.inspector === 'Roar') continue;   // Liongard's self-inspection repeats inspector health
        if (hasEdr && AGENTS.includes(s.inspector) && /defender|anti.?virus|anti.?malware|real.?time|tamper/i.test(sig.label)) continue;   // passive Defender is expected under an EDR
        const theme = (/\b(dkim|dmarc|spf)\b/i.exec(sig.label) || [])[1];
        const k = `${m.s}|${theme ? theme.toLowerCase() : sig.stem}`;
        const prev = findings.findIndex(f => f.key === k);
        if (prev >= 0) { if (!findings[prev].list && sig.list) findings[prev].list = sig.list; continue; }
        if (seenF.has(k)) continue; seenF.add(k);
        findings.push({ ...base, key: k, sev: sig.sev, label: plain(sig.label), value: sig.value, list: sig.list || null });
      } else if (sig.kind === 'expiry') {
        const k = `${m.s}|${sig.date}`; if (seenE.has(k)) continue; seenE.add(k);
        expiries.push({ ...base, label: sig.label, date: sig.date, days: sig.days });
      } else versions.push({ ...base, label: sig.label, value: sig.value });
    }
  }
  const sevOrder = { bad: 0, warn: 1 };
  findings.sort((a, b) => sevOrder[a.sev] - sevOrder[b.sev] || a.inspector.localeCompare(b.inspector) || a.system.localeCompare(b.system));
  expiries.sort((a, b) => a.date.localeCompare(b.date));

  // Firmware or software drift: the same inspector and metric reporting different versions across devices.
  const drift = [];
  const groups = new Map();
  for (const v of versions.filter(v => /firmware|software version|agent version/i.test(v.label))) {
    const k = `${v.inspector}|${v.label}`; (groups.get(k) || groups.set(k, []).get(k)).push(v);
  }
  for (const [k, g] of groups) {
    const vals = [...new Set(g.map(v => v.value))];
    if (vals.length > 1) drift.push({ inspector: g[0].inspector, label: g[0].label, caps: g[0].caps, values: vals.map(x => ({ value: x, systems: g.filter(v => v.value === x).map(v => v.system) })) });
  }

  // Capability coverage for this client.
  const caps = CAPABILITIES.map(c => {
    const insp = live.filter(s => s.caps.includes(c.id));
    const f = findings.filter(x => x.caps.includes(c.id));
    const failing = insp.filter(s => s.health === 'Failing' || s.health === 'Stale');
    const state = !insp.length ? (CORE.includes(c.id) ? 'gap' : 'unused') : failing.length === insp.length ? 'blind' : f.some(x => x.sev === 'bad') ? 'bad' : f.length || failing.length ? 'warn' : 'ok';
    return { id: c.id, label: c.label, q: c.q, state, tools: [...new Set(insp.map(s => s.inspector))], systems: insp.length, failing: failing.length, bad: f.filter(x => x.sev === 'bad').length, warn: f.filter(x => x.sev === 'warn').length };
  }).filter(c => c.id !== 'other' || c.systems);

  // Devices each tool knows about, from metrics that list them by name (for tools that don't link devices into inventory).
  const deviceLists = {};
  for (const m of raw.metrics) {
    const s = bySys.get(m.s);
    if (!s || !Array.isArray(m.v) || !DEVICE_LIST.test(m.n) || /without|missing|not |low memory|threat|patch|offline/i.test(m.n)) continue;
    const hosts = m.v.map(hostOf).filter(Boolean);
    if (hosts.length) { const set = deviceLists[s.inspector] || (deviceLists[s.inspector] = new Set()); hosts.forEach(h => set.add(h)); }
  }

  return { environment: raw.environment, pulledOn: raw.pulledOn, now: now.toISOString(), systems, findings, expiries, drift, caps, metricsBySys, metricCount: raw.metricCount,
    deviceLists: Object.fromEntries(Object.entries(deviceLists).map(([k, v]) => [k, [...v]])) };
}

// The extra section a page shows for the inspectors it doesn't read with its own rules.
function feedFor(pageId, env) {
  const f = FEEDS[pageId];
  if (!f || f.none) return null;
  const set = new Set(f.caps), deep = new Set(f.deep || []);
  const mine = s => s.caps.some(c => set.has(c)) && !deep.has(s.inspector);
  let findings = f.findings === false ? [] : env.findings.filter(x => mine(x) && (!f.sev || x.sev === f.sev) && (!f.match || f.match.test(x.label)) && (!f.exclude || !f.exclude.test(x.label)));
  if (f.limit) findings = findings.slice(0, f.limit);
  const expiries = f.expiries ? env.expiries.filter(x => mine(x) && (!f.match || pageId !== 'licences' || /licen|subscription|seat/i.test(x.label)) && x.days <= 400) : [];
  const drift = f.versions ? env.drift.filter(d => d.caps.some(c => set.has(c)) && !deep.has(d.inspector)) : [];
  const topic = pageId === 'licences' ? THEMES.licences : pageId === 'lifecycle' ? THEMES.expiry : null;
  const relevant = s => mine(s) && (!topic || (env.metricsBySys.get(s.systemId) || []).some(m => topic.test(m.n)));
  const tools = [...new Set(env.systems.filter(s => s.health !== 'Inactive' && relevant(s)).map(s => s.inspector))];
  const blind = [...new Set(env.systems.filter(s => relevant(s) && (s.health === 'Failing' || s.health === 'Stale')).map(s => s.name))];
  // Key values from each relevant system (seat counts, firmware, models), so the page shows data even when nothing is wrong.
  const facts = !f.facts ? [] : env.systems.filter(s => s.health !== 'Inactive' && relevant(s)).map(s => ({ system: s.name, inspector: s.inspector,
    rows: uniq((env.metricsBySys.get(s.systemId) || []).filter(m => f.facts.test(m.n) && (typeof m.v !== 'object' || m.v === null)).map(m => ({ n: plain(m.n), v: display(m.v, m.n) }))).sort((a, b) => a.n.localeCompare(b.n)).slice(0, 12) })).filter(x => x.rows.length);
  return { title: f.title, tools, facts, findings: findings.map(({ key, caps, ...x }) => x), expiries: expiries.map(({ caps, ...x }) => x), drift: drift.map(({ caps, ...x }) => x), blind };
}

// Model for the Customer stack page.
function stackPage(raw) {
  const env = computeEnv(raw);
  const live = env.systems.filter(s => s.health !== 'Inactive');
  const byInspector = new Map();
  for (const s of env.systems) (byInspector.get(s.inspector) || byInspector.set(s.inspector, []).get(s.inspector)).push(s);
  const inspectors = [...byInspector].map(([alias, list]) => {
    const f = env.findings.filter(x => x.inspector === alias);
    const order = ['Failing', 'Stale', 'Due', 'Fresh', 'Inactive'];
    const worst = list.map(s => s.health).sort((a, b) => order.indexOf(a) - order.indexOf(b))[0];
    return { alias, role: list[0].role, caps: list[0].caps.map(capLabel), known: list[0].known, count: list.length, health: worst, bad: f.filter(x => x.sev === 'bad').length, warn: f.filter(x => x.sev === 'warn').length,
      systems: list.map(s => ({ name: s.name, lpId: s.lpId, inspectorId: s.inspectorId, health: s.health, why: s.why, lastGood: s.lastGood,
        facts: uniq((env.metricsBySys.get(s.systemId) || []).filter(m => typeof m.v !== 'object' || m.v === null).map(m => ({ n: plain(m.n), v: display(m.v, m.n) }))).sort((a, b) => a.n.localeCompare(b.n)).slice(0, 80) })) };
  }).sort((a, b) => (b.bad - a.bad) || (b.warn - a.warn) || a.alias.localeCompare(b.alias));
  const gaps = env.caps.filter(c => c.state === 'gap');
  const covered = env.caps.filter(c => c.systems).length;
  const unmapped = inspectors.filter(i => !i.known).map(i => i.alias);
  const soon = env.expiries.filter(e => e.days <= 90);
  return {
    environment: env.environment, pulledOn: env.pulledOn,
    kpis: [
      { k: 'Inspectors in use', v: new Set(live.map(s => s.inspector)).size, s: `${live.length} systems monitored`, sev: 'info' },
      { k: 'Capabilities covered', v: `${covered} / ${env.caps.length}`, s: gaps.length ? `No ${gaps.map(c => c.label.toLowerCase()).join(', ')}` : 'All core capabilities monitored', sev: gaps.length ? 'warn' : 'ok' },
      // Current evidence only, like Cyber security; findings from old evidence are counted separately.
      { k: 'Problems', v: env.findings.filter(f => f.sev === 'bad' && !f.old).length, s: [`${env.findings.filter(f => f.sev === 'warn' && !f.old).length} more to review`, env.findings.some(f => f.old) ? `${env.findings.filter(f => f.old).length} from older evidence` : ''].filter(Boolean).join(', '), sev: env.findings.some(f => f.sev === 'bad' && !f.old) ? 'bad' : 'ok' },
      { k: 'Expired or due in 90 days', v: soon.length, s: soon.filter(e => e.days < 0).length ? `${soon.filter(e => e.days < 0).length} already expired` : 'Licences, warranties, subscriptions, certificates', sev: soon.some(e => e.days < 0) ? 'bad' : soon.length ? 'warn' : 'ok' },
      { k: 'Liongard metrics read', v: env.metricCount, s: 'Across every inspector in use', sev: 'info' },
    ],
    caps: env.caps, findings: env.findings.map(({ key, caps, ...x }) => x), expiries: env.expiries.filter(e => e.days <= 400).map(({ caps, ...x }) => x), drift: env.drift.map(({ caps, ...x }) => x), inspectors, unmapped,
  };
}

module.exports = { PROFILE_V, hostOf, FEEDS, discoverInstance, pageFeeds, collectEnv, computeEnv, feedFor, stackPage, SIGNALS, current, EVIDENCE_DAYS };
