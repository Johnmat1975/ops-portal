// Stack coverage: every device the client has, whatever its Liongard review state, against the tools that should be on it.
// Shows the actual RMM, AV/EDR and backup products per device, whether protection is really active, devices the tools
// disagree about, and gaps against a per-client policy of what workstations and servers must have.
// Tools are recognised through the capability map of all 117 Liongard inspectors (stack-catalog.js), so any vendor counts.
const { pMap } = require('../api');
const { osSupport } = require('../catalog');
const { profileOf } = require('../stack-catalog');

const WIN_Q = '{name: SystemInfo.CSName, caption: SystemInfo.Caption, build: SystemInfo.BuildNumber, ' +
  'av: DefenderInfo.Status.AntivirusEnabled, rtp: DefenderInfo.Status.RealTimeProtectionEnabled, sigOld: DefenderInfo.Status.DefenderSignaturesOutOfDate, mode: DefenderInfo.Status.AMRunningMode, ' +
  'thirdPartyAv: AntivirusSoftware[].displayName, fw: Firewall.{d: Domain, p: Private, u: Public}, pending: AvailableUpdates[].Title}';
const DEFAULT_STALE_DAYS = 45;   // devices not seen for this long are stale, matching Liongard Asset Inventory (changeable in Settings)

async function collect(api, env) {
  const [devices, sys, alerts] = await Promise.all([api.inventory('devices', env.ID), api.systems(env.ID), api.alerts(env.ID)]);
  const agents = sys.filter(s => s.enabled && s.systemDetailId && /^Windows (Workstation|Server)$/.test(s.inspector || ''));
  const windows = await pMap(agents, 6, async s => ({ systemId: s.systemId, systemDetailId: s.systemDetailId, inspectedOn: s.inspectedOn, ...(await api.evaluate(s.systemDetailId, WIN_Q).catch(err => ({ _error: String(err.message || err) }))) }));   // a failed read is unknown, never "off"
  return {
    environment: env,
    devices: devices.filter(d => !d.DeletedOn).map(d => ({ id: d.ID, host: d.Hostname, os: d.OperatingSystem, osVersion: d.OSVersion, type: d.Type, category: d.Category, role: d.Role, state: d.InventoryState,
      lastSeen: d.LastSeen, edr: d.EDR, antivirus: d.Antivirus, lastUser: d.LastLoginUser, manufacturer: d.Manufacturer, model: d.Model, serial: d.SerialNumber,
      warranty: d.WarrantyExpiration, eol: d.EOLDate, win11Ready: d.WinElevenReady, networkRole: d.NetworkRole,
      inspectors: (d.Inspectors || []).map(i => ({ alias: i.Alias, systemId: i.SystemID, systemDetailId: i.SystemDetailID })) })),
    deployed: [...new Set(sys.filter(s => s.enabled).map(s => s.inspector))],
    systems: sys.filter(s => s.enabled).map(s => ({ inspector: s.inspector, name: s.name, systemId: s.systemId, systemDetailId: s.systemDetailId, lpId: s.lpId, inspectorId: s.inspectorId })),
    windows,
    bitlockerAlerts: alerts.filter(a => /bitlocker|not encrypted|encrypt/i.test(`${a.Name} ${a.Description || ''}`) && !/clos/i.test((a.Status && a.Status.Name) || ''))
      .map(a => ({ name: a.Name, system: alertTarget(a.Name), created: a.CreatedOn, id: a.ID })),
  };
}

// Alert titles end with the target in quotes: 'Windows Workstation | BitLocker Not Enabled on an OS Volume | "PC-NAME"'.
const alertTarget = name => (/"([^"]+)"\s*$/.exec(name || '') || [])[1] || '';
const short = h => String(h || '').split('.')[0].toUpperCase();

// ---------- What kind of device, and which tool does what ----------
function kindOf(d) {
  const t = `${d.type || ''} ${d.role || ''}`.toLowerCase(), os = String(d.os || '');
  // Appliances and management controllers can't run an agent, so they aren't judged as servers.
  if (/idrac|\bilo\b|ipmi|\bbmc\b|appliance|esxi|vcenter|vmware|synology|qnap/i.test(`${d.host} ${d.model || ''} ${os}`)) return 'Appliance';
  if (/server/.test(t) || /server/i.test(os)) return 'Server';
  if (/smartphone|tablet|mobile|phone/.test(t) || /\b(ios|ipados|android)\b/i.test(os) || /mobile device/i.test(d.model || '')) return 'Mobile';
  if (/access.?point|switch|router|firewall|gateway|camera|printer|iot|ups|nas|storage|network|voip/.test(t) || /^network$|iot/.test(d.category || '')) return 'Network & IoT';
  if (/workstation|desktop|laptop|notebook/.test(t) || /windows|mac ?os|darwin|linux|ubuntu|^10\.0\./i.test(os)) return 'Workstation';
  return 'Unknown';
}
const AGENTABLE = new Set(['Server', 'Workstation']);

// Device-level tool categories, from the inspector's capability and role.
const CATS = [
  { key: 'rmm', label: 'RMM / MDM', test: p => p.caps.includes('management') && !/Liongard agent|Printers/.test(p.role) },
  { key: 'edr', label: 'EDR / AV', test: p => /EDR|MDR|Antivirus|Backup & protection/.test(p.role) },
  { key: 'control', label: 'App control', test: p => /Application control|Privilege management|Hardening/.test(p.role) },
  { key: 'backup', label: 'Backup', test: p => p.caps.includes('backup') && !/Storage/.test(p.role) },
  { key: 'agent', label: 'Liongard agent', test: p => p.role === 'Liongard agent' },
];
const catOf = alias => { const p = profileOf(alias); const c = CATS.find(c => c.test(p)); return c ? c.key : null; };

// Product names from the device record and the Windows agent, tidied to a vendor name.
function vendor(name) {
  const s = String(name || '').trim();
  if (!s) return '';
  if (/defender for endpoint|\bmde\b|\bsense\b/i.test(s)) return 'Defender for Endpoint';
  if (/defender|windows security/i.test(s)) return 'Microsoft Defender';
  const known = [['crowdstrike', 'CrowdStrike'], ['sentinel', 'SentinelOne'], ['sophos', 'Sophos'], ['huntress', 'Huntress'], ['cylance', 'Cylance'], ['webroot', 'Webroot'], ['eset', 'ESET'], ['bitdefender', 'Bitdefender'],
    ['malwarebytes', 'Malwarebytes'], ['trend', 'Trend Micro'], ['carbon black', 'Carbon Black'], ['symantec|norton', 'Symantec'], ['mcafee|trellix', 'Trellix (McAfee)'], ['kaspersky', 'Kaspersky'], ['acronis', 'Acronis'],
    ['capture client', 'SonicWall Capture Client'], ['withsecure|f-secure', 'WithSecure'], ['blackpoint', 'Blackpoint'], ['datto edr', 'Datto EDR'], ['avast', 'Avast'], ['\\bavg\\b', 'AVG']];
  const k = known.find(([re]) => new RegExp(re, 'i').test(s));
  return k ? k[1] : null;   // not a recognised AV/EDR product (device records sometimes list ordinary apps)
}
const MDR_ONLY = new Set(['Huntress', 'Blackpoint']);   // run alongside an AV by design, so these with an AV isn't a conflict
const asList = v => Array.isArray(v) ? v : v ? [v] : [];

function compute(input) {
  const STALE_DAYS = (input.thresholds && input.thresholds.device) || DEFAULT_STALE_DAYS;   // Settings › Defaults
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const days = iso => iso ? Math.floor((now - new Date(iso)) / 864e5) : null;
  // The Windows agent reports some flags as "True"/"False" strings and others as booleans; read them all as booleans.
  const bool = v => v === true || v === 1 || /^(true|yes|on|enabled|1)$/i.test(String(v == null ? '' : v).trim());
  const asBool = w => ({ ...w, av: w.av == null ? w.av : bool(w.av), rtp: w.rtp == null ? w.rtp : bool(w.rtp), sigOld: bool(w.sigOld),
    fw: w.fw && { d: bool(w.fw.d), p: bool(w.fw.p), u: bool(w.fw.u) } });
  // Only records the agent actually returned count. A failed read (or an empty one, from caches before 0.5) is unknown:
  // treating it as data would show Defender "off" for a device whose agent simply couldn't be read.
  const readOk = w => !w._error && (w.av != null || w.caption || w.name);
  const winBySys = new Map((input.windows || []).filter(readOk).map(w => [w.systemId, asBool(w)]));
  const winUnread = new Set((input.windows || []).filter(w => !readOk(w)).map(w => w.systemId));
  const latestSd = new Map((input.systems || []).map(s => [s.systemId, s.systemDetailId]));
  const bitlockerHosts = new Set((input.bitlockerAlerts || []).map(a => short(a.system.replace(/ Windows (Workstation|Server).*$/, ''))));
  const deployed = input.deployed || [];
  const deployedBy = k => deployed.filter(a => catOf(a) === k);
  const cats = CATS.filter(c => deployedBy(c.key).length).map(c => ({ key: c.key, label: c.label, tools: deployedBy(c.key) }));
  const clientEdr = deployedBy('edr').filter(a => !/Defender/i.test(a));
  // Some inspectors don't link devices into Liongard's inventory. A device "missing" a category that includes one of them
  // is unconfirmed (it may be in that tool), not missing; a category with no device data at all can't be judged.
  const lists = (input.stack && input.stack.deviceLists) || {};   // tools that list their devices in Liongard metrics
  const sysOf = alias => (input.systems || []).find(x => x.inspector === alias) || {};
  const linking = new Set([...input.devices.flatMap(d => d.inspectors.map(i => i.alias)), ...Object.keys(lists)]);
  const silent = k => deployedBy(k).filter(a => !linking.has(a));
  const recordEdr = input.devices.some(d => asList(d.edr).concat(asList(d.antivirus)).some(n => vendor(n)));
  const noDeviceData = cats.filter(c => silent(c.key).length === c.tools.length && !(c.key === 'edr' && recordEdr));
  // The client's own policy as set; the MSP's default (Settings) or the built-in one only asks for tools the client runs.
  const own = input.policy && !input.policy.fromDefault ? input.policy : null;
  const policyIn = own || defaultPolicy(cats, input.policy);
  const policy = Object.fromEntries(['workstation', 'server'].map(k => [k, (policyIn[k] || []).filter(c => !noDeviceData.some(n => n.key === c))]));   // device types only (a saved policy also carries the client's name)

  // ---------- Agents on each device and whether they're checking in ----------
  // Last check-in per device and tool (from the tools' own device lists), each tool's Liongard health, and the tools' own
  // "offline / stale" lists. Epoch values (Datto) and ISO strings both read as dates.
  const toDay = v => { if (v == null || v === '') return null; const t = typeof v === 'number' ? new Date(v > 1e12 ? v : v * 1000) : new Date(v); return isNaN(t) ? null : t; };
  const checkin = new Map();
  for (const c of input.checkins || []) { const t = toDay(c.seen); if (!t) continue; const k = `${short(c.host)}|${c.source}`; if (!checkin.has(k) || checkin.get(k) < t) checkin.set(k, t); }
  const sysHealth = new Map(((input.stack && input.stack.systems) || []).map(s => [s.systemId, s.health]));
  const PROBLEM_LIST = /offline|stale|not seen|inactive|not checked|failed|unhealthy|unprotected|disconnected/i;
  const hostOf = x => short(typeof x === 'object' && x ? (x.hostname || x.host || x.name || x.computerName || x.deviceName || '') : String(x || '').split(/[|,]/)[0]);
  const problemLists = ((input.stack && input.stack.findings) || []).filter(f => !f.old && Array.isArray(f.list) && f.list.length && PROBLEM_LIST.test(f.label))
    .map(f => ({ inspector: f.inspector, label: f.label, sev: f.sev, hosts: new Set(f.list.map(hostOf).filter(Boolean)) }));
  const AGENT_CATS = ['agent', 'rmm', 'edr', 'backup', 'control'];
  const agentStatus = (host, alias, systemId) => {
    const t = checkin.get(`${short(host)}|${alias}`);
    if (t) { const n = Math.floor((now - t) / 864e5); return { state: n <= 7 ? 'ok' : n <= 30 ? 'warn' : 'bad', why: n <= 0 ? 'Checked in today' : `Last checked in ${n >= 365 ? `${(n / 365).toFixed(1).replace(/\.0$/, '')} years` : `${n} day${n === 1 ? '' : 's'}`} ago`, seen: t.toISOString() }; }
    const hit = problemLists.find(p => p.inspector === alias && p.hosts.has(short(host)));
    if (hit) return { state: hit.sev === 'bad' ? 'bad' : 'warn', why: `${alias} lists it under “${hit.label}”` };
    const h = sysHealth.get(systemId);
    if (h === 'Failing' || h === 'Stale') return { state: 'warn', why: `${alias}’s data in Liongard is ${h.toLowerCase()}, so its view of this device may be out of date` };
    return { state: 'listed', why: `Listed by ${alias}; Liongard doesn’t record when it last checked in` };
  };

  const rows = input.devices.filter(d => d.state !== 'Archive').map(d => {
    const kind = kindOf(d);
    const tools = d.inspectors.filter(i => i.alias).map(i => ({ alias: i.alias, cat: catOf(i.alias), systemId: i.systemId, systemDetailId: latestSd.get(i.systemId) || i.systemDetailId }));
    for (const [alias, hosts] of Object.entries(lists)) if (!tools.some(t => t.alias === alias) && hosts.includes(short(d.host))) {
      const x = sysOf(alias); tools.push({ alias, cat: catOf(alias), systemId: x.systemId, systemDetailId: x.systemDetailId, fromList: true });
    }
    const byCat = k => [...new Set(tools.filter(t => t.cat === k).map(t => t.alias))];
    const link = alias => { const t = tools.find(x => x.alias === alias); return { name: alias, systemId: t && t.systemId, systemDetailId: t && t.systemDetailId }; };
    const win = d.inspectors.map(i => winBySys.get(i.systemId)).find(Boolean);
    const os = (win && win.caption) || d.os || '';
    const sup = osSupport(os);
    const editionKnown = /home|pro\b|enterprise|education/i.test(os);
    const supDate = sup ? (sup.entDate && (!editionKnown || /enterprise|education/i.test(os)) ? sup.entDate : sup.date) : null;
    const supDays = sup ? Math.floor((new Date(supDate) - now) / 864e5) : null;
    const seenDays = days(d.lastSeen);
    const stale = seenDays != null && seenDays > STALE_DAYS;

    // Protection: products from the security tools that see the device, the device record and the Windows agent.
    const fromTools = byCat('edr').map(a => ({ ...link(a), name: vendor(a) || a, via: a }));
    const fromRecord = [...asList(d.edr), ...asList(d.antivirus)].map(n => ({ name: vendor(n), via: 'Device record' }));
    const fromAgent = (win && Array.isArray(win.thirdPartyAv) ? win.thirdPartyAv : []).map(n => ({ name: vendor(n), via: 'Windows Security Center' }));
    const products = [...new Map([...fromTools, ...fromRecord, ...fromAgent].filter(p => p.name).map(p => [p.name, p])).values()];
    const nonDefender = products.filter(p => !/Microsoft Defender/.test(p.name));
    const defenderOn = win && win.av != null ? (win.av === true && win.rtp === true) : null;
    let protection, protNote = '';
    if (nonDefender.length) protection = 'edr';
    else if (products.some(p => /Defender/.test(p.name)) || defenderOn) protection = defenderOn === false ? 'off' : 'av';
    else protection = win ? 'none' : 'unknown';
    const avs = nonDefender.filter(p => !MDR_ONLY.has(p.name));
    if (avs.length > 1) protNote = `Two AV products (${avs.map(p => p.name).join(' and ')}) can conflict`;
    else if (protection === 'av' && clientEdr.length && AGENTABLE.has(kind)) protNote = `Defender only. This client’s standard is ${clientEdr.join(', ')}`;
    else if (protection === 'off') protNote = 'Defender is off and no other AV is reported';
    else if (protection === 'none') protNote = 'No antivirus reported by the Liongard agent';
    if (win && win.sigOld && protection !== 'edr') protNote = [protNote, 'Defender signatures out of date'].filter(Boolean).join('. ');

    const rmms = byCat('rmm');
    const backups = byCat('backup');
    const required = AGENTABLE.has(kind) ? (policy[kind === 'Server' ? 'server' : 'workstation'] || []) : [];
    const has = k => k === 'edr' ? protection === 'edr' || (protection === 'av' && !clientEdr.length) : byCat(k).length > 0;
    const gaps = required.filter(k => !has(k));
    const unconfirmed = gaps.filter(k => silent(k).length);   // could be in a tool that doesn't report devices to Liongard
    const missing = gaps.filter(k => !silent(k).length);
    const status = Object.fromEntries(cats.map(c => [c.key, has(c.key) ? 'ok' : missing.includes(c.key) ? 'bad' : unconfirmed.includes(c.key) ? 'warn' : 'none']));
    const managed = AGENTABLE.has(kind) && (rmms.length > 0 || byCat('edr').length > 0 || byCat('agent').length > 0 || nonDefender.length > 0);

    const defender = protection === 'edr' ? 'ok' : !win || win.av == null ? 'none' : (win.av === true && win.rtp === true && !win.sigOld) ? 'ok' : 'bad';
    const firewall = !win || !win.fw ? 'none' : (win.fw.d && win.fw.p && win.fw.u) ? 'ok' : 'bad';
    const pending = win && Array.isArray(win.pending) ? win.pending.length : null;
    const bitlocker = !win ? 'none' : bitlockerHosts.has(short(d.host)) ? 'bad' : 'ok';
    const homeProEnded = sup && sup.entDate && !editionKnown && new Date(sup.date) < now;

    const notes = [];
    if (!win && d.inspectors.some(i => winUnread.has(i.systemId))) notes.push('Couldn’t read this device’s Windows agent data from Liongard, so its protection, firewall and updates are unknown');
    if (missing.length) notes.push(`Missing ${missing.map(k => (CATS.find(c => c.key === k) || {}).label).join(', ')}`);
    for (const k of unconfirmed) { const t = silent(k); notes.push(`No ${(CATS.find(c => c.key === k) || {}).label} seen. Confirm in ${t.slice(0, 3).join(', ')}${t.length > 3 ? ` or ${t.length - 3} more` : ''}`); }
    if (protNote) notes.push(protNote);
    if (rmms.filter(a => /RMM/.test(profileOf(a).role)).length > 1) notes.push(`Two RMMs (${rmms.join(', ')})`);
    if (stale) notes.push(`Not seen for ${seenDays} days`);
    if (homeProEnded) notes.push(`${sup.label}: Home/Pro support has ended; Enterprise ends ${supDate}`);
    else if (sup && supDays < 0) notes.push(`${sup.label} out of support since ${supDate}${/Windows 10/.test(sup.label) ? ' (unless enrolled in Extended Security Updates)' : ''}`);
    else if (sup && supDays <= 180) notes.push(`${sup.label} support ends ${supDate}`);
    if (firewall === 'bad') notes.push('Windows Firewall off on at least one profile');
    if (pending) notes.push(`${pending} update${pending > 1 ? 's' : ''} waiting`);
    if (bitlocker === 'bad') notes.push('BitLocker alert open');

    return {
      id: d.id, host: short(d.host), fqdn: d.host, kind, server: kind === 'Server', state: d.state, reviewed: d.state === 'Inventory', lastSeen: d.lastSeen, seenDays, stale,
      os: /^10\.0\.\d+$/.test(os.trim()) && sup ? sup.label : shortOs(os), osRaw: os, eos: !!(sup && supDays < 0), supDays, supDate, user: d.lastUser,
      hw: [d.manufacturer, d.model].filter(Boolean).join(' '), serial: d.serial,
      managed, tools: status, missing, unconfirmed, required,
      rmm: rmms.map(link), products, protection, backups: backups.map(link), control: byCat('control').map(link), agent: byCat('agent').map(link),
      // Every agent on the device (Liongard agent, RMM, EDR, backup, app control) and whether it's checking in.
      agents: [...new Map(tools.filter(t => AGENT_CATS.includes(t.cat)).sort((a, b) => AGENT_CATS.indexOf(a.cat) - AGENT_CATS.indexOf(b.cat)).map(t => [t.alias, { name: t.alias, cat: t.cat, systemId: t.systemId, systemDetailId: t.systemDetailId, ...agentStatus(d.host, t.alias, t.systemId) }])).values()],
      seenBy: tools.filter(t => !t.cat).map(t => t.alias), defender, firewall, updates: pending == null ? 'none' : pending ? 'warn' : 'ok', pending, bitlocker, notes,
    };
  });

  const kindOrder = ['Server', 'Workstation', 'Mobile', 'Appliance', 'Network & IoT', 'Unknown'];
  rows.sort((a, b) => kindOrder.indexOf(a.kind) - kindOrder.indexOf(b.kind) || (b.missing.length - a.missing.length) || a.host.localeCompare(b.host));
  const endpoints = rows.filter(r => AGENTABLE.has(r.kind));
  const live = endpoints.filter(r => !r.stale);
  const unmanaged = live.filter(r => !r.managed);
  const full = live.filter(r => r.managed && !r.missing.length && !r.unconfirmed.length && !['off', 'none'].includes(r.protection));
  const toCheck = live.filter(r => r.unconfirmed.length);
  const eos = live.filter(r => r.eos);

  // Coverage % per category over live endpoints.
  const pct = (k, list) => list.length ? Math.round(list.filter(r => r.tools[k] === 'ok').length / list.length * 100) : null;
  const catCoverage = cats.map(c => ({ ...c, ws: pct(c.key, live.filter(r => r.kind === 'Workstation')), srv: pct(c.key, live.filter(r => r.kind === 'Server')),
    all: pct(c.key, live), count: live.filter(r => r.tools[c.key] === 'ok').length }));

  // Tool alignment: devices one tool knows about and another doesn't.
  const setOf = pred => new Set(live.filter(pred).map(r => r.host));
  const rmmSet = setOf(r => r.rmm.length), edrSet = setOf(r => r.protection === 'edr'), agentSet = setOf(r => r.agent.length);
  const diff = (a, b) => [...a].filter(x => !b.has(x)).sort();
  const align = [];
  if (deployedBy('rmm').length && clientEdr.length) {
    const few = a => a.length <= 3 ? a.join(', ') : `${a.slice(0, 3).join(', ')} or ${a.length - 3} more`;
    align.push({ t: 'In the RMM, but no EDR', d: `An RMM (${few(deployedBy('rmm'))}) manages them, but no EDR or AV (${few(clientEdr)}) reports them`, hosts: diff(rmmSet, edrSet), sev: 'bad' });
    align.push({ t: 'Protected, but not in the RMM', d: 'An AV/EDR reports them, but no RMM manages them, so they won’t get patches or scripts', hosts: diff(edrSet, rmmSet), sev: 'warn' });
  }
  if (deployedBy('agent').length) {
    const winHosts = new Set(live.filter(r => /windows/i.test(r.osRaw)).map(r => r.host));
    align.push({ t: 'Managed Windows devices with no Liongard agent', d: 'Liongard can’t see Defender, firewall, BitLocker or updates on these', hosts: diff(new Set([...rmmSet, ...edrSet].filter(h => winHosts.has(h))), agentSet), sev: 'warn' });
  }
  const used = {};
  for (const r of live) for (const x of [...r.rmm, ...r.backups, ...r.control, ...r.agent, ...r.products.filter(p => p.systemId)]) (used[x.via || x.name] = used[x.via || x.name] || new Set()).add(r.host);
  const toolCounts = Object.entries(used).map(([tool, hosts]) => ({ tool, cat: catOf(tool), n: hosts.size }))
    .sort((a, b) => CATS.findIndex(c => c.key === a.cat) - CATS.findIndex(c => c.key === b.cat) || b.n - a.n);

  const byKind = kindOrder.map(k => ({ kind: k, n: rows.filter(r => r.kind === k).length, stale: rows.filter(r => r.kind === k && r.stale).length, notReviewed: rows.filter(r => r.kind === k && !r.reviewed).length })).filter(x => x.n);
  const noEdr = live.filter(r => r.managed && r.missing.includes('edr'));
  const managedLive = live.filter(r => r.managed);
  const srvNoBackup = live.filter(r => r.kind === 'Server' && r.missing.includes('backup'));
  const notReviewed = rows.filter(r => !r.reviewed).length;
  const summary = [
    `${live.length} active endpoint${live.length === 1 ? '' : 's'} (${live.filter(r => r.kind === 'Server').length} servers, ${live.filter(r => r.kind === 'Workstation').length} workstations); ${full.length} meet this client’s coverage policy.`,
    ...cats.filter(c => toCheck.some(r => r.unconfirmed.includes(c.key))).map(c => { const h = toCheck.filter(r => r.unconfirmed.includes(c.key)).map(r => r.host); const t = silent(c.key);
      return `No ${c.label} seen on ${h.length} endpoint${h.length > 1 ? 's' : ''}${h.length <= 3 ? ` (${h.join(', ')})` : ''}. Confirm in ${t.slice(0, 3).join(', ')}${t.length > 3 ? ` or ${t.length - 3} other tools` : ''}, which ${t.length > 1 ? 'don\u2019t' : 'doesn\u2019t'} report devices to Liongard.`; }),
    noEdr.length ? `${noEdr.length} managed endpoint${noEdr.length > 1 ? 's have' : ' has'} no ${clientEdr.length <= 2 ? clientEdr.join(' / ') || 'EDR or AV' : 'EDR or AV'}${noEdr.length <= 4 ? `: ${noEdr.map(r => r.host).join(', ')}` : ''}.` : toCheck.some(r => r.unconfirmed.includes('edr')) ? ''
      // Practitioner #8: never "every endpoint is protected" while unmanaged ones can't be checked.
      : unmanaged.length ? `${managedLive.length} managed endpoint${managedLive.length === 1 ? '' : 's'} all have protection; ${unmanaged.length} unmanaged one${unmanaged.length === 1 ? '' : 's'} can’t be checked.` : 'Every managed endpoint has endpoint protection.',
    srvNoBackup.length ? `${srvNoBackup.length} server${srvNoBackup.length > 1 ? 's have' : ' has'} no backup tool reporting ${srvNoBackup.length > 1 ? 'them' : 'it'}.` : '',
    unmanaged.length ? `${unmanaged.length} endpoint${unmanaged.length > 1 ? 's are' : ' is'} on the network with no RMM, EDR or agent.` : '',
    eos.length ? `${eos.length} run an out-of-support OS.` : '',
    notReviewed ? `${notReviewed} of ${rows.length} devices haven’t been reviewed in Liongard yet. They are included here.` : '',
  ].filter(Boolean);

  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, staleDays: STALE_DAYS, summary,
    cats, catCoverage, policy: policyIn, noDeviceData: noDeviceData.map(c => ({ key: c.key, label: c.label, tools: c.tools })), policyOptions: CATS.map(c => ({ key: c.key, label: c.label, deployed: deployedBy(c.key).length > 0 })), clientEdr, customPolicy: !!own,
    kpis: [
      { k: 'Active endpoints', v: live.length, s: `${live.filter(r => r.kind === 'Server').length} servers, ${live.filter(r => r.kind === 'Workstation').length} workstations${endpoints.length - live.length ? `, plus ${endpoints.length - live.length} stale` : ''}`, sev: 'info' },
      { k: 'Meet coverage policy', v: `${full.length} / ${live.length}`, s: toCheck.length ? `${toCheck.length} more to confirm in tools that don\u2019t report devices` : 'Required tools present and protection active', sev: full.length === live.length ? 'ok' : full.length >= live.length * 0.8 ? 'warn' : 'bad' },
      // A zero with unmanaged machines beside it isn't an all-clear: they were never checked.
      { k: 'No EDR / AV', v: noEdr.length + toCheck.filter(r => r.unconfirmed.includes('edr')).length, s: [`${noEdr.length} of ${managedLive.length} managed`, toCheck.filter(r => r.unconfirmed.includes('edr')).length ? `${toCheck.filter(r => r.unconfirmed.includes('edr')).length} to confirm` : '', unmanaged.length ? `${unmanaged.length} unmanaged not checked` : ''].filter(Boolean).join(' · '), sev: noEdr.length ? 'bad' : toCheck.some(r => r.unconfirmed.includes('edr')) || unmanaged.length ? 'warn' : 'ok' },
      { k: 'Not managed', v: unmanaged.length, s: 'Computers with no RMM, EDR or agent', sev: unmanaged.length ? 'bad' : 'ok' },
      { k: 'Out of support OS', v: eos.length, s: eos.length ? [...new Set(eos.map(r => r.os))].join(', ') : 'None', sev: eos.length ? 'bad' : 'ok' },
    ],
    rows, byKind, align, toolCounts: toolCounts.concat(deployed.filter(a => catOf(a) && !used[a] && !['agent'].includes(catOf(a))).map(a => ({ tool: a, cat: catOf(a), n: 0 }))),
    // Kept for the pages that build on this one (Compliance, Cyber security, Lookup).
    managed: live.filter(r => r.managed), unmanaged, discovery: [], bitlockerAlerts: (input.bitlockerAlerts || []).length,
  };
}

// Default policy: workstations need RMM and EDR/AV; servers also need backup when the client has a backup tool.
function defaultPolicy(cats, base) {
  const has = k => cats.some(c => c.key === k);
  const b = base || { workstation: ['rmm', 'edr'], server: ['rmm', 'edr', 'backup'] };
  return { workstation: (b.workstation || []).filter(has), server: (b.server || []).filter(has) };
}

function shortOs(os) { return String(os || '').replace(/^Microsoft /, '').replace(/Windows Server (\d+).*/, 'Server $1').replace(/Windows 11 Enterprise LTSC/, 'Win 11 LTSC').replace(/Windows (\d+) (Pro|Enterprise|Home)\b.*/, 'Win $1 $2'); }

module.exports = { id: 'coverage', usesStack: true, collect, compute, alertTarget, vendor, kindOf, defaultPolicy };
