// Electron main process: owns the API key, talks to Liongard, runs the reconciliation rules.
// The renderer only ever receives the computed page model.
const VALIDATE = require('./validate');
const { app, BrowserWindow, ipcMain, safeStorage, shell, dialog, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { LiongardApi } = require('./api');
const PANELS = require('./panels');
const STACK = require('./stack');
const ICONS = require('./icons');

// Dev runs (npm start) keep their original settings folder; installed copies use "Liongard Ops Portal".
if (!app.isPackaged) app.setName('liongard-ops-portal');

const userFile = n => path.join(app.getPath('userData'), n);
// Write to a temp file and rename, so a crash mid-write never leaves a half-written file.
// Owner-only file mode: settings and caches hold client names, people and devices; credentials.bin holds the encrypted key.
const writeFileSafe = (f, data) => { const t = userFile(`${f}.tmp`); fs.writeFileSync(t, data, { mode: 0o600 }); fs.renameSync(t, userFile(f)); };
// Caches can always be pulled again, so one that can't be read is simply treated as missing.
const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(userFile(f), 'utf8')); } catch { return d; } };
const writeJson = (f, v) => writeFileSafe(f, JSON.stringify(v, null, 2));
// The MSP's own work (settings, statuses, marks, remediation, score history) can't be pulled again from Liongard.
// A missing file starts empty. A file that can't be parsed is set aside as <name>.corrupt-<time> (never overwritten),
// and the last good copy (<name>.bak, kept on every save) is used instead. Any other read error stops the save.
const STORES = ['settings.json', 'action-status.json', 'compliance-status.json', 'compliance-history.json', 'remediation.json'];
const storeWarnings = [];
function readStore(f, d = {}) {
  let text;
  try { text = fs.readFileSync(userFile(f), 'utf8'); } catch (err) {
    if (err.code === 'ENOENT') return d;
    throw new Error(`Couldn't read your saved ${f} (${err.code || err.message}), so nothing was changed.`);
  }
  try { return JSON.parse(text); } catch {
    const aside = `${f}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    try { fs.renameSync(userFile(f), userFile(aside)); } catch { throw new Error(`Your saved ${f} is damaged and couldn't be set aside, so nothing was changed.`); }
    let back = null;
    try { back = JSON.parse(fs.readFileSync(userFile(`${f}.bak`), 'utf8')); } catch {}
    storeWarnings.push(`${f} was damaged. It was kept as ${aside}${back ? ' and the last good copy was restored' : '; nothing could be restored'}.`);
    if (back) writeFileSafe(f, JSON.stringify(back, null, 2));
    return back || d;
  }
}
function writeStore(f, v) {
  try { fs.copyFileSync(userFile(f), userFile(`${f}.bak`)); fs.chmodSync(userFile(`${f}.bak`), 0o600); } catch {}
  writeJson(f, v);
}
// The app's own pages: only they may call the main process, and only they may load in the window.
const OWN = require('node:url').pathToFileURL(path.join(__dirname, '../renderer')).href + '/';
const handle = (channel, fn) => ipcMain.handle(channel, (e, ...args) => {
  if (!e.senderFrame || !e.senderFrame.url.startsWith(OWN)) throw new Error('Blocked: request did not come from the portal.');
  return fn(e, ...args);
});
// QA hooks (PORTAL_SNAPSHOT, PORTAL_EVAL, PORTAL_PDF…) only work in development, never in an installed copy.
const qa = n => (app.isPackaged ? undefined : process.env[n]);

let settings = { instance: '', env: null };   // nothing is shown until a key is saved and an environment chosen

function credentials() {
  try {
    const buf = fs.readFileSync(userFile('credentials.bin'));
    return JSON.parse(safeStorage.decryptString(buf));
  } catch { return null; }
}
function api() {
  const c = credentials();
  if (!c) throw new Error('No API key saved yet. Open Settings and add a Liongard access key.');
  return new LiongardApi({ instance: settings.instance, ...c });
}
// Bump when a collector's output shape changes, so caches from older builds are pulled again.
// v2 (0.4): caches without a version are treated as stale (they could lack keys newer pages expect, e.g. Cyber's alerts).
const CACHE_V = 3;   // v3: Identity also carries device links (People & devices)
// Caches are per instance, because environment IDs repeat across Liongard instances.
const cacheName = (panel, envId, instance = settings.instance) => `cache-${instance}-${panel}-${envId}.json`;
function readCache(panel, envId, instance = settings.instance) {
  const raw = readJson(cacheName(panel, envId, instance), null);
  // Never show another instance's data, and re-pull a cache written by an older build (or with no version) whose shape may differ.
  return raw && raw.instance === instance && raw.v === CACHE_V ? raw : null;
}
// Cached pages hold client people, emails and devices: any not refreshed for 30 days (7 or 90, set in Settings) is deleted at startup.
const CACHE_CHOICES = [7, 30, 90];
const cacheDays = () => CACHE_CHOICES.includes(settings.cacheDays) ? settings.cacheDays : 30;
// Old cache files from earlier builds (no instance in the name) are never read again: delete them, and lock down the rest.
function tidyCaches() {
  for (const f of fs.readdirSync(app.getPath('userData'))) {
    if (!/^cache-.*\.json$/.test(f)) continue;
    let old = /^cache-[a-z]+-\d+\.json$/.test(f);
    try { old = old || Date.now() - fs.statSync(userFile(f)).mtimeMs > cacheDays() * 864e5; } catch {}
    if (old) { try { fs.unlinkSync(userFile(f)); } catch {} continue; }
    try { fs.chmodSync(userFile(f), 0o600); } catch {}
  }
  for (const f of [...STORES, 'instance-profile.json', 'credentials.bin', 'icons.json']) { try { fs.chmodSync(userFile(f), 0o600); } catch {} }
}
// Remove every cached page (on a new instance or key, when the key is cleared, or on request).
function clearCaches() {
  let n = 0;
  for (const f of fs.readdirSync(app.getPath('userData'))) if (/^cache-.*\.json$/.test(f)) { try { fs.unlinkSync(userFile(f)); n++; } catch {} }
  return n;
}

handle('settings:get', () => ({ ...settings, hasKey: !!credentials(), ready: !!credentials() && !!settings.env, encryption: safeStorage.isEncryptionAvailable(), warnings: storeWarnings, cacheDays: cacheDays(), version: app.getVersion() }));

handle('settings:saveKey', async (_e, { instance, accessKey, accessSecret }) => {
  if (inFlight) throw new Error('A pull from Liongard is still running. Wait for it to finish, then save the key.');
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Secure key storage (macOS Keychain or Windows DPAPI) is not available, so the key was not saved.');
  const test = new LiongardApi({ instance, accessKey, accessSecret });
  const envs = await test.environments();            // proves the key works before storing it
  const old = credentials();
  writeFileSafe('credentials.bin', safeStorage.encryptString(JSON.stringify({ accessKey, accessSecret })));
  if (instance !== settings.instance) { clearCaches(); settings = { ...settings, env: null }; }   // a different instance: forget the old client and its data
  else if (!old || old.accessKey !== accessKey) clearCaches();   // a different key may see different clients: pull again with it
  settings = { ...settings, instance, lastTest: { at: new Date().toISOString(), environments: envs.length } };
  writeStore('settings.json', settings);
  try { fs.unlinkSync(userFile('instance-profile.json')); } catch {}   // a new key may see a different instance
  return { environments: envs.length };
});

handle('settings:clearKey', () => {
  try { fs.unlinkSync(userFile('credentials.bin')); } catch {}
  try { fs.unlinkSync(userFile('instance-profile.json')); } catch {}
  clearCaches();
  settings = { ...settings, env: null };
  writeStore('settings.json', settings);
});

// Settings › Clear cached client data: every page pulled from Liongard is deleted (the key and the MSP's own work stay).
handle('cache:clear', () => ({ removed: clearCaches() }));


handle('envs:list', async () => api().environments());

handle('env:select', (_e, env) => { settings = { ...settings, env: VALIDATE.envChoice(env) }; writeStore('settings.json', settings); return settings.env; });

// Which inspectors this MSP uses, discovered from the instance when the app connects and refreshed daily.
const discovering = new Map();   // per instance, so a key saved for another instance never gets this one's profile
async function instanceProfile(refresh) {
  const instance = settings.instance;
  const cached = readJson('instance-profile.json', null);
  if (!refresh && cached && cached.instance === instance && cached.v === STACK.PROFILE_V && Date.now() - new Date(cached.pulledOn) < 864e5) return cached;
  if (!discovering.has(instance)) discovering.set(instance, STACK.discoverInstance(api()).then(p => {
    p = { ...p, instance };
    if (instance === settings.instance) { writeJson('instance-profile.json', p); ICONS.ensureIcons(userFile('icons.json'), p.icons || []).catch(() => {}); }
    return p;
  }).finally(() => discovering.delete(instance)));
  return discovering.get(instance);
}
// Inspector icons for the pages ({ "lower-case alias": data URI }). Fetched once from Liongard's image host, then kept locally.
let iconsReady = null;
handle('icons:get', async () => {
  const have = ICONS.iconMap(userFile('icons.json'));
  if (Object.keys(have).length || !credentials()) return have;
  // First run (or an older profile without icon URLs): read the catalogue once and fetch the icons.
  iconsReady = iconsReady || (async () => {
    const prof = readJson('instance-profile.json', null);
    const list = prof && prof.icons ? prof.icons : (await api().inspectorCatalog()).map(i => ({ alias: i.Alias, url: i.Icon || i.Logo })).filter(x => x.alias && x.url);
    await ICONS.ensureIcons(userFile('icons.json'), list);
  })().catch(() => {}).finally(() => { iconsReady = null; });
  await iconsReady;
  return ICONS.iconMap(userFile('icons.json'));
});

handle('stack:profile', async (_e, { refresh } = {}) => {
  if (!credentials()) return null;
  const p = await instanceProfile(refresh);
  return { pulledOn: p.pulledOn, environments: p.environments, catalogue: p.catalogue, metricCatalogue: p.metricCatalogue,
    inUse: p.inUse.map(({ envs, ...i }) => ({ ...i, envCount: envs.length })), notUsed: p.notUsed.length,
    env: settings.env ? STACK.pageFeeds(p, settings.env.ID) : null };
});

// Pages built from other pages' data: which part of their input is which page. They share one copy, so the numbers agree.
const PARTS = {
  cyber: { chg: 'changes', id: 'identity', cov: 'coverage', insp: 'inspectors', mail: 'email', net: 'network' },
  compliance: { cov: 'coverage', id: 'identity', mail: 'email', net: 'network', insp: 'inspectors', lic: 'licences' },
  wallboard: { insp: 'inspectors', mail: 'email' },
  lookup: { id: 'identity', cov: 'coverage', mail: 'email', ai: 'ai' },
  licences: { cov: 'coverage', id: 'identity' },
  actions: { cy: 'cyber', id: 'identity', cov: 'coverage', mail: 'email', net: 'network', insp: 'inspectors', lic: 'licences', life: 'lifecycle' },
  overview: { cy: 'cyber', id: 'identity', cov: 'coverage', mail: 'email', net: 'network', insp: 'inspectors', lic: 'licences', life: 'lifecycle' },
};

// Load one page: from cache, or from Liongard when refreshing. `batch` (Refresh all) shares one API client and one
// timestamp across pages, and lets composite pages reuse parts already pulled in the same batch instead of pulling them again.
// Every load is pinned to the instance and client it started with (`ctx`), so switching client or key mid-pull
// can never cache or record one client's data under another.
let inFlight = 0;
async function loadPanel(id, opts = {}) {
  inFlight++;
  try { return await loadPanelPinned(id, opts); } finally { inFlight--; }
}
async function loadPanelPinned(id, { refresh, batch, cachedOnly, ctx: pin } = {}) {
  const panel = PANELS[id];
  if (!panel) throw new Error(`Unknown panel "${id}".`);
  if (!credentials()) throw new Error('Connect to Liongard first: open the portal page and enter your API key.');
  // `pin` (cached-only reads of another client, for the switcher's last-known state) never reaches Liongard.
  if (pin && !cachedOnly) throw new Error('Bad request.');
  const ctx = (batch && batch.ctx) || pin || { instance: settings.instance, env: settings.env };
  const { env, instance } = ctx;
  if (!env) throw new Error('Pick an environment on the portal page first.');
  const key = statusKey(ctx);
  const client = (batch && batch.client) || api();   // one client per load, so pages and the stack share memoised API calls
  const stamp = () => (batch && batch.pulledOn) || new Date().toISOString();
  const meta = () => ({ source: 'api', pulledOn: stamp(), instance, v: CACHE_V });
  const cache = (part, raw) => writeJson(cacheName(part, env.ID, instance), raw);
  const cached = part => readCache(part, env.ID, instance);
  // Cached only (launcher badges, the side menu and the health ribbon): never call Liongard. If this page, its parts or
  // the stack it reads aren't all on this computer, say so with null instead of pulling them.
  if (cachedOnly) {
    const parts0 = PARTS[id] || {};
    const feed0 = STACK.FEEDS[id];
    const needStack = id === 'stack' || panel.usesStack || (feed0 && !feed0.none);
    const have = id === 'stack' || cached(id) || (panel.partsOnly && Object.values(parts0).length && Object.values(parts0).every(p => cached(p)));
    if (!have || (needStack && !cached('stack'))) return null;
    refresh = false;
  }
  // Lists Liongard cut off at a page limit during this load, kept in the cache so "Partial data" survives Refresh all.
  const cutBefore = (client.truncated || []).length;
  const cutNow = () => (client.truncated || []).slice(cutBefore);
  // The stack (every inspector's Liongard metrics) is pulled at most once per load.
  let stackRaw = null;
  const getStack = async () => {
    if (stackRaw) return stackRaw;
    if (batch && batch.stack) return (stackRaw = batch.stack);
    stackRaw = !refresh && cached('stack');
    if (!stackRaw) { const from = (client.truncated || []).length; stackRaw = { ...(await STACK.collectEnv(client, env)), ...meta() }; stackRaw.truncated = (client.truncated || []).slice(from); cache('stack', stackRaw); }
    if (batch) batch.stack = stackRaw;
    return stackRaw;
  };
  if (id === 'stack') { const st = await getStack(); return { ...panel.compute(st), instance, envId: env.ID, truncated: st.truncated || [] }; }
  const parts = PARTS[id] || {};
  let raw = !refresh && cached(id);
  // A page built only from other pages (partsOnly) is assembled from their caches when they're all there: no new pull.
  if (!raw && !refresh && panel.partsOnly) {
    const got = Object.entries(parts).map(([k, part]) => [k, cached(part)]);
    if (got.every(([, c]) => c)) raw = { environment: env, ...Object.fromEntries(got), source: 'cache', pulledOn: got.map(([, c]) => c.pulledOn).sort()[0], instance, v: CACHE_V };
  }
  if (!raw) {
    // In a batch, a composite page's parts that were already pulled are reused rather than pulled again.
    const fresh = batch ? Object.fromEntries(Object.entries(parts).map(([k, part]) => [k, batch.raws[part]]).filter(([, v]) => v)) : {};
    const collected = await panel.collect(client, env, fresh);   // composite collectors skip the parts in `fresh`
    raw = { ...collected, ...fresh, ...meta() };
    raw.truncated = [...new Set([...cutNow(), ...Object.values(fresh).flatMap(f => f.truncated || [])])];
    cache(id, raw);
    if (batch) batch.raws[id] = raw;
    // A page built from other pages refreshes them too, so they show the same data.
    for (const [k, part] of Object.entries(parts)) if (raw[k] && !raw[k].error && !fresh[k]) {
      const partRaw = { ...raw[k], environment: env, ...meta(), truncated: raw.truncated };
      cache(part, partRaw); if (batch) batch.raws[part] = partRaw;
    }
  } else {
    // ...and reads their latest data, so a refresh on Identity shows on Cyber security straight away.
    for (const [k, part] of Object.entries(parts)) { const c = cached(part); if (c && !(c.pulledOn < raw.pulledOn)) raw = { ...raw, [k]: c }; }   // never swap in older data
  }
  // Stack coverage shows when each agent last checked in: those times come from the tools' device lists that Identity reads.
  if (id === 'actions' || id === 'overview') raw = { ...raw, statuses: readStore('action-status.json')[key] || {}, remediation: readStore('remediation.json')[key] || {} };
  // Compliance: the client's profile (which frameworks apply), the MSP's marks and answers, and the saved score history.
  if (id === 'compliance') raw = { ...raw, profile: (settings.complianceProfile || {})[env.ID] || null, marks: readStore('compliance-status.json')[key] || {}, history: readStore('compliance-history.json')[key] || [], remediation: readStore('remediation.json')[key] || {} };
  if (id === 'coverage') { const idc = cached('identity'); if (idc && Array.isArray(idc.links)) raw = { ...raw, checkins: idc.links.map(l => ({ host: l.host, source: l.source, seen: l.seen })) }; }
  // The client's coverage policy (what workstations and servers must have), set on the Stack coverage page.
  if (settings.msp) raw = { ...raw, msp: settings.msp };   // the MSP's own domains and account names, set on the Identity page
  // One rule for "stale" on every page (Settings › Defaults): devices not seen, accounts not signed in.
  const D = settings.defaults || {};
  raw = { ...raw, thresholds: { device: D.staleDevice || 45, account: D.staleAccount || 90 } };
  // A client with no compliance profile of its own starts from the MSP's default region and target.
  if (id === 'compliance' && !raw.profile && (D.region || D.target)) raw = { ...raw, profile: { industry: '', region: D.region || '', cards: false, insurance: false, iso: false, extra: [], hidden: [], target: D.target || 8, fromDefaults: true } };
  // The client's own policy, or the MSP's default (marked, so it only asks for tools the client actually runs).
  const pol = (settings.coveragePolicy || {})[env.ID] || (D.coveragePolicy && { ...D.coveragePolicy, fromDefault: true });
  if (pol) raw = { ...raw, policy: id === 'coverage' ? pol : raw.policy, coveragePolicy: pol };
  // Pages that read every inspector's metric findings get them alongside their own data (computed once, used twice).
  const feed = STACK.FEEDS[id];
  let stackEnv = null, stackErr = null;
  if (panel.usesStack || (feed && !feed.none)) { try { stackEnv = STACK.computeEnv(await getStack()); } catch (err) { stackErr = String(err.message || err); } }
  const model = { ...panel.compute(panel.usesStack && stackEnv ? { ...raw, stack: stackEnv } : raw), instance, envId: env.ID,
    truncated: [...new Set([...(raw.truncated || []), ...cutNow()])], warnings: storeWarnings.slice() };
  // Save this pull's scores for the trend: one snapshot per data pull (recomputing the same pull replaces it), 120 at most.
  if (!cachedOnly && id === 'compliance' && model.snapshot && model.snapshot.at) {
    const all = readStore('compliance-history.json');
    all[key] = [...(all[key] || []).filter(h => h.at !== model.snapshot.at), model.snapshot].sort((a, b) => a.at.localeCompare(b.at)).slice(-120);
    writeStore('compliance-history.json', all);
  }
  // Record what this pull says about each remediation item, so the Action plan can show it without recomputing Compliance.
  if (!cachedOnly && id === 'compliance' && model.remediation && model.remediation.length) {
    const all = readStore('remediation.json'), mine = all[key] || {};
    let changed = false;
    for (const r of model.remediation) if (mine[r.id] && (mine[r.id].state !== r.state || mine[r.id].seenAt !== model.pulledOn)) { mine[r.id] = { ...mine[r.id], state: r.state, seenAt: model.pulledOn }; changed = true; }
    if (changed) { all[key] = mine; writeStore('remediation.json', all); }
  }
  // Every page also gets what the client's other inspectors report, through Liongard's metrics.
  if (feed && !feed.none) model.more = stackEnv ? STACK.feedFor(id, stackEnv) : { error: stackErr || 'No metric data' };
  return model;
}

handle('panel:load', (_e, { id, refresh } = {}) => loadPanel(id, { refresh }));
// A page's model from what's already cached on this computer, or null. Never calls Liongard (launcher badges, ribbon).
handle('panel:cached', (_e, { id, envId } = {}) => {
  if (!PANELS[id] || !credentials()) return null;
  if (envId == null) return settings.env ? loadPanel(id, { cachedOnly: true }) : null;
  // Another client's last-known state: only the Overview, only from this computer's caches.
  if (id !== 'overview' || !Number.isInteger(+envId) || +envId <= 0 || +envId > 1e9) throw new Error('Bad request.');
  return clientState(+envId);
});
// A small summary of a client's cached Overview (Act now / Review areas and the data age), recomputed only when that
// client's caches or the saved statuses change. Never calls Liongard: with no cache for a client, the answer is null.
const stateMemo = new Map();
const mtime = f => { try { return fs.statSync(userFile(f)).mtimeMs; } catch { return 0; } };
async function clientState(envId) {
  const instance = settings.instance;
  const sig = ['overview', 'stack', 'cyber', 'identity', 'coverage', 'email', 'network', 'inspectors', 'lifecycle', 'licences'].map(p => mtime(cacheName(p, envId, instance))).join('|') + `|${mtime('action-status.json')}`;
  const k = `${instance}|${envId}`, hit = stateMemo.get(k);
  if (hit && hit.sig === sig) return hit.v;
  let v = null;
  if (sig.split('|').slice(0, -1).some(Number)) {
    const known = settings.env && +settings.env.ID === envId ? settings.env : { ID: envId, Name: '' };
    const m = await loadPanel('overview', { cachedOnly: true, ctx: { instance, env: known } }).catch(() => null);
    if (m) {
      const by = s => (m.areas || []).filter(a => a.state === s).map(a => a.t);
      v = { envId, name: (m.environment && m.environment.Name) || known.Name || '', pulledOn: m.pulledOn || null, act: by('act').length, review: by('review').length, unknown: by('unknown').length, actAreas: by('act'), reviewAreas: by('review') };
    }
  }
  stateMemo.set(k, { sig, v });
  return v;
}

// Action plan statuses (done, in progress, accepted risk…), kept on this computer per instance and client.
const ACTION_STATUS = ['open', 'progress', 'ticketed', 'done', 'accepted', 'na'];
// A PSA ticket number: free text, kept short and plain so it can't carry markup or paths.
const TICKET_RE = /^[A-Za-z0-9#._\/ -]{0,40}$/;
const statusKey = (ctx = settings) => `${ctx.instance}|${ctx.env && ctx.env.ID}`;
handle('actions:setStatus', (_e, { key, status, count, title, ticket } = {}) => {
  if (!settings.env || typeof key !== 'string' || key.length > 200 || !ACTION_STATUS.includes(status)) throw new Error('Bad request.');
  if (ticket != null && (typeof ticket !== 'string' || !TICKET_RE.test(ticket.trim()))) throw new Error('A ticket number can have letters, numbers, spaces and # . _ / - (40 at most).');
  const store = readStore('action-status.json');
  const mine = store[statusKey()] || (store[statusKey()] = {});
  if (status === 'open') delete mine[key];
  else mine[key] = { status, at: new Date().toISOString(), count: Number.isFinite(+count) ? +count : null, title: String(title || '').slice(0, 200), ...(status === 'ticketed' && ticket ? { ticket: ticket.trim() } : {}) };
  writeStore('action-status.json', store);
  return mine[key] || { status: 'open' };
});

// Compliance marks (done, attested, exception) and answers to the policy questions, per instance and client.
// Keys: a check ("mfa"), a policy question ("q:riskAssess"), or a framework control ("c:CE:A7.R4", "c:HIPAA:164.308(a)(1)(ii)(A)").
// Controls take an attestation, the MSP's own evidence ("recorded", with a result) or an accepted risk; each with who,
// the evidence reference and an expiry, shown in the evidence pack apart from Liongard's results.
const MARK_STATES = ['done', 'attested', 'recorded', 'exception', 'yes', 'partly', 'no', 'clear'];
const RECORD_RESULTS = ['met', 'partly', 'notmet', 'na'];
handle('compliance:mark', (_e, { key, state, note, by, until, ref, result } = {}) => {
  const ctl = typeof key === 'string' && /^c:[A-Z0-9]{2,6}:[A-Za-z0-9.()\- ]{1,40}$/.test(key);
  if (!settings.env || typeof key !== 'string' || !(ctl || /^(q:)?[A-Za-z0-9]{1,40}$/.test(key)) || !MARK_STATES.includes(state)) throw new Error('Bad request.');
  if (state === 'recorded' && (!ctl || !RECORD_RESULTS.includes(result))) throw new Error('Choose a result.');
  if (until && !/^\d{4}-\d{2}-\d{2}$/.test(until)) throw new Error('Bad date.');
  const store = readStore('compliance-status.json');
  const mine = store[statusKey()] || (store[statusKey()] = {});
  if (state === 'clear') delete mine[key];
  else mine[key] = { state, at: new Date().toISOString(), note: String(note || '').slice(0, ctl ? 1000 : 300), by: String(by || '').slice(0, 120), until: until || null,
    ...(ctl ? { ref: String(ref || '').slice(0, 200), result: state === 'recorded' ? result : null } : {}) };
  writeStore('compliance-status.json', store);
  return mine[key] || null;
});
// Remediation list: items added from the Compliance drill-down (a person, device, domain, firewall…), with severity,
// owner, due date and status. Kept per instance and client; Compliance checks each one against every data pull.
const REM_STATUS = ['open', 'progress', 'done'], REM_SEV = ['Critical', 'High', 'Medium', 'Low'];
const remId = (check, t) => `${check}|${t}`.slice(0, 300);
handle('remediation:add', (_e, items = []) => {
  if (!settings.env || !Array.isArray(items) || items.length > 500) throw new Error('Bad request.');
  const all = readStore('remediation.json'), mine = all[statusKey()] || (all[statusKey()] = {});
  const str = (v, n) => String(v ?? '').slice(0, n);
  const link = l => l && typeof l === 'object' ? Object.fromEntries(['identityId', 'deviceId', 'systemId', 'systemDetailId', 'lpId', 'inspectorId'].filter(k => l[k] != null).map(k => [k, str(l[k], 120)])) : null;
  for (const i of items) {
    if (!i || !/^[A-Za-z0-9]{1,40}$/.test(i.check || '') || !i.t) continue;
    const id = remId(i.check, str(i.t, 200));
    if (!mine[id]) mine[id] = { check: i.check, checkName: str(i.checkName, 120), kind: str(i.kind, 20), t: str(i.t, 200), d: str(i.d, 300), tool: str(i.tool, 80), link: link(i.link), sev: REM_SEV.includes(i.sev) ? i.sev : 'Medium', owner: '', due: null, status: 'open', at: new Date().toISOString(), doneAt: null };
  }
  writeStore('remediation.json', all);
  return Object.keys(mine).length;
});
handle('remediation:update', (_e, { id, sev, owner, due, status, remove } = {}) => {
  if (!settings.env || typeof id !== 'string' || id.length > 300) throw new Error('Bad request.');
  const all = readStore('remediation.json'), mine = all[statusKey()] || {};
  const r = mine[id]; if (!r) throw new Error('That item is no longer on the list.');
  if (remove) delete mine[id];
  else {
    if (sev !== undefined) { if (!REM_SEV.includes(sev)) throw new Error('Bad severity.'); r.sev = sev; }
    if (owner !== undefined) r.owner = String(owner).slice(0, 80);
    if (due !== undefined) { if (due && !/^\d{4}-\d{2}-\d{2}$/.test(due)) throw new Error('Bad date.'); r.due = due || null; }
    if (status !== undefined) { if (!REM_STATUS.includes(status)) throw new Error('Bad status.'); if (status === 'done' && r.status !== 'done') r.doneAt = new Date().toISOString(); if (status !== 'done') r.doneAt = null; r.status = status; }
  }
  all[statusKey()] = mine; writeStore('remediation.json', all);
  return mine[id] || null;
});
handle('compliance:profile', (_e, p) => {
  if (!settings.env) return null;
  const all = { ...(settings.complianceProfile || {}) };
  const keys = a => [...new Set((a || []).map(String).filter(k => /^[A-Z0-9]{2,6}$/.test(k)))];
  if (p) all[settings.env.ID] = { industry: String(p.industry || '').slice(0, 40), region: String(p.region || '').slice(0, 40), cards: !!p.cards, insurance: !!p.insurance, iso: !!p.iso, extra: keys(p.extra), hidden: keys(p.hidden), target: Math.min(10, Math.max(1, Math.round((+p.target || 8) * 2) / 2)), name: settings.env.Name };
  else delete all[settings.env.ID];
  settings = { ...settings, complianceProfile: all };
  writeStore('settings.json', settings);
  return all[settings.env.ID] || null;
});

// Refresh all: every page for this client in one pass, one timestamp, one API client (repeat calls are memoised),
// parts pulled once. Pages are done in an order that lets composite pages reuse what's already been pulled.
const REFRESH_ORDER = ['identity', 'coverage', 'email', 'network', 'inspectors', 'changes', 'licences', 'lifecycle', 'ai', 'cyber', 'compliance', 'actions', 'overview', 'wallboard', 'lookup', 'stack', 'register'];
let refreshing = null;
handle('client:refreshAll', async e => {
  const ctx = { instance: settings.instance, env: settings.env };
  if (refreshing) {
    if (refreshing.key === statusKey(ctx)) return refreshing.p;
    throw new Error(`Still refreshing ${refreshing.name}. Try again when it finishes.`);
  }
  const batch = { client: api(), pulledOn: new Date().toISOString(), raws: {}, stack: null, ctx };
  const done = [], failed = [];
  const p = (async () => {
    for (const id of REFRESH_ORDER.filter(x => PANELS[x])) {
      try { e.sender.send('client:progress', { id, n: done.length + failed.length, of: REFRESH_ORDER.length }); } catch {}
      try { await loadPanel(id, { refresh: true, batch }); done.push(id); } catch (err) { failed.push({ id, error: String(err.message || err) }); }
    }
    const r = { pulledOn: batch.pulledOn, done, failed, calls: batch.client.calls || null };
    // For Settings › Connection: how much of Liongard's API the last Refresh all used.
    settings = { ...settings, lastRefresh: { at: batch.pulledOn, calls: r.calls, ms: Date.now() - Date.parse(batch.pulledOn), client: ctx.env && ctx.env.Name } };
    try { writeStore('settings.json', settings); } catch {}
    return r;
  })();
  refreshing = { key: statusKey(ctx), name: (ctx.env && ctx.env.Name) || 'another client', p: p.finally(() => { refreshing = null; }) };
  return refreshing.p;
});

// "Which devices?" for a metric that only reports a count: run Liongard's own query for that metric without its
// length(...) wrapper on the system's dataprint, so the items behind the number come back. Read-only, on demand.
// Name each item by the most telling field, then add a few useful details (status, last seen, OS…), not internal IDs.
const NAME_KEYS = ['hostname', 'host_name', 'computername', 'computer_name', 'devicename', 'device_name', 'machinename', 'displayname', 'display_name', 'name', 'username', 'user_name', 'upn', 'userprincipalname', 'email', 'mail', 'description', 'client_code', 'id'];
const DETAIL = /status|online|health|last.?(seen|check|login|logon|sign|contact|audit|reboot)|^os$|operating.?system|os.?name|site|user|version|state|type|ip/i;
// Epoch timestamps (Datto's lastSeen is milliseconds) read as dates.
const when = (k, v) => typeof v === 'number' && /last|seen|date|time|on$/i.test(k) && (v > 1e12 || (v > 1e9 && v < 1e10)) ? new Date(v > 1e12 ? v : v * 1000).toISOString().slice(0, 10) : v;
const itemNames = rows => rows.map(x => {
  if (x == null || typeof x !== 'object') return String(x);
  const keys = Object.keys(x), lc = new Map(keys.map(k => [k.toLowerCase(), k]));
  const k = NAME_KEYS.map(n => lc.get(n)).find(kk => kk && x[kk] != null && x[kk] !== '') || keys[0];
  const extra = keys.filter(kk => kk !== k && DETAIL.test(kk) && !/(id|uid|guid)$/i.test(kk) && x[kk] != null && x[kk] !== '' && typeof x[kk] !== 'object').slice(0, 3).map(kk => `${kk}: ${when(kk, x[kk])}`).join(' · ');
  return extra ? `${x[k]} (${extra})` : String(x[k]);
});
handle('metric:items', async (_e, { metric, systemDetailId } = {}) => {
  if (typeof metric !== 'string' || metric.length > 300 || !Number.isInteger(+systemDetailId)) throw new Error('Bad request.');
  const client = api();
  const query = await client.metricQuery(metric);
  if (!query) return { error: 'Liongard didn’t return a definition for this metric.' };
  const q = query.trim();
  const inner = (/^length\(\s*([\s\S]+)\s*\)$/.exec(q) || /^([\s\S]+?)\s*\|\s*length\(\s*@\s*\)$/.exec(q) || [])[1];
  if (!inner) return { error: 'This number is a calculation Liongard doesn’t break down into items.', query: q };
  const v = await client.evaluate(+systemDetailId, inner);
  const rows = Array.isArray(v) ? v.flat() : v == null ? [] : [v];
  return { items: itemNames(rows.filter(x => x != null && x !== '')).slice(0, 500), query: inner };
});

// PDF of the current page (the renderer switches to its print layout first).
handle('export:pdf', async (e, { name, landscape } = {}) => {
  const win = BrowserWindow.fromWebContents(e.sender);
  const filePath = qa('PORTAL_PDF') || (await dialog.showSaveDialog(win, { defaultPath: `${name || 'ops-portal'}.pdf`.replace(/\s+/g, '-'), filters: [{ name: 'PDF', extensions: ['pdf'] }] })).filePath;   // PORTAL_PDF: QA only
  if (!filePath) return null;
  win.setBackgroundColor('#ffffff');   // the window's dark backdrop otherwise shows in the page margins
  const pdf = await e.sender.printToPDF({ printBackground: true, pageSize: 'A4', landscape: !!landscape, margins: { top: 0.5, bottom: 0.6, left: 0.45, right: 0.45 },
    displayHeaderFooter: true, headerTemplate: '<span></span>',
    footerTemplate: '<div style="font:9px Arial;color:#667;width:100%;padding:0 36px;display:flex;justify-content:space-between"><span class="title"></span><span>Powered by Liongard&rsquo;s Data Lake</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>' });
  win.setBackgroundColor('#0c1722');
  fs.writeFileSync(filePath, pdf);
  return filePath;
});

// CSV of one table.
handle('export:csv', async (e, { name, csv }) => {
  const { filePath } = await dialog.showSaveDialog(BrowserWindow.fromWebContents(e.sender), { defaultPath: `${name || 'table'}.csv`.replace(/\s+/g, '-'), filters: [{ name: 'CSV', extensions: ['csv'] }] });
  if (filePath) fs.writeFileSync(filePath, '\ufeff' + csv);   // BOM so Excel reads UTF-8
  return filePath || null;
});

handle('msp:set', (_e, msp) => {
  const clean = a => [...new Set((a || []).map(x => String(x).trim()).filter(Boolean))].slice(0, 20);
  settings = { ...settings, msp: msp ? { domains: clean(msp.domains).map(d => d.replace(/^@/, '').toLowerCase()), names: clean(msp.names) } : undefined };
  writeStore('settings.json', settings);
  return settings.msp || null;
});

handle('coverage:policy', (_e, policy) => {
  if (!settings.env) return null;
  const all = { ...(settings.coveragePolicy || {}) };
  if (policy) all[settings.env.ID] = { workstation: [...(policy.workstation || [])], server: [...(policy.server || [])], name: settings.env.Name }; else delete all[settings.env.ID];
  settings = { ...settings, coveragePolicy: all };
  writeStore('settings.json', settings);
  return all[settings.env.ID] || null;
});

// Any other text file (for example a calendar of renewals). Only these plain-text types can be saved.
const EXPORT_TYPES = ['ics', 'txt', 'md', 'json'];
handle('export:file', async (e, { name, ext, content, label }) => {
  if (!EXPORT_TYPES.includes(String(ext || '').toLowerCase())) throw new Error('Unsupported file type.');
  if (typeof content !== 'string') throw new Error('Bad request.');
  const { filePath } = await dialog.showSaveDialog(BrowserWindow.fromWebContents(e.sender), { defaultPath: `${name || 'export'}.${ext}`.replace(/\s+/g, '-'), filters: [{ name: label || ext.toUpperCase(), extensions: [ext] }] });
  if (filePath) fs.writeFileSync(filePath, content);
  return filePath || null;
});

handle('export:html', async (e, html) => {
  const { filePath } = await dialog.showSaveDialog(BrowserWindow.fromWebContents(e.sender), {
    defaultPath: `ops-portal-${(settings.env && settings.env.Name) || 'liongard'}.html`.replace(/\s+/g, '-'),
    filters: [{ name: 'HTML', extensions: ['html'] }],
  });
  if (filePath) fs.writeFileSync(filePath, html);
  return filePath || null;
});

// ---------- Settings page ----------
const CATS = ['rmm', 'edr', 'control', 'backup', 'agent'];
const REGIONS = ['United Kingdom', 'European Union', 'United States', 'Australia', 'South Africa', 'Other'];
// The MSP's currency for prices it enters (seat prices), shown on every page that shows money.
const CURRENCIES = ['GBP', 'EUR', 'USD', 'AUD', 'NZD', 'CAD', 'ZAR', 'CHF', 'SEK', 'NOK', 'DKK', 'PLN', 'SGD', 'INR', 'JPY'];
const clean = (v, n) => String(v ?? '').trim().slice(0, n);
// The settings the Settings page can change. Anything else in the patch is ignored; every value is checked.
const SETTERS = {
  branding: b => {
    if (!b) return undefined;
    const logo = typeof b.logo === 'string' && /^data:image\/(png|jpeg|svg\+xml|webp);base64,[A-Za-z0-9+/=]+$/.test(b.logo) && b.logo.length <= 500000 ? b.logo : null;
    if (b.logo && !logo) throw new Error('The logo must be a PNG, JPEG, SVG or WebP image under about 350 KB.');
    return { name: clean(b.name, 60), logo };
  },
  prices: p => VALIDATE.priceList(p),   // decimal commas read correctly; bad entries rejected, never silently dropped
  cacheDays: d => { if (!CACHE_CHOICES.includes(+d)) throw new Error('Choose 7, 30 or 90 days.'); return +d; },
  defaults: d => {
    if (!d) return undefined;
    const days = (v, lo, hi) => v == null || v === '' ? undefined : Math.min(hi, Math.max(lo, Math.round(+v) || lo));
    const list = a => [...new Set((a || []).filter(x => CATS.includes(x)))];
    return {
      target: d.target == null || d.target === '' ? undefined : Math.min(10, Math.max(1, Math.round(+d.target * 2) / 2)),
      region: REGIONS.includes(d.region) ? d.region : undefined,
      currency: CURRENCIES.includes(d.currency) ? d.currency : undefined,
      staleDevice: days(d.staleDevice, 7, 365), staleAccount: days(d.staleAccount, 14, 730),
      coveragePolicy: d.coveragePolicy ? { workstation: list(d.coveragePolicy.workstation), server: list(d.coveragePolicy.server) } : undefined,
    };
  },
};
handle('settings:update', (_e, patch = {}) => {
  if (!patch || typeof patch !== 'object') throw new Error('Bad request.');
  const next = { ...settings };
  for (const [k, fn] of Object.entries(SETTERS)) if (k in patch) { const v = fn(patch[k]); if (v === undefined) delete next[k]; else next[k] = v; }
  settings = next;
  writeStore('settings.json', settings);
  if ('cacheDays' in patch) tidyCaches();   // a shorter period applies straight away
  return { ok: true };
});
// Test connection: the saved key against the instance, without changing anything.
handle('settings:testKey', async () => {
  const envs = await api().environments();
  settings = { ...settings, lastTest: { at: new Date().toISOString(), environments: envs.length } };
  writeStore('settings.json', settings);
  return settings.lastTest;
});
// What's kept on this computer: cached pages (and for how many clients) and the MSP's own saved work.
handle('app:info', () => {
  const dir = app.getPath('userData');
  let pages = 0, bytes = 0, oldest = null; const clients = new Set(), overviews = new Set();
  for (const f of fs.readdirSync(dir)) {
    const m = /^cache-(.+)-([a-z]+)-(\d+)\.json$/.exec(f); if (!m) continue;
    try { const st = fs.statSync(path.join(dir, f)); pages++; bytes += st.size; clients.add(`${m[1]}|${m[3]}`); if (!oldest || st.mtimeMs < oldest) oldest = st.mtimeMs; } catch {}
    if (m[1] === settings.instance && ['overview', 'cyber', 'stack'].includes(m[2])) overviews.add(+m[3]);
  }
  const changed = f => { try { return fs.statSync(userFile(f)).mtime.toISOString(); } catch { return null; } };
  const count = (f, per) => { let all = {}; try { all = readStore(f); } catch {} const keys = Object.keys(all); return { clients: keys.length, items: keys.reduce((n, k) => n + per(all[k]), 0), changed: changed(f) }; };
  const size = v => Array.isArray(v) ? v.length : Object.keys(v || {}).length;
  return {
    version: app.getVersion(), cache: { pages, clients: clients.size, bytes, oldest: oldest && new Date(oldest).toISOString(), days: cacheDays(), envIds: [...overviews].slice(0, 500) },
    stores: [
      { what: 'Action plan statuses', ...count('action-status.json', size) },
      { what: 'Remediation lists', ...count('remediation.json', size) },
      { what: 'Compliance marks and answers', ...count('compliance-status.json', size) },
      { what: 'Compliance score history (snapshots)', ...count('compliance-history.json', size) },
    ],
    warnings: storeWarnings,
  };
});
// Export and import of the MSP's own work (never the key or cached client data), for a backup, a new computer or a colleague.
const EXPORT_KIND = 'liongard-ops-portal-backup';
const EXPORT_SETTINGS = ['msp', 'coveragePolicy', 'complianceProfile', 'branding', 'prices', 'defaults', 'cacheDays'];
handle('data:export', async e => {
  const out = { kind: EXPORT_KIND, version: 1, app: app.getVersion(), exportedAt: new Date().toISOString(), instance: settings.instance,
    settings: Object.fromEntries(EXPORT_SETTINGS.filter(k => settings[k] != null).map(k => [k, settings[k]])),
    stores: Object.fromEntries(STORES.filter(f => f !== 'settings.json').map(f => [f, readStore(f)])) };
  const { filePath } = await dialog.showSaveDialog(BrowserWindow.fromWebContents(e.sender), { defaultPath: `ops-portal-backup-${new Date().toISOString().slice(0, 10)}.json`, filters: [{ name: 'Ops Portal backup', extensions: ['json'] }] });
  if (!filePath) return null;
  fs.writeFileSync(filePath, JSON.stringify(out, null, 2), { mode: 0o600 });
  return filePath;
});
// Import is two steps: read and summarise what would change, then apply only after the user confirms.
let pendingImport = null;
handle('data:import', async e => {
  const { filePaths } = await dialog.showOpenDialog(BrowserWindow.fromWebContents(e.sender), { properties: ['openFile'], filters: [{ name: 'Ops Portal backup', extensions: ['json'] }] });
  if (!filePaths || !filePaths[0]) return null;
  if (fs.statSync(filePaths[0]).size > 20e6) throw new Error('That file is too large to be an Ops Portal backup.');
  let data; try { data = JSON.parse(fs.readFileSync(filePaths[0], 'utf8')); } catch { throw new Error('That file isn’t valid JSON.'); }
  if (!data || data.kind !== EXPORT_KIND || typeof data.stores !== 'object') throw new Error('That file isn’t an Ops Portal backup.');
  const summary = [];
  for (const f of STORES.filter(x => x !== 'settings.json')) {
    const inc = data.stores[f]; if (!inc || typeof inc !== 'object' || Array.isArray(inc)) continue;
    const have = readStore(f); let added = 0, replaced = 0;
    for (const [k, v] of Object.entries(inc)) {
      if (!/^[a-z0-9-]*\|\d+$/i.test(k) || v == null || typeof v !== 'object') continue;
      const items = Array.isArray(v) ? v : Object.keys(v);
      const mine = have[k] || (Array.isArray(v) ? [] : {});
      if (Array.isArray(v)) added += v.filter(h => !(mine || []).some(x => x.at === h.at)).length;
      else for (const id of items) mine[id] ? replaced++ : added++;
    }
    summary.push({ what: f, added, replaced });
  }
  const st = data.settings || {};
  pendingImport = { data, at: Date.now() };
  return { file: path.basename(filePaths[0]), exportedAt: data.exportedAt, instance: data.instance, otherInstance: !!data.instance && data.instance !== settings.instance, summary,
    settings: EXPORT_SETTINGS.filter(k => st[k] != null) };
});
handle('data:importApply', () => {
  if (!pendingImport || Date.now() - pendingImport.at > 10 * 60e3) throw new Error('Choose the file again: the import timed out.');
  const { data } = pendingImport; pendingImport = null;
  for (const f of STORES.filter(x => x !== 'settings.json')) {
    const inc = data.stores[f]; if (!inc || typeof inc !== 'object' || Array.isArray(inc)) continue;
    const have = readStore(f);
    for (const [k, v] of Object.entries(inc)) {
      if (!/^[a-z0-9-]*\|\d+$/i.test(k) || v == null || typeof v !== 'object') continue;
      if (Array.isArray(v)) { const mine = Array.isArray(have[k]) ? have[k] : []; have[k] = [...mine, ...v.filter(h => h && typeof h.at === 'string' && !mine.some(x => x.at === h.at))].sort((a, b) => a.at.localeCompare(b.at)).slice(-120); }
      else have[k] = { ...(have[k] || {}), ...v };   // the imported item wins where both have it
    }
    writeStore(f, have);
  }
  // Settings: per-client maps merge; MSP-wide values (branding, prices, defaults) fill in only what isn't set here.
  const st = data.settings || {}, next = { ...settings };
  for (const k of ['coveragePolicy', 'complianceProfile']) if (st[k] && typeof st[k] === 'object') next[k] = { ...(next[k] || {}), ...st[k] };
  if (st.msp && !next.msp) next.msp = st.msp;
  for (const k of ['branding', 'prices', 'defaults', 'cacheDays']) if (st[k] != null && next[k] == null) { try { const v = SETTERS[k](st[k]); if (v !== undefined) next[k] = v; } catch {} }
  settings = next; writeStore('settings.json', settings);
  return { ok: true };
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1320, height: 900, minWidth: 420, backgroundColor: '#0c1722', title: 'Liongard Ops Portal',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false },
  });
  // Only local pages inside the app; Liongard links open in the default browser.
  win.webContents.on('will-navigate', (ev, url) => { if (!url.startsWith(OWN)) { ev.preventDefault(); openExternal(url); } });
  win.webContents.setWindowOpenHandler(({ url }) => { openExternal(url); return { action: 'deny' }; });
  win.loadFile(path.join(__dirname, '../renderer/index.html'));
  return win;
}
// Only Liongard, its docs and MITRE ATT&CK open outside the app.
function openExternal(url) { if (/^https:\/\/([a-z0-9-]+\.app\.liongard\.com|docs\.liongard\.com|attack\.mitre\.org)\//i.test(url)) shell.openExternal(url); }

// One copy at a time, so an old window never keeps running stale code. QA snapshots run separately.
if (!qa('PORTAL_SNAPSHOT') && !app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { const w = BrowserWindow.getAllWindows()[0]; if (w) { if (w.isMinimized()) w.restore(); w.focus(); } });

app.whenReady().then(() => {
  try { settings = { ...settings, ...readStore('settings.json') }; } catch (err) { storeWarnings.push(err.message); }
  tidyCaches();
  delete settings.demo;
  // The pages need no camera, microphone, location, notifications…: refuse every permission except writing to the clipboard (Copy buttons).
  const allow = p => p === 'clipboard-sanitized-write';
  session.defaultSession.setPermissionRequestHandler((_wc, p, cb) => cb(allow(p)));
  session.defaultSession.setPermissionCheckHandler((_wc, p) => allow(p));
  const win = createWindow();
  // Headless screenshot for QA: PORTAL_SNAPSHOT=/path/out.png PORTAL_PAGE=licences.html npx electron .
  if (qa('PORTAL_SNAPSHOT')) {
    if (process.env.PORTAL_SIZE) { const [w, h] = process.env.PORTAL_SIZE.split('x').map(Number); win.setContentSize(w, h); }   // e.g. 1920x1080
    if (process.env.PORTAL_PAGE) { const [f, qs] = process.env.PORTAL_PAGE.split('?'); win.loadFile(path.join(__dirname, '../renderer', f), qs ? { search: qs } : {}); }
    win.webContents.once('did-finish-load', () => setTimeout(async () => {
      for (let i = 0; i < 120; i++) {   // wait up to 60 s for a live pull to finish
        if (!(await win.webContents.executeJavaScript('!!document.querySelector(".loading") || document.body.innerText.includes("Finding which inspectors")'))) break;
        await new Promise(r => setTimeout(r, 500));
      }
      const sc = process.env.PORTAL_SCROLL;
      if (sc) await win.webContents.executeJavaScript(/^\d+$/.test(sc) ? `document.querySelectorAll("#licBody h3, #panelBody h3, #panelBody .search")[${+sc}]?.scrollIntoView()` : `document.querySelector(${JSON.stringify(sc)})?.scrollIntoView()`);
      await new Promise(r => setTimeout(r, 300));
      if (process.env.PORTAL_EVAL) console.log('EVAL', JSON.stringify(await win.webContents.executeJavaScript(process.env.PORTAL_EVAL)));   // QA only
      if (process.env.PORTAL_EVAL) await new Promise(r => setTimeout(r, 500));   // let the page paint what the QA step opened
      if (process.env.PORTAL_PDF) { const mode = JSON.stringify(process.env.PORTAL_PDF_MODE || 'full'); await win.webContents.executeJavaScript(`(x => exportPdf(${mode}, (x || {}).title || VIEW.title, (x || {}).kicker))((VIEW.exports || []).find(e => e.mode === ${mode}))`); }
      fs.writeFileSync(process.env.PORTAL_SNAPSHOT, (await win.webContents.capturePage()).toPNG());
      app.quit();
    }, 1500));
  }
});
app.on('window-all-closed', () => app.quit());
