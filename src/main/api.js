// Read-only Liongard API client. Runs in the Electron main process only; the renderer never sees the key.
// v1 = https://{instance}.app.liongard.com/api/v1, v2 = .../api/v2. Auth: X-ROAR-API-KEY = base64("AccessKey:AccessSecret").
// Request formats verified against a live Liongard instance (Oct 2026):
//  - v1 conditions[] use "/" paths, "=" for integers, "is" for booleans; page/pageSize and orderBy[] work.
//  - v2 /timelines/query rejects AnyOf and any Sorting, so environment-wide lookups use v1 /timeline instead.
//  - v2 /dataprints/evaluate requires Pagination even for object results.

const q = c => 'conditions[]=' + encodeURIComponent(JSON.stringify(c));
// Run fn over items with at most `limit` requests in flight.
async function pMap(items, limit, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}
const order = (path, dir = 'desc') => 'orderBy[]=' + encodeURIComponent(JSON.stringify({ path, order: dir }));

// Liongard may throttle above ~100 requests a minute per user: stay under 80, across every client object in this app.
const RATE = 80, WINDOW = 60000, sent = [];
async function throttle() {
  for (;;) {
    const now = Date.now();
    while (sent.length && now - sent[0] > WINDOW) sent.shift();
    if (sent.length < RATE) { sent.push(now); return; }
    await new Promise(r => setTimeout(r, WINDOW - (now - sent[0]) + 25));
  }
}

class LiongardApi {
  constructor({ instance, accessKey, accessSecret }) {
    if (!/^[a-z0-9-]+$/i.test(instance || '')) throw new Error('Instance should look like "us1" or "eu1" (the part before .app.liongard.com).');
    this.instance = instance;
    this.base = `https://${instance}.app.liongard.com/api`;
    this.auth = Buffer.from(`${accessKey}:${accessSecret}`).toString('base64');
  }

  // Each call times out after 60 s. Busy (429) and server errors (5xx) or a dropped connection are retried up to
  // 3 times with growing, jittered waits, honouring Retry-After. A refused key fails straight away.
  // Identical requests within one client's life (one page load, or one Refresh all) are made once and shared.
  req(method, path, body) {
    this._memo = this._memo || new Map();
    const k = `${method} ${path} ${body ? JSON.stringify(body) : ''}`;
    if (!this._memo.has(k)) this._memo.set(k, this._req(method, path, body).catch(e => { this._memo.delete(k); throw e; }));
    return this._memo.get(k);
  }
  // Note a list that was cut off at a page limit, so the page can say "partial" instead of looking complete.
  cut(what) { (this.truncated = this.truncated || []).includes(what) || this.truncated.push(what); }

  async _req(method, path, body) {
    let res;
    for (let attempt = 0; ; attempt++) {
      let retryAfter = 0;
      try {
        await throttle();
        this.calls = (this.calls || 0) + 1;
        res = await fetch(this.base + path, {
          method,
          headers: { 'X-ROAR-API-KEY': this.auth, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(60000),
        });
        if (res.status !== 429 && res.status < 500) break;
        retryAfter = (+res.headers.get('retry-after') || 0) * 1000;
        if (attempt >= 3) break;
      } catch (err) {
        if (attempt >= 3) throw new Error(`${method} ${path.split('?')[0]} failed: ${err.name === 'TimeoutError' ? 'Liongard took too long to answer' : 'could not reach Liongard'} (${err.message}).`);
      }
      await new Promise(r => setTimeout(r, Math.min(30000, Math.max(retryAfter, 1000 * 2 ** attempt + Math.random() * 500))));
    }
    if (res.status === 401 || res.status === 403) throw new Error(`Liongard refused the API key (${res.status}). Check the key, secret and instance.`);
    if (!res.ok) throw new Error(`${method} ${path.split('?')[0]} failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }

  async environments() {
    const rows = await this.v1All('/v1/environments?fields[]=ID&fields[]=Name&fields[]=Visible', 500, 40);   // paged: MSPs can have thousands of clients
    return rows.filter(e => e.Visible !== false).map(e => ({ ID: e.ID, Name: e.Name })).sort((a, b) => a.Name.localeCompare(b.Name));
  }

  // All launchpoints in an environment, enabled and disabled.
  launchpoints(envId) {
    return this.v1All(`/v1/launchpoints?${q({ path: 'Environment/ID', op: '=', value: +envId })}`, 500, 20);
  }

  // The most recent run of every launchpoint in the environment, in one call.
  // Note: "Latest" marks the latest run, not the latest good dataprint. A failed latest run has no SystemDetail.
  async latestRuns(envId) {
    const url = `/v1/timeline?${q({ path: 'Environment/ID', op: '=', value: +envId })}&${q({ path: 'Latest', op: 'is', value: true })}` +
      '&fields[]=ID&fields[]=Launchpoint&fields[]=System&fields[]=SystemDetail&fields[]=Status&fields[]=FinishedAt&fields[]=CreatedOn&fields[]=ExitMessage&pageSize=1000';
    const rows = [];
    for (let page = 0; ; page++) {   // 1,000 launchpoints a page (v1 pages count from 0); large environments take several
      const batch = await this.req('GET', `${url}&page=${page}`);
      rows.push(...batch);
      if (batch.length < 1000) break;
      if (page >= 49) { this.cut(`latest runs (first ${rows.length})`); break; }
    }
    const byLp = new Map();
    for (const t of rows) {
      const lpId = t.Launchpoint && t.Launchpoint.ID;
      if (lpId) byLp.set(lpId, { status: t.Status, at: t.FinishedAt || t.CreatedOn, message: t.ExitMessage || '', systemId: t.System && t.System.ID,
        systemDetailId: t.SystemDetail && t.SystemDetail.ID || null });
    }
    return byLp;
  }

  // Newest run of one launchpoint that produced a dataprint (used when its latest run failed).
  async lastGoodRun(lpId) {
    const rows = await this.req('GET', `/v1/timeline?${q({ path: 'Launchpoint/ID', op: '=', value: +lpId })}&${order('CreatedOn')}` +
      '&fields[]=ID&fields[]=System&fields[]=SystemDetail&fields[]=FinishedAt&fields[]=CreatedOn&fields[]=Status&pageSize=50');
    const t = rows.find(r => r.SystemDetail && r.SystemDetail.ID);
    const sys = rows.find(r => r.System && r.System.ID);   // failed runs can still name the system
    return t ? { systemDetailId: t.SystemDetail.ID, at: t.FinishedAt || t.CreatedOn, systemId: (t.System && t.System.ID) || (sys && sys.System.ID) || null } : null;
  }

  // Launchpoints joined to their last attempt and last good dataprint. Cached for the life of this client.
  systems(envId) {   // the in-flight request is shared, so parts loading in parallel don't each pull launchpoints again
    this._sysP = this._sysP || new Map();
    if (!this._sysP.has(envId)) this._sysP.set(envId, this._systems(envId).catch(e => { this._sysP.delete(envId); throw e; }));
    return this._sysP.get(envId);
  }
  async _systems(envId) {
    const [lps, runs] = await Promise.all([this.launchpoints(envId), this.latestRuns(envId)]);
    const rows = await pMap(lps, 6, async l => {
      const run = runs.get(l.ID);
      let good = run && run.systemDetailId ? { systemDetailId: run.systemDetailId, at: run.at, systemId: run.systemId } : null;
      if (!good && run && l.Enabled !== false) good = await this.lastGoodRun(l.ID);   // latest run failed: find the last good one
      return {
        lpId: l.ID, name: l.Alias, enabled: l.Enabled !== false, status: l.Status,
        inspectorId: l.Inspector && l.Inspector.ID, inspector: l.Inspector && l.Inspector.Alias, category: l.Inspector && l.Inspector.InspectorCategory,
        freq: { type: l.FreqType, interval: l.FreqInterval }, scheduled: !!l.NextScheduledFor && l.FreqType !== 'once',
        lastAttempt: run ? { status: run.status, at: run.at, message: run.message } : null,
        systemId: (l.System && l.System.ID) || (run && run.systemId) || (good && good.systemId) || null,
        systemDetailId: good ? good.systemDetailId : null, inspectedOn: good ? good.at : null,
      };
    });
    return rows;
  }

  // v2 Asset Inventory (Filters and Sorting are required; Page counts from 1 on v2).
  inventory(kind, envId) {   // memoised per client, so panels that share inventory don't fetch it twice
    this._inv = this._inv || new Map();
    const k = `${kind}:${envId}`;
    if (!this._inv.has(k)) this._inv.set(k, this._inventory(kind, envId).catch(e => { this._inv.delete(k); throw e; }));
    return this._inv.get(k);
  }

  async _inventory(kind, envId) {
    const path = kind === 'devices' ? '/v2/inventory/device-profiles/query' : '/v2/inventory/identities/query';
    const key = kind === 'devices' ? 'DeviceProfiles' : 'Identities';
    const out = [];
    for (let page = 1; ; page++) {
      const r = await this.req('POST', path, { Environment: +envId, Filters: [], Sorting: [{ SortBy: 'ID', Direction: 'ASC' }], Pagination: { Page: page, PageSize: 200 } });
      const d = r.Data || {}; out.push(...(d[key] || []));
      if (!d.Pagination || !d.Pagination.HasMoreRows) break;
      if (page >= 99) { this.cut(kind === 'devices' ? `devices (first ${out.length})` : `identities (first ${out.length})`); break; }
    }
    return out;
  }

  // v1 list endpoints page from 0. Follows pages until a short page comes back, or a page brings nothing new
  // (an endpoint that ignores page/pageSize returns the same rows every time).
  async v1All(path, pageSize = 500, maxPages = 20) {
    const out = [], seen = new Set();
    for (let page = 0; ; page++) {
      const rows = await this.req('GET', `${path}${path.includes('?') ? '&' : '?'}page=${page}&pageSize=${pageSize}`);
      const fresh = rows.filter(r => !r || r.ID == null || !seen.has(r.ID));
      fresh.forEach(r => r && r.ID != null && seen.add(r.ID));
      out.push(...fresh);
      if (rows.length < pageSize || !fresh.length) break;
      if (page + 1 >= maxPages) { this.cut(`${path.split('?')[0].replace('/v1/', '')} (first ${out.length})`); break; }
    }
    return out;
  }

  // Change detections since a date (v1; v2 /detections has a different filter model).
  detections(envId, since) {
    const d = new Date(since), v = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')} 00:00:00`;
    return this.v1All(`/v1/detections?${q({ path: 'Environment/ID', op: '=', value: +envId })}&${q({ path: 'CreatedOn', op: '>=', value: v })}&${order('CreatedOn')}`);
  }

  // Alerts (v1 "tasks") for an environment.
  alerts(envId) {
    this._alerts = this._alerts || new Map();
    if (!this._alerts.has(+envId)) this._alerts.set(+envId, this.v1All(`/v1/tasks?${q({ path: 'Environment/ID', op: '=', value: +envId })}`));
    return this._alerts.get(+envId);
  }

  // Liongard's inspector catalogue (every inspector type, used or not).
  inspectorCatalog() { return this.req('GET', '/v1/inspectors'); }

  // One metric's definition by exact name: the JMESPath query Liongard runs on the dataprint (newest inspector version).
  async metricQuery(name) {
    const f = encodeURIComponent(JSON.stringify({ FilterBy: 'Name', Op: 'matches_exactly', Value: name }));
    const r = await this.req('GET', `/v2/metrics?Page=1&PageSize=5&Filters[]=${f}`);
    const d = Array.isArray(r.Data) ? r.Data : (r.Data && r.Data.Data) || [];
    const m = d.find(x => x.Name === name) || d[0];
    const v = m && (m.MetricVersions || []).filter(x => x.Query).sort((a, b) => (b.InspectorVersionID || 0) - (a.InspectorVersionID || 0))[0];
    return v ? v.Query : null;
  }

  // Metric catalogue (Liongard's and the MSP's own): name and inspector only.
  async metricCatalog() {
    const out = [];
    for (let page = 1; page < 100; page++) {
      const r = await this.req('GET', `/v2/metrics?Page=${page}&PageSize=500`);
      const d = Array.isArray(r.Data) ? r.Data : (r.Data && r.Data.Data) || [];
      out.push(...d.map(m => ({ name: m.Name, inspectorId: m.InspectorID || (m.Inspector && (m.Inspector[0] || m.Inspector).ID), enabled: m.Enabled !== false })));
      if (d.length < 500) break;
    }
    return out;
  }

  // Every launchpoint in the instance, across all environments (used to discover the MSP's stack).
  allLaunchpoints() { return this.v1All('/v1/launchpoints', 500, 100); }

  // Latest run of every launchpoint in the instance, in pages.
  allLatestRuns() { return this.v1All(`/v1/timeline?${q({ path: 'Latest', op: 'is', value: true })}&fields[]=ID&fields[]=Launchpoint&fields[]=System&fields[]=SystemDetail&fields[]=Status&fields[]=FinishedAt&fields[]=CreatedOn&fields[]=Environment`, 1000, 50); }

  // Liongard metric values (pre-evaluated on each inspection) for a set of systems.
  // /v2/metrics/evaluate/systems caps PageSize at 250; 25 systems per request keeps each call quick.
  async metricValues(systemIds) {
    const ids = [...new Set(systemIds.filter(Boolean).map(Number))], batches = [];
    for (let i = 0; i < ids.length; i += 25) batches.push(ids.slice(i, i + 25));
    const out = await pMap(batches, 4, async b => {
      const rows = [];
      for (let page = 1; page < 200; page++) {
        const r = await this.req('POST', '/v2/metrics/evaluate/systems', { Systems: b, Pagination: { Page: page, PageSize: 250 } });
        rows.push(...(r.Data || []));
        if (!r.Pagination || !r.Pagination.HasMoreRows) break;
        if (page >= 199) { this.cut(`metric values (first ${rows.length} for some systems)`); break; }
      }
      return rows;
    });
    return out.flat();
  }

  // Run a JMESPath against a dataprint, following pagination for array results.
  async evaluate(systemDetailId, query) {
    let value, page = 1;
    for (;;) {
      const r = await this.req('POST', `/v2/dataprints/evaluate/${systemDetailId}`, { QueryPath: query, Pagination: { Page: page, PageSize: 500 } });
      const d = Array.isArray(r.Data) ? ((r.Data[0] && r.Data[0].Data) || r.Data[0] || {}) : (r.Data || {});
      const v = d.Value !== undefined ? d.Value : d;
      if (!Array.isArray(v)) return v;
      value = (value || []).concat(v);
      if (!d.Pagination || !d.Pagination.HasMoreRows) return value;
      if (page >= 200) { this.cut(`dataprint rows (first ${value.length})`); return value; }   // stop at 100,000 rows
      page++;
    }
  }
}

module.exports = { LiongardApi, pMap };
