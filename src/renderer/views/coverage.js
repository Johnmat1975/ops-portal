// Stack coverage view: every device, the actual products on it, tool alignment and gaps against the client's coverage policy.
window.VIEWS.coverage = {
  title: 'Stack coverage',
  kpiItems: {
    'Active endpoints': (m, c) => m.rows.filter(r => (r.kind === 'Server' || r.kind === 'Workstation') && !r.stale).map(r => ({ t: r.host, d: `${r.kind} · ${r.os || '—'} · ${r.products.map(p => p.name).join(', ') || 'no protection reported'}`, url: LG.device(c, r.id), page: 'lookup', q: r.host })),
    'Meet coverage policy': (m, c) => m.rows.filter(r => (r.kind === 'Server' || r.kind === 'Workstation') && !r.stale).map(r => ({ t: r.host, d: r.notes.join('. ') || 'Meets policy', url: LG.device(c, r.id), sev: r.missing.length ? 'bad' : r.unconfirmed.length || ['off', 'none'].includes(r.protection) ? 'warn' : 'ok' })),
    'No EDR / AV': (m, c) => m.rows.filter(r => !r.stale && ((r.managed && r.missing.includes('edr')) || r.unconfirmed.includes('edr'))).map(r => ({ t: r.host, d: `${r.kind} · ${r.notes.join('. ')}`, url: LG.device(c, r.id), sev: r.missing.includes('edr') ? 'bad' : 'warn' })),
    'Not managed': (m, c) => m.unmanaged.map(r => ({ t: r.host, d: `${r.kind} · ${r.os || '—'} · seen by ${r.seenBy.join(', ') || 'discovery'}`, url: LG.device(c, r.id), sev: 'bad' })),
    'Out of support OS': (m, c) => m.rows.filter(r => r.eos && !r.stale && (r.kind === 'Server' || r.kind === 'Workstation')).map(r => ({ t: r.host, d: `${r.osRaw} · out of support since ${r.supDate}`, url: LG.device(c, r.id), sev: 'bad' })),
  },
  intro: 'Every device this client has, whether or not it has been reviewed in Liongard, with the RMM, AV/EDR and backup products actually on it. A product is shown only when Liongard holds evidence for it on that device.',
  render(m, ctx) {
    const bar = (v, label) => v == null ? '' : `<div class="cbar"><span>${label}</span><div class="track"><div style="width:${v}%;background:${v >= 95 ? 'var(--ok)' : v >= 75 ? 'var(--warn)' : 'var(--crit)'}"></div></div><span class="mono">${v}%</span></div>`;
    const kinds = ['Endpoints', ...m.byKind.map(k => k.kind), 'All'];
    const label = k => ({ Server: 'Servers', Workstation: 'Workstations', Mobile: 'Mobile', Appliance: 'Appliances', 'Network & IoT': 'Network & IoT', Unknown: 'Unknown' }[k] || k);
    const count = k => k === 'Endpoints' ? m.rows.filter(r => r.kind === 'Server' || r.kind === 'Workstation').length : k === 'All' ? m.rows.length : (m.byKind.find(x => x.kind === k) || {}).n;
    const pol = k => (m.policy[k] || []).map(c => (m.policyOptions.find(o => o.key === c) || {}).label).join(', ') || 'nothing';
    const deviceChip = h => { const r = m.rows.find(x => x.host === h); return `<span class="chip c-none mono">${r ? lgA(LG.device(ctx, r.id), esc(h), 'Open this device in Liongard') : esc(h)}</span>`; };
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Coverage and policy</h3>
      <div class="two">
        <div class="card"><h3>Coverage by category</h3><p class="sub">Share of active endpoints with each kind of tool. Stale devices (not seen for ${m.staleDays}+ days) are left out.</p>
          ${m.catCoverage.map(c => `<div class="catrow"><b>${esc(c.label)}</b> <span class="sub" style="margin:0">${esc(c.tools.length <= 3 ? c.tools.join(', ') : `${c.tools.length} tools`)}</span>${bar(c.ws, 'Workstations')}${bar(c.srv, 'Servers')}</div>`).join('')}
          ${m.noDeviceData.length ? `<p class="sub">Can’t be judged per device: ${m.noDeviceData.map(c => `${esc(c.label)} (${esc(c.tools.join(', '))} don’t report devices to Liongard)`).join('; ')}.</p>` : ''}</div>
        <div class="card"><h3>Coverage policy for this client</h3>
          <p style="margin:0">Workstations must have <b>${esc(pol('workstation'))}</b>. Servers must have <b>${esc(pol('server'))}</b>.${m.customPolicy ? '' : ' <span class="sub">(default)</span>'}</p>
          <details class="no-print msp"><summary class="sub">Change what’s required</summary>
            <div class="policy">${['workstation', 'server'].map(k => `<fieldset><legend>${k === 'server' ? 'Servers' : 'Workstations'}</legend>${m.policyOptions.filter(o => o.deployed).map(o => `<label><input type="checkbox" data-pk="${k}" value="${o.key}" ${(m.policy[k] || []).includes(o.key) ? 'checked' : ''}> ${esc(o.label)}</label>`).join('')}</fieldset>`).join('')}</div>
            <div style="display:flex;gap:8px;margin-top:8px"><button type="button" class="btn sm" id="polSave">Save policy</button><button type="button" class="btn ghost sm" id="polReset">Use default</button></div>
          </details>
          <p class="sub">Saved on this computer for ${esc(m.environment.Name)} only. Every page that checks coverage uses it.</p></div>
      </div>
      ${m.align.length ? `<h3 style="margin-top:22px">Do the tools agree?</h3><div class="two">${m.align.map(a => `<div class="card ${a.hosts.length ? `flag${a.sev === 'warn' ? ' warn' : ''}` : ''}"><h3><span class="bignum">${a.hosts.length}</span> ${esc(a.t)}</h3><p class="sub" style="margin:0">${esc(a.d)}.</p>
        ${a.hosts.length ? `<div class="chipwrap tech">${a.hosts.slice(0, 12).map(deviceChip).join('')}</div>${a.hosts.length > 12 ? `<details class="tech"><summary class="sub">Show all ${a.hosts.length}</summary><div class="chipwrap">${a.hosts.slice(12).map(deviceChip).join('')}</div></details>` : ''}` : '<p class="sub" style="margin:0">None.</p>'}</div>`).join('')}</div>` : ''}
      <details class="card tech" style="margin-top:12px"><summary><b>Devices each tool reports</b> <span class="sub">(${m.toolCounts.filter(t => !t.n).length} tools report none to Liongard)</span></summary>
        <div class="tw"><table><thead><tr><th>Tool</th><th>Category</th><th class="c">Active endpoints</th></tr></thead><tbody>${m.toolCounts.map(t => `<tr><td>${esc(t.tool)}</td><td>${esc((m.policyOptions.find(o => o.key === t.cat) || {}).label || '')}</td><td class="c mono">${t.n || '<span class="chip c-warn">None reported</span>'}</td></tr>`).join('')}</tbody></table></div></details>
      <h3 style="margin-top:22px">Devices</h3>
      <div class="filters">
        <div class="quick" id="cvKind">${kinds.map((k, i) => `<button type="button" data-k="${k}" aria-pressed="${i === 0}">${label(k)} <span class="sub">${count(k)}</span></button>`).join('')}</div>
        <select id="cvGap" aria-label="Show"><option value="">Any status</option><option value="gap">Missing a required tool</option><option value="edr">No EDR / AV</option><option value="rmm">No RMM / MDM</option><option value="backup">No backup</option><option value="confirm">To confirm</option><option value="unmanaged">Not managed</option><option value="eos">Out of support OS</option><option value="stale">Stale (${m.staleDays}+ days)</option><option value="review">Not reviewed in Liongard</option><option value="conflict">Two AVs or two RMMs</option></select>
        <select id="cvTool" aria-label="Tool"><option value="">Any tool</option>${[...new Set(m.toolCounts.filter(t => t.n).map(t => t.tool))].map(t => `<option>${esc(t)}</option>`).join('')}</select>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="cvQ" placeholder="Search device, user, OS or product" autocomplete="off" aria-label="Search devices"></div>
      </div>
      <p class="sub" id="cvCount"></p>
      <div class="tw tech"><table id="cvTable"></table></div>
      <div class="legend tech"><span><span class="chip c-ok">EDR</span> Protected by an EDR or third-party AV</span><span><span class="chip c-warn">AV only</span> Defender or basic AV only</span><span><span class="chip c-crit">Off</span> Protection off or none</span><span><span class="chip c-none">Unknown</span> No protection data</span><span>Agents: one icon per agent on the device; the ring is green when it checked in within 7 days, amber when late or the tool’s Liongard data is stale, red when it hasn’t checked in for 30+ days, and grey when Liongard doesn’t record a check-in time. Windows health (AV, firewall, BitLocker, updates) comes from the Liongard Windows agent.</span></div>`;
  },
  after(m, ctx) {
    // Agents: one icon per agent on the device, ringed by whether it's checking in (hover says why).
    const AG_STATE = { ok: 'Checking in', warn: 'Check-in late or tool data stale', bad: 'Not checking in', listed: 'Listed, check-in time unknown' };
    const agentsCell = r => (r.agents || []).length ? `<span class="ags-i">${r.agents.map(a => {
      const icon = toolIcon(a.name) || `<span class="ag-txt">${esc(a.name.split(/\s+/).map(w => w[0]).join('').slice(0, 3))}</span>`;
      const tip = `${a.name}: ${a.why}`;
      return a.systemId ? lgA(LG.system(ctx, a.systemId, a.systemDetailId), `<span class="ag-i ag-${a.state}" title="${esc(tip)}">${icon}</span>`, tip) : `<span class="ag-i ag-${a.state}" title="${esc(tip)}">${icon}</span>`;
    }).join('')}</span>` : '<span class="sub">None seen</span>';
    // Windows health: the four checks Liongard's Windows agent reads, as labelled ticks.
    const healthCell = r => `<span class="wh">${T[r.defender]}<span>AV</span></span><span class="wh">${T[r.firewall]}<span>Firewall</span></span><span class="wh">${T[r.bitlocker]}<span>BitLocker</span></span><span class="wh">${r.pending ? `<span class="chip c-warn">${esc(r.pending)}</span><span>update${r.pending === 1 ? '' : 's'} waiting</span>` : `${T[r.updates]}<span>Updates</span>`}</span>`;
    const T = { ok: '<i class="tick t-ok" title="OK">✓</i>', bad: '<i class="tick t-bad" title="Problem">✕</i>', warn: '<i class="tick t-warn" title="Check">!</i>', none: '<i class="tick t-none" title="Not reported">–</i>' };
    const PROT = { edr: ['c-ok', 'EDR'], av: ['c-warn', 'AV only'], off: ['c-crit', 'Off'], none: ['c-crit', 'None'], unknown: ['c-none', 'Unknown'] };
    const names = list => list.map(x => `${toolIcon(x.name)}${lgA(LG.system(ctx, x.systemId, x.systemDetailId), esc(x.name), `Open ${x.name} in Liongard`)}`).join(', ');
    let kind = 'Endpoints', gap = '', tool = '', q = '';
    let shown = 50, pageKey = '';
    const match = r => {
      if (kind === 'Endpoints' ? !(r.kind === 'Server' || r.kind === 'Workstation') : kind !== 'All' && r.kind !== kind) return false;
      const tools = [...r.rmm, ...r.backups, ...r.control, ...r.agent].map(x => x.name).concat(r.products.map(p => p.via));
      if (tool && !tools.includes(tool)) return false;
      if (gap === 'gap' && !r.missing.length) return false;
      if (['edr', 'rmm', 'backup'].includes(gap) && !(r.missing.includes(gap) || r.unconfirmed.includes(gap))) return false;
      if (gap === 'confirm' && !r.unconfirmed.length) return false;
      if (gap === 'unmanaged' && (r.managed || !(r.kind === 'Server' || r.kind === 'Workstation'))) return false;
      if (gap === 'eos' && !r.eos) return false;
      if (gap === 'stale' && !r.stale) return false;
      if (gap === 'review' && r.reviewed) return false;
      if (gap === 'conflict' && !r.notes.some(n => /^Two /.test(n))) return false;
      return !q || [r.host, r.user, r.os, r.hw, ...tools, ...r.products.map(p => p.name)].join(' ').toLowerCase().includes(q);
    };
    $('cvTable').addEventListener('click', e => { const b = e.target.closest('[data-more]'); if (!b) return; shown = b.dataset.more === 'all' ? Infinity : shown + 50; draw(); });
    const draw = () => {
      const rows = m.rows.filter(match);
      $('cvCount').textContent = `${rows.length} device${rows.length === 1 ? '' : 's'}`;
      // Long lists show 50 at a time (Show more / Show all); CSV and PDFs still include every row.
      if (pageKey !== JSON.stringify([kind, gap, tool, q])) { pageKey = JSON.stringify([kind, gap, tool, q]); shown = 50; }
      $('cvTable').innerHTML = `<thead><tr><th>Device</th><th>OS</th><th>Protection</th><th>RMM / MDM</th><th>Backup</th><th>Other tools</th><th title="Every agent on the device (Liongard agent, RMM, EDR, backup, app control); the ring shows whether it’s checking in">Agents</th><th title="Read by Liongard’s Windows agent: antivirus on, firewall on, no BitLocker alert, updates waiting">Windows health</th><th>Last seen</th><th>Notes</th></tr></thead><tbody>` +
        (rows.map((r, i) => {
          const [pc, pl] = PROT[r.protection] || PROT.unknown;
          const agentable = r.kind === 'Server' || r.kind === 'Workstation';
          return `<tr class="${r.stale ? 'dim' : ''}${i >= shown ? ' paged' : ''}">
          <td class="wrap" style="min-width:140px;max-width:220px" data-csv="${esc(r.host)}" title="${esc([r.hw, r.serial && `Serial ${r.serial}`].filter(Boolean).join(' · '))}"><b class="mono">${lgA(LG.device(ctx, r.id), esc(r.host), 'Open this device in Liongard')}</b> ${pageA('lookup', r.host, '↗', 'Everything about this device (Lookup)')}${r.reviewed ? '' : ' <span class="chip c-none" title="Still in Discovery in Liongard">Not reviewed</span>'}
            <div class="sub" style="margin:0">${esc(r.kind)}${r.user ? ` · ${esc(r.user.replace(/^.*\\/, ''))}` : ''}</div></td>
          <td class="wrap" style="min-width:110px" data-csv="${esc(r.osRaw)}${r.eos ? ` (out of support since ${esc(r.supDate)})` : ''}">${r.eos ? `<span class="chip c-crit" title="Out of support since ${esc(r.supDate)}">${esc(r.os || '—')}</span>` : esc(r.os || '—')}${r.supDate && !r.eos && r.supDays <= 365 ? `<div class="sub" style="margin:0">Support ends ${fmtDate(r.supDate, true)}</div>` : ''}</td>
          <td class="wrap" style="min-width:150px" data-csv="${esc(pl)}: ${esc(r.products.map(p => p.name).join(', '))}">${agentable || r.products.length ? `<span class="chip ${pc}">${pl}</span>` : ''} ${r.products.map(p => `<span class="prod" title="Seen by: ${esc(p.via)}">${toolIcon(p.name)}${p.systemId ? lgA(LG.system(ctx, p.systemId, p.systemDetailId), esc(p.name), `Open ${p.via} in Liongard`) : esc(p.name)}</span>`).join(' ')}</td>
          <td class="wrap" data-csv="${esc(r.rmm.map(x => x.name).join(', '))}">${names(r.rmm) || (r.tools.rmm === 'bad' ? '<span class="chip c-crit">Missing</span>' : r.tools.rmm === 'warn' ? '<span class="chip c-warn">Not seen</span>' : '')}</td>
          <td class="wrap" data-csv="${esc(r.backups.map(x => x.name).join(', '))}">${names(r.backups) || (r.tools.backup === 'bad' ? '<span class="chip c-crit">Missing</span>' : r.tools.backup === 'warn' ? '<span class="chip c-warn">Not seen</span>' : '')}</td>
          <td class="wrap" data-csv="${esc([...r.control, ...r.agent].map(x => x.name).join(', '))}">${names([...r.control, ...r.agent])}</td>
          <td style="min-width:120px" data-csv="${esc((r.agents || []).map(a => `${a.name} (${AG_STATE[a.state]})`).join('; '))}">${agentsCell(r)}</td>
          <td style="min-width:150px" data-csv="AV ${r.defender} / FW ${r.firewall} / BitLocker ${r.bitlocker} / updates ${esc(r.pending ?? 'n/a')}">${agentable && r.agent.length ? healthCell(r) : '<span class="sub">No Liongard agent</span>'}</td>
          <td class="num" data-csv="${esc(r.lastSeen || '')}">${r.lastSeen ? `${r.stale ? `<span class="chip c-warn">${r.seenDays} days</span>` : `${fmtDate(r.lastSeen)}`}` : '—'}</td>
          <td class="wrap notes" style="min-width:260px" data-csv="${esc(r.notes.join('. '))}">${r.notes.length ? `<span class="clamp" title="${esc(r.notes.join('. '))}">${esc(r.notes.join('. '))}</span>` : agentable ? '<span class="sub">Meets policy</span>' : ''}</td></tr>`; }).join('') || '<tr><td colspan="10">No devices match.</td></tr>') + (rows.length > shown ? `<tr class="more-row no-print"><td colspan="10" style="text-align:center">Showing ${shown} of ${rows.length} · <button type="button" class="linkbtn" data-more="50">Show 50 more</button> · <button type="button" class="linkbtn" data-more="all">Show all</button></td></tr>` : '') + '</tbody>';
    };
    const pick = (id, attr, fn) => $(id).addEventListener('click', e => { const b = e.target.closest(`[${attr}]`); if (!b) return; [...$(id).children].forEach(x => x.setAttribute('aria-pressed', x === b)); fn(b.getAttribute(attr)); draw(); });
    pick('cvKind', 'data-k', v => { kind = v; });
    $('cvGap').addEventListener('change', e => { gap = e.target.value; if (gap && !['eos', 'stale', 'review'].includes(gap) && kind !== 'Endpoints' && kind !== 'Server' && kind !== 'Workstation') { kind = 'Endpoints'; [...$('cvKind').children].forEach(x => x.setAttribute('aria-pressed', x.dataset.k === 'Endpoints')); } draw(); });
    $('cvTool').addEventListener('change', e => { tool = e.target.value; draw(); });
    $('cvQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); draw(); });
    draw();
    const save = async policy => { await window.portal.setCoveragePolicy(policy); location.reload(); };
    $('polSave').addEventListener('click', () => { const p = { workstation: [], server: [] }; document.querySelectorAll('[data-pk]:checked').forEach(c => p[c.dataset.pk].push(c.value)); save(p); });
    $('polReset').addEventListener('click', () => save(null));
  },
  how: m => [
    `POST /api/v2/inventory/device-profiles/query  (Environment ${m.environment.ID})  → every device, its state, last seen, and which inspectors link it`,
    'POST /api/v2/metrics/evaluate/systems  → device lists from tools that don’t link devices into inventory (RMM server and workstation lists, EDR endpoint lists, per-device backups)',
    'POST /api/v2/dataprints/evaluate/…  Windows Workstation/Server: Defender status and mode, installed AV, firewall, waiting updates, OS caption',
    `GET  /api/v1/tasks  (Environment/ID = ${m.environment.ID})  → open BitLocker alerts`,
    'Tool categories: the capability map of all 117 Liongard inspectors (src/main/stack-catalog.js) · rules: src/main/panels/coverage.js',
  ].join('\n'),
};
