// Wallboard view: large type for a service-desk screen.
window.VIEWS.wallboard = {
  title: 'Wallboard',
  kpiItems: {
    'Open alerts': (m, c) => (m.openAlerts || []).map(a => ({ t: a.name, d: `${a.priority || ''} · ${a.inspector || ''} · since ${fmtDate(a.created)}`, url: LG.alert(c, a.id), sev: a.priority === 'Critical' ? 'bad' : 'warn' })),
    'Systems failing': m => m.failing.map(f => ({ t: f.name, d: f.why, page: 'inspectors', q: f.name, sev: 'bad' })),
    'Systems stale': m => (m.stale || []).map(f => ({ t: f.name, d: `${f.health} · ${f.why}`, page: 'inspectors', q: f.name, sev: 'warn' })),
    'Domains that can be spoofed': (m, c) => m.domains.filter(d => d.spoofable).map(d => ({ t: d.name, d: `Grade ${d.grade} · ${d.dmarc}`, url: d.sys && LG.system(c, d.sys.systemId, d.sys.systemDetailId), sev: 'bad' })),
  },
  intro: 'Open alerts, inspector health and external exposure, sized for the service-desk screen. Refresh from Liongard to update it.',
  render(m, ctx) {
    const hcol = { Fresh: 'var(--ok)', Due: 'var(--none)', Stale: 'var(--warn)', Failing: 'var(--crit)' };
    const tot = Math.max(1, m.health.reduce((s, h) => s + h.n, 0));
    const spoof = m.domains.filter(d => d.spoofable);
    // an empty column says "All clear" and names what checked, but only when that part was actually read;
    // a part that failed (tile shows —) says "Couldn’t read", never all-clear.
    const read = k => { const t = (m.kpis || []).find(x => x.k === k); return !!t && t.v !== '—'; };
    const clear = (ok, by, why) => ok ? `<li class="wb-clear"><div class="state st-ok"><span class="st-ic" aria-hidden="true">✓</span><div><b>All clear</b><p class="sub">${esc(by)}</p></div></div></li>`
      : `<li class="wb-clear"><div class="state st-blind"><span class="st-ic" aria-hidden="true">!</span><div><b>Couldn’t read</b><p class="sub">${esc(why)}</p></div></div></li>`;
    const col = (id, title, page, body) => `<section class="wb-col"><div class="wb-h"><h3>${title}</h3>${page === 'alerts' ? lgA(LG.alerts(ctx), 'All alerts', 'Open this client\u2019s alerts in Liongard') : pageA(page, '', 'Open →')}</div><ul class="plain wb-list" id="${id}">${body}</ul><div class="wb-more sub" data-for="${id}"></div></section>`;
    return `
      <div class="filters no-print wb-bar"><label class="sub" style="margin:0">Refresh every <select id="wbAuto" aria-label="Auto refresh"><option value="0">Off</option><option value="5">5 minutes</option><option value="15">15 minutes</option><option value="30">30 minutes</option></select></label>
        <button type="button" class="btn ghost sm" id="wbFull">Full screen</button><span class="sub" id="wbNext"></span></div>
      <div class="wall">
        <div class="kpis wb-kpis">${kpiStrip(m.kpis)}</div>
        <div class="wb-grid" id="wbGrid">
          ${col('wbAlerts', `Open alerts <span class="sub">${m.alertGroups.reduce((t, a) => t + a.count, 0)}</span>`, 'alerts', m.alertGroups.map(a => `<li class="wb-${a.priority === 'Critical' || a.priority === 'High' ? 'bad' : a.priority === 'Medium' ? 'warn' : 'none'}">${riskChip(a.priority, a.priority)}<div>${toolIcon(a.inspector)}
            <b>${lgA(LG.alert(ctx, a.ids && a.ids[0]), esc(a.title), 'Open this alert in Liongard')}</b>${a.count > 1 ? ` <span class="mono">×${a.count}</span>` : ''}
            <div class="sub">${a.targets.length ? esc(a.targets.length > 3 ? `${a.targets.slice(0, 3).join(', ')} +${a.targets.length - 3}` : a.targets.join(', ')) + ' · ' : ''}since ${fmtDate(a.oldest)}</div></div></li>`).join('') || clear(read('Open alerts'), 'Checked by Liongard alerts: nothing open.', 'Liongard’s alerts couldn’t be read. Refresh to try again.'))}
          ${col('wbHealth', 'Inspector health', 'inspectors', `<li class="wb-static"><div style="width:100%"><div class="stack">${m.health.map(h => `<div style="width:${h.n / tot * 100}%;background:${hcol[h.h]}" title="${h.h}: ${h.n}"></div>`).join('')}</div>
              <div class="legend">${m.health.map(h => `<span><i class="tick" style="width:12px;height:12px;background:${hcol[h.h]}"></i>${h.h} ${h.n}</span>`).join('')}</div></div></li>` +
            m.failing.map(f => `<li class="wb-bad"><i class="tick t-bad">✕</i><div><b>${toolIcon(f.inspector)}${esc(f.name)}</b><div class="sub">${esc(f.why)}</div></div></li>`).join('') +
            (m.stale || []).map(f => `<li class="wb-warn"><i class="tick t-warn">!</i><div><b>${toolIcon(f.inspector)}${esc(f.name)}</b><div class="sub">${esc(f.health)}: ${esc(f.why)}</div></div></li>`).join('') +
            (!m.failing.length && !(m.stale || []).length ? clear(read('Systems failing'), 'Every inspector is returning fresh data.', 'Inspector health couldn’t be read. Refresh to try again.') : ''))}
          ${col('wbProblems', 'Problems and exposure', 'stack', spoof.map(d => `<li class="wb-bad"><i class="tick t-bad">✕</i><div><b>${d.sys ? lgA(LG.system(ctx, d.sys.systemId, d.sys.systemDetailId), esc(d.name)) : esc(d.name)}</b> <span class="sub">can be spoofed</span><div class="sub">Grade ${esc(d.grade)} · ${esc(d.dmarc)}</div></div></li>`).join('') +
            (m.problems || []).map(p => `<li class="wb-bad"><i class="tick t-bad">✕</i><div><b>${esc(p.label)}</b> <span class="mono">${esc(p.value)}</span><div class="sub">${toolIcon(p.inspector)}${lgA(LG.system(ctx, p.systemId, p.systemDetailId), esc(p.system))} · ${esc(p.inspector)}</div></div></li>`).join('') +
            m.domains.filter(d => !d.spoofable).map(d => `<li class="wb-warn"><i class="tick t-warn">!</i><div><b>${esc(d.name)}</b><div class="sub">${d.certState !== 'pass' ? `Certificate: ${esc(d.cert)}` : `Grade ${esc(d.grade)}`}</div></div></li>`).join('') ||
            clear(read('Domains that can be spoofed'), 'Checked by the email and domain inspectors and Liongard metrics.', 'Domain data couldn’t be read. Refresh to try again.'))}
        </div>
      </div>`;
  },
  after() {
    // Fit the three columns to the screen: no page scrolling, and "+N more" where a list doesn't fit.
    const fit = () => {
      const grid = $('wbGrid'); if (!grid) return;
      const top = grid.getBoundingClientRect().top + window.scrollY;
      grid.style.height = `${Math.max(320, window.innerHeight - top - 48)}px`;
      document.querySelectorAll('.wb-list').forEach(ul => {
        const items = [...ul.children]; items.forEach(li => { li.hidden = false; });
        const limit = ul.getBoundingClientRect().bottom; let hidden = 0;
        for (const li of items) if (li.getBoundingClientRect().bottom > limit + 1) { li.hidden = true; hidden++; }
        const more = document.querySelector(`.wb-more[data-for="${ul.id}"]`); if (more) more.textContent = hidden ? `+${hidden} more` : '';
      });
    };
    // after() runs again on every refresh, so window-level listeners are added once and always call the latest fit().
    const W = window.VIEWS.wallboard; W._fit = fit; requestAnimationFrame(fit);
    if (!W._wired) {
      W._wired = true;
      window.addEventListener('resize', () => W._fit());
      document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement) document.body.classList.remove('kiosk'); setTimeout(() => W._fit(), 150); });
    }
    // Service-desk screen: refresh on a timer and fill the screen.
    let next = 0; const KEY = 'wallboardRefresh';
    clearInterval(W._t);   // the timer from the previous load
    const set = mins => { clearInterval(W._t); next = mins ? Date.now() + mins * 6e4 : 0; try { localStorage.setItem(KEY, String(mins)); } catch {}
      if (mins) W._t = setInterval(() => { const left = Math.round((next - Date.now()) / 1000); $('wbNext').textContent = left > 0 ? `Next refresh in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : ''; if (left <= 0) { clearInterval(W._t); $('refreshBtn').click(); } }, 1000);
      else $('wbNext').textContent = ''; };
    let saved = 0; try { saved = +localStorage.getItem(KEY) || 0; } catch {}
    $('wbAuto').value = String(saved); set(saved);
    W._rearm = () => set(+$('wbAuto').value || 0);   // after a failed refresh, keep the timer going
    $('wbAuto').addEventListener('change', e => set(+e.target.value));
    $('wbFull').addEventListener('click', () => { document.body.classList.toggle('kiosk'); if (document.body.classList.contains('kiosk')) document.documentElement.requestFullscreen && document.documentElement.requestFullscreen().catch(() => {}); else document.exitFullscreen && document.fullscreenElement && document.exitFullscreen(); setTimeout(fit, 150); });
  },
  retry: () => { const W = window.VIEWS.wallboard; if (W._rearm) W._rearm(); },
  how: m => [
    `GET /api/v1/tasks  (Environment/ID = ${m.environment.ID})  → open alerts, grouped by rule; the target is the quoted name at the end of each alert title`,
    'Inspector health and domain rows use the same rules as the Inspector health and Email & domain security pages.',
    'Rules: src/main/panels/wallboard.js',
  ].join('\n'),
};
