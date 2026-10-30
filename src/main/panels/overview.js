// Overview: the areas an MSP should look at first for this client, right now. One card per area (threats, identity,
// devices, email, network, backup, renewals, monitoring) with its worst open problem, built from the Action plan's list
// (the same rules and numbers) and Cyber security's coverage, so nothing new is pulled from Liongard.
// An area with no tool of that kind is "Not covered"; one whose data couldn't be read is "Couldn't read", never green.
const actions = require('./actions');
const cyber = require('./cyber');
const email = require('./email');
const network = require('./network');

const AREAS = [
  { key: 'threats', t: 'Threats & alerts', cats: ['Threats', 'Alerts'], page: 'cyber', parts: ['Cyber security'], tiles: ['threats', 'alerts'], ok: 'No active threats or open critical alerts' },
  { key: 'identity', t: 'Identity & access', cats: ['Identity'], page: 'identity', parts: ['Identity & access'], tiles: ['privmfa', 'mfa'], ok: 'MFA, leavers and stale accounts look fine' },
  { key: 'devices', t: 'Devices & patching', cats: ['Endpoints'], page: 'coverage', parts: ['Stack coverage'], tiles: ['edr', 'patch'], ok: 'Devices are managed, protected and supported' },
  { key: 'email', t: 'Email & domains', cats: ['Email'], page: 'email', parts: ['Email & domain security'], ok: 'Domains are protected from spoofing' },
  { key: 'network', t: 'Network & firewalls', cats: ['Network'], page: 'network', parts: ['Network & firmware'], ok: 'No critical findings on the firewalls' },
  { key: 'backup', t: 'Backup', cats: ['Backup'], page: 'coverage', parts: ['Stack coverage', 'Inspector health'], ok: 'Devices that need backup have it' },
  { key: 'renewals', t: 'Renewals & licences', cats: ['Renewals', 'Licences'], page: 'lifecycle', parts: ['Lifecycle & renewals'], ok: 'Nothing expired or due in 30 days' },
  { key: 'monitoring', t: 'Liongard monitoring', cats: ['Monitoring'], page: 'inspectors', parts: ['Inspector health'], ok: 'Every inspector is returning data' },
];
const RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function compute(input) {
  const plan = actions.compute(input);
  const isOpen = a => a.status === 'open' || a.status === 'progress' || a.status === 'ticketed';
  const open = plan.actions.filter(isOpen);
  const extra = { pulledOn: input.pulledOn, stack: input.stack, msp: input.msp, coveragePolicy: input.coveragePolicy, policy: input.coveragePolicy, thresholds: input.thresholds };
  const ok = r => r && !r.error;
  const safe = (fn, raw) => { try { return ok(raw) ? fn({ ...raw, ...extra }) : null; } catch { return null; } };
  const cy = ok(input.cy) ? safe(cyber.compute, { ...input.cy, id: input.id || input.cy.id, cov: input.cov || input.cy.cov, mail: input.mail || input.cy.mail, insp: input.insp || input.cy.insp }) : null;
  const em = safe(email.compute, input.mail), net = safe(network.compute, input.net);
  const tile = k => cy && cy.posture.find(p => p.key === k);
  const blind = t => cy && (cy.cover.find(c => c.t === t) || {}).status === 'Blind';
  // No tool of this kind for the client (and nothing found), so a quiet area isn't an all-clear.
  const notCovered = {
    threats: (tile('threats') || {}).notCovered,
    identity: ['privmfa', 'mfa'].every(k => (tile(k) || {}).notCovered),
    devices: (tile('edr') || {}).notCovered,
    email: em ? !em.domains.length && (tile('fwd') || {}).notCovered : false,
    network: net ? !net.cards.length : false,
    backup: blind('T1490'),
  };

  const areas = AREAS.map(a => {
    const mine = open.filter(x => a.cats.includes(x.cat)).sort((x, y) => RANK[x.risk] - RANK[y.risk] || y.count - x.count);
    // Couldn't read: the area's pages failed, or one of its Cyber security checks couldn't be made (not "not covered").
    const unreadTiles = (a.tiles || []).map(tile).filter(t => t && t.unknown && !t.notCovered);
    const unread = a.parts.every(p => plan.missing.includes(p)) || (!notCovered[a.key] && unreadTiles.length > 0);
    const n = r => mine.filter(x => x.risk === r).length;
    const worst = mine[0];
    const state = mine.length ? (n('critical') || n('high') ? 'act' : 'review')
      : unread ? 'unknown' : notCovered[a.key] ? 'none' : 'ok';
    return {
      key: a.key, t: a.t, page: a.page, state, count: mine.length, critical: n('critical'), high: n('high'),
      headline: worst ? worst.title : state === 'unknown' ? (unreadTiles[0] ? unreadTiles[0].detail : 'Couldn’t read this area from Liongard') : state === 'none' ? 'Not covered: no tool of this kind is connected for this client' : a.ok,
      why: worst ? worst.why : '',
      top: mine.slice(0, 3).map(x => ({ title: x.title, risk: x.risk, page: x.page, count: x.count })),
      cats: a.cats,
    };
  });
  const STATE_ORDER = { act: 0, review: 1, unknown: 2, none: 3, ok: 4 };
  areas.sort((x, y) => STATE_ORDER[x.state] - STATE_ORDER[y.state] || y.critical - x.critical || y.high - x.high || y.count - x.count);

  const by = s => areas.filter(a => a.state === s);
  const first = [...open].sort((x, y) => RANK[x.risk] - RANK[y.risk] || (y.quickWin - x.quickWin) || y.count - x.count).slice(0, 5)
    .map(x => ({ title: x.title, risk: x.risk, why: x.why, page: x.page, owner: x.owner, effort: x.effortLabel, quickWin: x.quickWin, area: (AREAS.find(a => a.cats.includes(x.cat)) || {}).t || x.cat }));

  return {
    environment: input.environment, pulledOn: plan.pulledOn, source: input.source, areas, first, missing: plan.missing,
    kpis: [
      { k: 'Act now', v: by('act').length, s: by('act').length ? by('act').map(a => a.t).join(', ') : 'No area has critical or high-risk problems', sev: by('act').length ? 'bad' : 'ok' },
      { k: 'To review', v: by('review').length, s: by('review').length ? by('review').map(a => a.t).join(', ') : 'Nothing medium or low open', sev: by('review').length ? 'warn' : 'ok' },
      { k: 'Not covered', v: by('none').length, s: by('none').length ? by('none').map(a => a.t).join(', ') : 'Every area has a tool reporting', sev: by('none').length ? 'none' : 'ok' },   // not covered is neutral slate (dashed), not amber
      { k: 'Looks fine', v: by('ok').length, s: by('ok').length ? by('ok').map(a => a.t).join(', ') : 'No area is clear yet', sev: 'info' },
    ],
    summary: [
      by('act').length ? `Act now on ${by('act').map(a => a.t.toLowerCase()).join(', ')}.` : open.length ? 'Nothing critical or high-risk is open.' : 'Nothing to fix from the data Liongard has for this client.',
      first[0] ? `Start with: ${first[0].title}.` : '',
      by('none').length ? `Not covered, so a quiet result there isn’t an all-clear: ${by('none').map(a => a.t.toLowerCase()).join(', ')}.` : '',
      by('unknown').length ? `Couldn’t read: ${by('unknown').map(a => a.t.toLowerCase()).join(', ')}. Refresh to try again.` : '',
    ].filter(Boolean),
  };
}

// Built from the same parts as the Action plan (and assembled from their caches when they're all there).
module.exports = { id: 'overview', usesStack: true, partsOnly: true, collect: actions.collect, compute, AREAS };
