// Compliance at a glance: technical-control evidence derived from the other panels, mapped to common frameworks.
// This is evidence of technical controls Liongard can see, over the assets that reported. It is not an assessment:
// policies, people and process still need an assessor. Each check says exactly what it looked at.
const coverage = require('./coverage');
const identity = require('./identity');
const email = require('./email');
const network = require('./network');
const inspectors = require('./inspectors');
const licences = require('./licences');
const { SIGNALS, current } = require('../stack');

const BACKUP = /\b(veeam|datto (bcdr|saas|siris|backup)|acronis|axcient|cove data protection|n-able backup|backupify|dropsuite|spanning|redstor|barracuda backup|rubrik|commvault|carbonite|storagecraft|backup)\b/i;   // whole words: "Discovery" contains "cove"

// Each framework's own control list: ID, name,
// what Liongard tests, what it can't, the source citation, and a rating: full or partial (Liongard evidence), attest
// (policy or process the client or MSP confirms) or not_assessed (outside what Liongard can see).
const CAT_FILES = { CE: 'ce', CIS: 'cis-ig1', PCI: 'pci', HIPAA: 'hipaa', NIS2: 'nis2', DORA: 'dora', CSF: 'csf', ISO: 'iso', E8: 'e8', POPIA: 'popia', INS: 'ins' };
const CATALOGUE = Object.fromEntries(Object.entries(CAT_FILES).map(([k, f]) => [k, require(`../frameworks/${f}.json`).map(c => ({
  id: c.id, name: c.name, summary: c.framework_text_summary || '', rating: c.rating, checks: c.checks || [], tested: c.tested || '', gap: c.gap || '', source: c.source || '',
  group: c.iasme_section || c.theme || null, ra: c.required_or_addressable || null }))]));
const CHECK_KEYS = ['privMfa', 'mfa', 'malware', 'os', 'patch', 'encrypt', 'hostFw', 'boundary', 'assets', 'edrAll', 'dmarc', 'training', 'backup', 'evidence', 'leavers', 'stale', 'adminAcct'];
// Framework references per check, derived from the catalogues: the controls a check evidences (full or partial).
// Attest-rated controls a check only supports, and the MSP's own evidence-freshness check, aren't framework references.
const MAP = Object.fromEntries(CHECK_KEYS.map(k => [k, Object.fromEntries(Object.entries(CATALOGUE).map(([fw, list]) => [fw, list.filter(c => k !== 'evidence' && ['full', 'partial'].includes(c.rating) && c.checks.includes(k)).map(c => c.id)]))]));
// Which page holds the detail for each check.
const PAGE = { privMfa: 'identity', mfa: 'identity', leavers: 'identity', stale: 'identity', adminAcct: 'identity', malware: 'coverage', edrAll: 'coverage', os: 'coverage', patch: 'coverage', encrypt: 'coverage',
  hostFw: 'coverage', assets: 'coverage', boundary: 'network', dmarc: 'email', training: 'licences', backup: 'stack', evidence: 'inspectors' };
// unit: what the framework calls its items; assessor: who the evidence pack supports; extra: framework-specific scope wording.
const FRAMEWORKS = [
  { key: 'CE', name: 'Cyber Essentials v3.3 (Danzell)', note: 'Requirements for IT infrastructure, v3.3 (April 2026)', unit: 'requirements', assessor: 'Certification Body',
    extra: 'Certification scope is agreed with the Certification Body. Cloud services cannot be excluded from scope under v3.3.',
    groups: { A2: 'A2 · Scope', A4: 'A4 · Firewalls', A5: 'A5 · Secure configuration', A6: 'A6 · Security update management', A7: 'A7 · User access control', A8: 'A8 · Malware protection' } },
  { key: 'CIS', name: 'CIS Controls v8.1 (IG1)', note: 'Implementation Group 1 safeguards', unit: 'safeguards', assessor: 'assessor',
    lead: 'Controls 13, 16 and 18 have no IG1 safeguards, so they are not in scope at this Implementation Group (not the same as 0%).',
    groups: { 1: '1 · Inventory and control of enterprise assets', 2: '2 · Inventory and control of software assets', 3: '3 · Data protection', 4: '4 · Secure configuration', 5: '5 · Account management', 6: '6 · Access control management', 7: '7 · Continuous vulnerability management', 8: '8 · Audit log management', 9: '9 · Email and web browser protections', 10: '10 · Malware defenses', 11: '11 · Data recovery', 12: '12 · Network infrastructure management', 14: '14 · Security awareness and skills training', 15: '15 · Service provider management', 17: '17 · Incident response management' } },
  { key: 'PCI', name: 'PCI DSS v4.0.1', note: 'Requirements 1–12, with the sub-requirements Liongard evidences', unit: 'requirements', assessor: 'QSA',
    extra: 'Liongard does not identify which systems are in the cardholder data environment. Results cover all systems Liongard observed and must be reconciled to the CDE by the assessor.',
    groups: { 1: 'Req 1 · Network security controls', 2: 'Req 2 · Secure configurations', 3: 'Req 3 · Protect stored account data', 4: 'Req 4 · Protect data in transmission', 5: 'Req 5 · Malicious software', 6: 'Req 6 · Secure systems and software', 7: 'Req 7 · Restrict access by need to know', 8: 'Req 8 · Identify and authenticate', 9: 'Req 9 · Physical access', 10: 'Req 10 · Log and monitor', 11: 'Req 11 · Test security regularly', 12: 'Req 12 · Policies and programs' } },
  { key: 'HIPAA', name: 'HIPAA Security Rule', note: '45 CFR 164 Subpart C standards and implementation specifications', unit: 'standards and specifications', assessor: 'auditor',
    groups: { '164.308': 'Administrative safeguards (164.308)', '164.310': 'Physical safeguards (164.310)', '164.312': 'Technical safeguards (164.312)', '164.314': 'Organizational requirements (164.314)', '164.316': 'Policies and documentation (164.316)' } },
  { key: 'NIS2', name: 'NIS2 Article 21', note: 'Cybersecurity risk-management measures, Art. 21(2)(a)–(j)', unit: 'measures', assessor: 'competent authority or auditor', groups: {} },
  { key: 'DORA', name: 'DORA (EU) 2022/2554', note: 'ICT risk management framework, Articles 5–15', unit: 'articles', assessor: 'auditor', groups: {} },
  { key: 'CSF', name: 'NIST CSF 2.0', note: 'Categories, with subcategories where Liongard has evidence', unit: 'categories and subcategories', assessor: 'assessor',
    groups: { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' } },
  { key: 'ISO', name: 'ISO/IEC 27001:2022 Annex A', note: 'All 93 Annex A controls', unit: 'controls', assessor: 'certification auditor',
    groups: { Organizational: '5 · Organizational controls', People: '6 · People controls', Physical: '7 · Physical controls', Technological: '8 · Technological controls' } },
  { key: 'E8', name: 'Essential Eight', note: 'The eight strategies at Maturity Level One', unit: 'strategies', assessor: 'assessor', groups: {} },
  { key: 'POPIA', name: 'POPIA (South Africa)', note: 'Protection of Personal Information Act 4 of 2013: the conditions for lawful processing, with security safeguards in s19–22', unit: 'sections and regulations', assessor: 'Information Officer or auditor',
    extra: 'POPIA applies to the systems that hold personal information. The client declares which those are; Liongard can’t tell which systems process personal information. The MSP is usually itself an operator under sections 20–21.',
    groups: { acc: 'Accountability (s8)', lim: 'Processing limitation (s9–12)', pur: 'Purpose specification (s13–14)', fur: 'Further processing limitation (s15)', qual: 'Information quality (s16)', open: 'Openness (s17–18)', sec: 'Security safeguards (s19–22)', dsp: 'Data subject participation (s23–24)', io: 'Information Officer (s55)', reg: 'Regulations 2018 (reg 4)' } },
  { key: 'INS', name: 'Cyber insurance readiness', note: 'Controls insurers commonly ask about', unit: 'questions', assessor: 'insurer or broker', groups: {} },
];
// Which group a control sits in, for the evidence pack's sections.
const POPIA_GROUP = id => { if (/^reg/.test(id)) return 'reg'; const n = parseInt(id.replace(/^s/, ''), 10); return n === 8 ? 'acc' : n <= 12 ? 'lim' : n <= 14 ? 'pur' : n === 15 ? 'fur' : n === 16 ? 'qual' : n <= 18 ? 'open' : n <= 22 ? 'sec' : n <= 24 ? 'dsp' : 'io'; };
const groupOf = (fw, c) => fw === 'POPIA' ? POPIA_GROUP(c.id) : c.group || (fw === 'CSF' ? c.id.slice(0, 2) : fw === 'HIPAA' ? c.id.slice(0, 7) : ['CIS', 'PCI'].includes(fw) ? c.id.split('.')[0] : '');
// Where a framework says "all" (CE A7, PCI 8.4.2, E8), MFA that isn't on every account fails rather than passing in part.
const STRICT = { CE: ['mfa', 'privMfa'], PCI: ['mfa', 'privMfa'], E8: ['mfa', 'privMfa'] };

// Which frameworks apply to a client, from the profile set on this page (industry, region, what they do).
// No profile yet: every framework is shown, as before. `extra` and `hidden` are the MSP's own additions and removals.
const INDUSTRIES = ['Healthcare', 'Finance & insurance', 'Legal & professional', 'Retail & hospitality', 'Manufacturing', 'Education', 'Public sector', 'Technology', 'Energy & utilities', 'Other'];
const REGIONS = ['United States', 'United Kingdom', 'European Union', 'Australia', 'South Africa', 'Other'];
const RULES = {
  CE: p => p.region === 'United Kingdom' && 'UK organisation',
  CIS: () => 'Good baseline for any client',
  PCI: p => p.cards && 'Takes card payments',
  HIPAA: p => p.industry === 'Healthcare' && p.region === 'United States' && 'Healthcare in the US',
  NIS2: p => p.region === 'European Union' && !['Retail & hospitality', 'Legal & professional', 'Other'].includes(p.industry) && 'EU, in a NIS2 sector (check essential or important entity)',
  DORA: p => p.region === 'European Union' && p.industry === 'Finance & insurance' && 'EU financial entity',
  CSF: p => p.region === 'United States' && 'Good baseline for US clients',
  ISO: p => p.iso && 'Holds or is working towards ISO 27001',
  E8: p => p.region === 'Australia' && 'Australian organisation',
  POPIA: p => p.region === 'South Africa' && 'Processes personal information in South Africa',
  INS: p => p.insurance && 'Has cyber insurance',
};
// Score areas for the posture score (0-10). Every check sits in exactly one area.
const AREAS = [
  ['Identity', ['privMfa', 'mfa', 'leavers', 'stale', 'adminAcct']],
  ['Devices', ['malware', 'edrAll', 'os', 'patch', 'encrypt', 'hostFw', 'assets']],
  ['Email', ['dmarc']], ['Backup', ['backup']], ['Network', ['boundary']], ['People', ['training']], ['Monitoring', ['evidence']],
];
// The tools a check's evidence comes from (stack capabilities), so each row can say which inspector and how old.
const SOURCE = { privMfa: ['identity'], mfa: ['identity'], leavers: ['identity'], stale: ['identity'], adminAcct: ['identity'],
  malware: ['security', 'management'], edrAll: ['security'], os: ['management'], patch: ['management'], encrypt: ['management', 'security'], hostFw: ['management'], assets: ['management', 'network'],
  boundary: ['network'], dmarc: /domain|dns/i, training: ['awareness'], backup: ['backup'] };
// Questions Liongard can't answer from data: policies, process and the Essential Eight strategies it can't see.
// They're answered on this page (yes, partly, no) and shown apart from the technical score.
const POLICY = [
  { key: 'riskAssess', name: 'A risk assessment was done in the last 12 months', refs: { CIS: [], PCI: ['12.3.1'], HIPAA: ['164.308(a)(1)(ii)(A)'], NIS2: ['21(2)(a)'], DORA: ['Art 6(8)'], CSF: ['ID.RA-01'], ISO: ['Clause 6.1.2'], INS: ['Risk assessment'] } },
  { key: 'policy', name: 'An information security policy is approved by management', refs: { PCI: ['12.1.1'], HIPAA: ['164.316(a)'], NIS2: ['21(2)(a)'], DORA: ['Art 5(2)'], CSF: ['GV.PO-01'], ISO: ['5.1'] } },
  { key: 'irPlan', name: 'An incident response plan is written and tested', refs: { CIS: ['17.1', '17.3'], PCI: ['12.10.1'], HIPAA: ['164.308(a)(6)'], NIS2: ['21(2)(b)'], DORA: ['Art 11'], CSF: ['RS.MA-01'], ISO: ['5.24'], INS: ['Incident response plan'] } },
  { key: 'restoreTest', name: 'Restoring from backup has been tested', refs: { HIPAA: ['164.308(a)(7)(ii)(D)'], NIS2: ['21(2)(c)'], DORA: ['Art 12(2)'], CSF: ['PR.DS-11'], ISO: ['8.13'], E8: ['Regular backups'], INS: ['Restores tested'] } },
  { key: 'suppliers', name: 'Suppliers’ security risk is reviewed', refs: { PCI: ['12.8.1'], HIPAA: ['164.308(b)(1)'], NIS2: ['21(2)(d)'], DORA: ['Art 28'], CSF: ['GV.SC-07'], ISO: ['5.19'] } },
  { key: 'appControl', name: 'Application control blocks unapproved programs', refs: { E8: ['Application control'], CIS: ['2.3'] } },
  { key: 'macros', name: 'Office macros are blocked unless trusted', refs: { E8: ['Restrict Microsoft Office macros'] } },
  { key: 'appHarden', name: 'Browsers and apps are hardened (no Flash, Java or ads in browsers)', refs: { E8: ['User application hardening'] } },
  { key: 'patchApps', name: 'Applications are patched within a month', refs: { E8: ['Patch applications'], CIS: ['7.4'], INS: ['Patching on time'] } },
];
const DAY = 864e5;

// Parts in `have` were already pulled (Refresh all); a part that fails becomes { error } and its checks show "No evidence".
async function collect(api, env, have = {}) {
  const keys = ['cov', 'id', 'mail', 'net', 'insp', 'lic'];
  const [cov, id, mail, net, insp, lic] = await Promise.all([coverage, identity, email, network, inspectors, licences].map((p, i) => have[keys[i]] || p.collect(api, env).catch(e => ({ error: e.message }))));
  return { environment: env, cov, id, mail, net, insp, lic };
}

function compute(input) {
  const P = input.pulledOn;
  // The other pages' rules, fed the same shared data and settings they use, so every page agrees.
  const extra = { pulledOn: P, stack: input.stack, policy: input.coveragePolicy, msp: input.msp, thresholds: input.thresholds };
  const safe = (fn, raw) => { try { return raw && !raw.error ? fn({ ...raw, ...extra }) : null; } catch { return null; } };
  const cov = safe(coverage.compute, input.cov), id = safe(identity.compute, input.id), em = safe(email.compute, input.mail),
    net = safe(network.compute, input.net), ih = safe(inspectors.compute, input.insp), lic = safe(licences.compute, input.lic && !input.lic.error ? { ...input.lic, inspectedOn: input.lic.inspectedOn } : null);
  const checks = [];
  const add = (key, name, status, evidence, fix = '') => checks.push({ key, name, status, evidence, fix, refs: MAP[key], page: PAGE[key] });
  // What each check found, item by item (people, devices, domains, firewalls, inspectors), for the drill-down and the
  // remediation list. Built from the same rows the check counts, so the list always matches the result.
  const setItems = (key, list) => { const c = checks.find(x => x.key === key); if (c) c.items = list.slice(0, 500); };
  // Population for the evidence pack: how many were in scope, how many could be evaluated, how many pass.
  const setPop = (key, inScope, evaluated, passing, unit) => { const c = checks.find(x => x.key === key); if (c) c.pop = { inScope, evaluated, passing: Math.max(0, passing), unit }; };
  const PER = (r, d) => ({ kind: r.privileged || r.kind === 'Admin account' ? 'Admin' : 'User', t: r.name, d: d || r.email || r.username || '', link: { identityId: r.id } });
  const DEV = (r, d) => ({ kind: r.kind === 'Server' ? 'Server' : 'Device', t: r.host, d: d || [r.kind, r.os].filter(Boolean).join(' · '), link: r.id ? { deviceId: r.id } : null });
  const FND = f => ({ kind: 'System', t: f.system, d: `${f.label}: ${f.value}${f.inspector ? ` (${f.inspector})` : ''}`, tool: f.inspector, link: { systemId: f.systemId, systemDetailId: f.systemDetailId } });
  const INSP = r => ({ kind: 'Inspector', t: r.name, d: r.why || r.health, tool: r.inspector, link: { systemId: r.systemId, systemDetailId: r.systemDetailId, lpId: r.lpId, inspectorId: r.inspectorId } });
  const k = (m, label) => m && (m.kpis.find(x => x.k === label) || {}).v;

  if (id) {
    const priv = id.rows.filter(r => r.privileged && r.enabled);
    const noMfa = id.mfa ? id.rows.filter(r => id.mfa.admins.includes(r.id)) : priv.filter(r => r.mfa === 'NO');   // the same accounts as Identity's "Admins without MFA"
    add('privMfa', 'MFA on every account with admin rights', !priv.length ? 'none' : noMfa.length ? 'fail' : 'pass', `${priv.length - noMfa.length} of ${priv.length} accounts with admin rights have MFA everywhere${noMfa.length ? `. Missing: ${noMfa.map(r => r.name).join(', ')}` : ''}`, noMfa.length ? 'Enforce MFA on these admin accounts first' : '');
    setPop('privMfa', priv.length, priv.length, priv.length - noMfa.length, 'accounts with admin rights');
    setItems('privMfa', noMfa.map(r => PER(r, (r.mfaMissingIn || []).length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : 'No MFA reported')));
    const leavers = id.rows.filter(r => (r.otherAccess || []).length);
    // 0 of 0 is never a pass: a check with nothing to look at is "none" (no evidence), not an all-clear.
    const anyIds = id.rows.length > 0;
    add('leavers', 'Leavers removed from every system', leavers.length ? 'fail' : anyIds ? 'pass' : 'none', leavers.length ? `${leavers.length} disabled account${leavers.length > 1 ? 's are' : ' is'} still present in other tools: ${leavers.slice(0, 5).map(r => `${r.name} (${r.otherAccess.join(', ')})`).join('; ')}` : 'No disabled accounts found in other tools', leavers.length ? 'Remove them from the remaining tools' : '');
    { const dis = id.rows.filter(r => !r.enabled).length; setPop('leavers', dis, dis, dis - leavers.length, 'disabled accounts'); }
    setItems('leavers', leavers.map(r => PER(r, `Disabled, but still in ${r.otherAccess.join(', ')}`)));
    // Same accounts as Identity's "Stale accounts" tile. Accounts with no sign-in recorded can't be judged, so they're named, not passed.
    const stale = id.rows.filter(r => r.stale && r.kind !== 'Service');
    const unknown = id.rows.filter(r => r.enabled && !r.stale && !r.lastLogin && (r.kind === 'Person' || r.kind === 'Admin account'));
    const disagree = id.rows.filter(r => r.staleConflict);
    add('stale', 'Unused accounts disabled', stale.length ? (stale.length > 3 ? 'fail' : 'partial') : unknown.length || disagree.length ? 'partial' : anyIds ? 'pass' : 'none',
      [stale.length ? `${stale.length} enabled account${stale.length > 1 ? 's haven\u2019t' : ' hasn\u2019t'} signed in for ${id.staleDays || 90}+ days or ${stale.length > 1 ? 'are' : 'is'} reported stale` : 'No enabled account is stale',
        unknown.length ? `${unknown.length} ${unknown.length > 1 ? 'have' : 'has'} no sign-in recorded, so ${unknown.length > 1 ? 'they' : 'it'} can’t be checked` : '',
        disagree.length ? `${disagree.length} ${disagree.length > 1 ? 'are' : 'is'} reported stale by ${[...new Set(disagree.flatMap(r => r.staleIn))].join(', ')} but signed in recently (sources disagree)` : ''].filter(Boolean).join('. '),
      stale.length ? 'Disable accounts nobody uses' : unknown.length || disagree.length ? 'Check the accounts listed under “Sources disagree” and those with no sign-in, on Identity & access' : '');
    { const en = id.rows.filter(r => r.enabled && r.kind !== 'Service').length; setPop('stale', en, en - unknown.length, en - unknown.length - stale.length, 'enabled accounts'); }
    setItems('stale', [...stale.map(r => PER(r, r.lastLogin ? `Last sign-in ${String(r.lastLogin).slice(0, 10)}` : 'Reported stale')), ...unknown.map(r => PER(r, 'No sign-in recorded, so it can’t be checked'))]);
    const sharedAdmins = id.rows.filter(r => r.enabled && r.kind === 'Person' && r.admin && r.admin.some(a => /global admin|super|owner|domain admin/i.test(a.role || '')));
    if (id.admins && id.admins.length) add('adminAcct', 'Separate admin accounts for admin work', sharedAdmins.length ? 'partial' : 'pass', sharedAdmins.length ? `${sharedAdmins.length} everyday account${sharedAdmins.length > 1 ? 's hold' : ' holds'} top-level admin roles: ${sharedAdmins.slice(0, 5).map(r => r.name).join(', ')}` : 'Top-level admin roles sit on dedicated admin accounts', sharedAdmins.length ? 'Give admins a separate account for admin work' : '');
    { const adm = id.rows.filter(r => r.enabled && (r.admin || []).length).length; setPop('adminAcct', adm, adm, adm - sharedAdmins.length, 'accounts with admin roles'); }
    setItems('adminAcct', sharedAdmins.map(r => PER(r, `Everyday account with ${r.admin.map(a => a.role).filter(Boolean).slice(0, 2).join(', ')}`)));
    const cov2 = k(id, 'MFA everywhere'), pct = parseInt(cov2, 10);
    add('mfa', 'MFA for all users', isNaN(pct) ? 'none' : pct >= 98 ? 'pass' : pct >= 80 ? 'partial' : 'fail', `${cov2} of people have MFA in every system (${(id.kpis.find(x => x.k === 'MFA everywhere') || {}).s})`, pct < 98 ? 'Enrol the remaining accounts' : '');
    { const mm = /(\d+) of (\d+)/.exec((id.kpis.find(x => x.k === 'MFA everywhere') || {}).s || ''); if (mm) setPop('mfa', +mm[2], +mm[2], +mm[1], 'people'); }
    setItems('mfa', id.rows.filter(r => r.enabled && (r.kind === 'Person' || r.kind === 'Admin account') && (r.mfa === 'NO' || r.mfa === 'PARTIAL' || (r.mfaMissingIn || []).length))
      .map(r => PER(r, (r.mfaMissingIn || []).length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : r.mfa === 'PARTIAL' ? 'MFA in some systems only' : 'No MFA reported')));
  }
  if (cov) {
    const m = cov.managed;
    // A device with no protection data is never counted as protected: it's listed, and the check is partial.
    const unk = m.filter(r => r.protection === 'unknown'), known = m.filter(r => r.protection !== 'unknown');
    const noAv = known.filter(r => r.protection ? ['off', 'none'].includes(r.protection) : r.defender === 'bad');
    const noEdr = m.filter(r => (r.missing || []).includes('edr')), toCheck = m.filter(r => (r.unconfirmed || []).includes('edr'));
    add('malware', 'Anti-malware active on managed endpoints', !known.length ? 'none' : noAv.length ? 'fail' : unk.length ? 'partial' : 'pass', `${known.length - noAv.length} of ${known.length} with protection data have an EDR or active antivirus${noAv.length ? `. None or off on ${noAv.map(r => r.host).join(', ')}` : ''}${unk.length ? `. No protection data for ${unk.length}` : ''}`, noAv.length ? `Turn on protection on ${noAv.map(r => r.host).join(', ')}` : unk.length ? 'Confirm protection on the devices with no data' : '');
    setPop('malware', m.length, known.length, known.length - noAv.length, 'managed endpoints');
    setItems('malware', [...noAv.map(r => DEV(r, 'No EDR, antivirus off or missing')), ...unk.map(r => DEV(r, 'No protection data'))]);
    if (cov.cats.some(c => c.key === 'edr')) add('edrAll', 'EDR on every managed endpoint', !m.length ? 'none' : noEdr.length ? 'fail' : toCheck.length ? 'partial' : 'pass', `${m.length - noEdr.length - toCheck.length} of ${m.length} confirmed${noEdr.length ? `, ${noEdr.length} missing` : ''}${toCheck.length ? `, ${toCheck.length} to confirm in tools that don\u2019t report devices` : ''}`, noEdr.length ? `Deploy the EDR sensor to ${noEdr.slice(0, 8).map(r => r.host).join(', ')}` : '');
    setPop('edrAll', m.length, m.length - toCheck.length, m.length - noEdr.length - toCheck.length, 'managed endpoints');
    setItems('edrAll', [...noEdr.map(r => DEV(r, 'No EDR sensor reported')), ...toCheck.map(r => DEV(r, 'EDR not confirmed: the EDR tool doesn’t list devices'))]);
    const all = [...cov.managed, ...cov.unmanaged], eos = all.filter(r => r.eos);
    add('os', 'Supported operating systems only', eos.length ? 'fail' : all.length ? 'pass' : 'none', eos.length ? `${eos.length} device${eos.length > 1 ? 's' : ''} on an unsupported OS: ${eos.map(r => r.host).join(', ')}` : all.length ? `All ${all.length} endpoints are on a supported OS` : 'No endpoints found', eos.length ? 'Upgrade or retire them' : '');
    setPop('os', all.length, all.length, all.length - eos.length, 'endpoints');
    setItems('os', eos.map(r => DEV(r, `${r.os || 'Operating system'} is past end of support`)));
    const withData = m.filter(r => r.pending != null), behind = withData.filter(r => r.pending > 0);
    add('patch', 'Security updates installed', !withData.length ? 'none' : behind.length ? (behind.length / withData.length > .5 ? 'fail' : 'partial') : 'pass', withData.length ? `${withData.length - behind.length} of ${withData.length} agent-reporting endpoints have no updates waiting` : 'No endpoint reports Windows Update data', behind.length ? 'Install the waiting updates and check the update schedule' : '');
    setPop('patch', m.length, withData.length, withData.length - behind.length, 'managed endpoints');
    setItems('patch', behind.map(r => DEV(r, `${r.pending} update${r.pending === 1 ? '' : 's'} waiting`)));
    // Encryption: BitLocker alerts on devices plus every tool's current encryption findings (the same ones Cyber security counts).
    const enc = m.filter(r => r.bitlocker !== 'none'), noEnc = enc.filter(r => r.bitlocker === 'bad');
    const encF = current(input.stack, SIGNALS.encrypt), encSys = [...new Set(encF.map(f => f.system))];
    const encOff = [...new Set([...noEnc.map(r => r.host), ...encSys])];
    add('encrypt', 'Disk encryption on endpoints', !enc.length && !encF.length ? 'none' : encOff.length ? 'fail' : 'pass',
      encOff.length ? `Encryption off or not confirmed on ${encOff.length}: ${encOff.slice(0, 6).join(', ')}${encOff.length > 6 ? ' and more' : ''}` : `${enc.length} endpoint${enc.length === 1 ? '' : 's'} with no BitLocker alert, and no tool reports encryption off`,
      encOff.length ? 'Turn on BitLocker (or the platform’s disk encryption) on the devices listed' : '');
    setPop('encrypt', m.length, enc.length, enc.length - noEnc.length, 'managed endpoints');
    setItems('encrypt', [...noEnc.map(r => DEV(r, 'BitLocker off or not confirmed')), ...encF.map(FND)]);
    const fw = m.filter(r => r.firewall !== 'none'), fwOff = fw.filter(r => r.firewall === 'bad');
    add('hostFw', 'Host firewall on every profile', !fw.length ? 'none' : fwOff.length ? 'fail' : 'pass', fw.length ? `${fw.length - fwOff.length} of ${fw.length} have Windows Firewall on for domain, private and public${fwOff.length ? `. Off on ${fwOff.slice(0, 6).map(r => r.host).join(', ')}` : ''}` : 'No host firewall evidence', fwOff.length ? 'Turn Windows Firewall on for every profile on the devices listed' : '');
    setPop('hostFw', m.length, fw.length, fw.length - fwOff.length, 'managed endpoints');
    setItems('hostFw', fwOff.map(r => DEV(r, 'Windows Firewall off on at least one profile')));
    add('assets', 'Every endpoint on the network is managed', cov.unmanaged.length ? 'fail' : m.length ? 'pass' : 'none', `${cov.unmanaged.length} unmanaged endpoint${cov.unmanaged.length === 1 ? '' : 's'} seen by discovery tools`, cov.unmanaged.length ? 'Onboard them to RMM and EDR, or remove them' : '');
    setPop('assets', m.length + cov.unmanaged.length, m.length + cov.unmanaged.length, m.length, 'endpoints seen');
    setItems('assets', cov.unmanaged.map(r => DEV(r, `Seen by ${(r.seenBy || r.sources || []).join ? (r.seenBy || r.sources || []).join(', ') || 'discovery' : 'discovery'}, no RMM or EDR`)));
  }
  if (net) {
    const cardsRead = net.cards.filter(c => !c.unread);   // a firewall Liongard couldn't read is no evidence either way
    const bad = cardsRead.filter(c => c.flag === 'crit' && c.rows.length > 2);
    add('boundary', 'Boundary firewalls healthy and protected', !cardsRead.length ? 'none' : bad.length ? 'fail' : 'pass', cardsRead.length ? `${cardsRead.length - bad.length} of ${cardsRead.length} firewalls with no critical findings${bad.length ? `. Issues on ${bad.map(c => c.name).join(', ')}` : ''}${cardsRead.length < net.cards.length ? `. ${net.cards.length - cardsRead.length} couldn’t be read` : ''}` : net.cards.length ? 'Couldn’t read the firewalls from Liongard' : 'No firewall inspectors', bad.length ? 'See Network & firmware' : '');
    const role = c => { const x = `${c.role || ''} ${c.name}`; return /firewall|sonicwall|barracuda|fortigate|watchguard|meraki mx|pfsense|sophos/i.test(x) ? 'Firewall' : /switch/i.test(x) ? 'Switch' : /access point|wireless/i.test(x) ? 'Access point' : 'Network'; };
    setPop('boundary', net.cards.length, cardsRead.length, cardsRead.length - bad.length, 'firewalls');
    setItems('boundary', bad.map(c => ({ kind: role(c), t: `${c.name} (${c.site})`, d: c.rows.filter(r => r[2] === 'bad' && r[0] !== 'Inspector').map(r => `${r[0]}: ${r[1]}`).slice(0, 3).join(' · '), tool: c.name, link: c.systemId ? { systemId: c.systemId, systemDetailId: c.systemDetailId } : null })));
  }
  if (em && em.domains.length) {
    const bad = em.domains.filter(d => d.spoofable), badSend = bad.filter(d => d.sends);
    add('dmarc', 'Email domains protected from spoofing', !bad.length ? 'pass' : badSend.length ? 'fail' : 'partial', `${em.domains.length - bad.length} of ${em.domains.length} domains protected${bad.length ? `. Spoofable: ${bad.map(d => d.name).join(', ')}` : ''}`, bad.length ? 'Publish the records listed on Email & domain security' : '');
    setPop('dmarc', em.domains.length, em.domains.length, em.domains.length - bad.length, 'domains');
    setItems('dmarc', bad.map(d => ({ kind: 'Domain', t: d.name, d: `Grade ${d.grade}${d.sends ? ' · sends email' : ''}${d.dmarc && d.dmarc[2] ? ` · ${d.dmarc[2]}` : ''}`, tool: 'Internet Domain/DNS', link: d.sys ? { systemId: d.sys.systemId, systemDetailId: d.sys.systemDetailId } : null })));
  }
  if (lic && lic.systems && lic.systems.KnowBe4) {
    const missing = lic.people.filter(p => !p.orphan && !p.shared && p.cells.kb4 === 'bad').length, never = (lic.dormKpis.find(x => /KnowBe4/.test(x.k)) || {}).v || 0;
    add('training', 'Security awareness training for every user', missing + never ? 'partial' : lic.people.some(p => !p.orphan && !p.shared) ? 'pass' : 'none', `${missing} licensed user${missing === 1 ? '' : 's'} not enrolled, ${never} seat${never === 1 ? '' : 's'} never used`, missing + never ? 'Enrol and chase the users listed on Licence reconciliation' : '');
    { const lp = lic.people.filter(p => !p.orphan && !p.shared).length; setPop('training', lp, lp, lp - missing, 'licensed users'); }
    setItems('training', lic.people.filter(p => !p.orphan && !p.shared && p.cells.kb4 === 'bad').map(p => ({ kind: 'User', t: p.name, d: `${p.upn || ''} · licensed but not enrolled in training`.replace(/^ · /, ''), tool: 'KnowBe4', link: null })));
  } else add('training', 'Security awareness training for every user', 'none', 'No KnowBe4 (or other training) inspector', 'Connect the training platform to Liongard');
  if (ih) {
    const isBackup = r => (input.stack ? (input.stack.systems.find(s => s.lpId === r.lpId) || {}).caps || [] : []).includes('backup') || BACKUP.test(r.inspector || '');
    const backups = ih.rows.filter(r => isBackup(r) && r.health !== 'Inactive');
    // A fresh backup inspector isn't enough: its jobs must be succeeding too (failed or stale jobs in current evidence).
    const jobIssues = current(input.stack, SIGNALS.backupFail, 'backup').filter(f => f.sev === 'bad' || f.sev === 'warn');
    if (jobIssues.length && backups.length && !backups.some(r => r.health === 'Failing' || r.health === 'Stale'))
      add('backup', 'Backups monitored and current', jobIssues.some(f => f.sev === 'bad') ? 'fail' : 'partial',
        `Backup inspectors are reporting, but ${jobIssues.length} job finding${jobIssues.length > 1 ? 's' : ''}: ${jobIssues.slice(0, 4).map(f => `${f.label} (${f.value}) in ${f.inspector}`).join('; ')}`, 'Fix the failing or stale backup jobs');
    else add('backup', 'Backups monitored and current', !backups.length ? 'none' : backups.some(r => r.health === 'Failing' || r.health === 'Stale') ? 'fail' : 'pass', backups.length ? `${backups.length} backup inspector${backups.length > 1 ? 's' : ''}: ${backups.map(r => `${r.name} (${r.health})`).join(', ')}` : 'No backup inspector deployed, so there is no backup evidence', backups.length ? '' : 'Connect the backup platform to Liongard');
    const backupBad = backups.filter(r => r.health === 'Failing' || r.health === 'Stale');
    setPop('backup', backups.length, backups.length, backups.length - backupBad.length, 'backup inspectors');
    setItems('backup', backupBad.length ? backupBad.map(INSP) : jobIssues.map(FND));
    const live = ih.rows.filter(r => r.health !== 'Inactive'), fresh = live.filter(r => r.health === 'Fresh' || r.health === 'Due');
    const evS = !live.length ? 'none' : fresh.length / live.length >= .9 ? 'pass' : fresh.length / Math.max(1, live.length) >= .5 ? 'partial' : 'fail';
    add('evidence', 'Monitoring evidence is current', evS, `${fresh.length} of ${live.length} inspectors have current data`, evS === 'pass' ? '' : 'Put every launchpoint on a schedule and fix failing inspectors (see Inspector health)');
    setItems('evidence', live.filter(r => r.health !== 'Fresh' && r.health !== 'Due').map(INSP));
  }

  // Fail closed: when a source couldn't be read, its checks stay on the list as "No evidence" (left out of the score and
  // listed), instead of vanishing and quietly raising the score.
  const MISSING = [
    [id, 'identity', [['privMfa', 'MFA on every account with admin rights'], ['mfa', 'MFA for all users'], ['leavers', 'Leavers removed from every system'], ['stale', 'Unused accounts disabled']]],
    [cov, 'device coverage', [['malware', 'Anti-malware active on managed endpoints'], ['os', 'Supported operating systems only'], ['patch', 'Security updates installed'], ['encrypt', 'Disk encryption on endpoints'], ['hostFw', 'Host firewall on every profile'], ['assets', 'Every endpoint on the network is managed']]],
    [net, 'network', [['boundary', 'Boundary firewalls healthy and protected']]],
    [em, 'email and domain', [['dmarc', 'Email domains protected from spoofing']]],
    [ih, 'inspector health', [['backup', 'Backups monitored and current'], ['evidence', 'Monitoring evidence is current']]],
  ];
  for (const [model, what, list] of MISSING) if (!model) for (const [key, name] of list) if (!checks.some(c => c.key === key))
    { add(key, name, 'none', `Couldn’t read ${what} data from Liongard, so this wasn’t checked`, 'Refresh the page; if it persists, check the inspectors on Inspector health'); checks[checks.length - 1].unread = true; }
  const W = { pass: 1, partial: .5, fail: 0 };
  // Same colour bands as the framework cards: 80%+ green, 50%+ amber, below that red.
  const band = v => v == null ? 'info' : v >= 80 ? 'ok' : v >= 50 ? 'warn' : 'bad';
  // ---------- Marks: what the MSP recorded against a check (done, attested, exception) ----------
  // "Done" is only a claim until Liongard's data agrees: verified when the check passes on data pulled after it was
  // marked, reopened when data pulled after it still fails. Attesting is only for checks Liongard has no evidence
  // for; when evidence turns up it wins. Attestations last 12 months, exceptions until their date.
  const marks = input.marks || {}, now = new Date(P || Date.now());
  for (const c of checks) {
    const mk = marks[c.key];
    if (!mk) continue;
    c.mark = mk;
    const after = P && mk.at && new Date(P) > new Date(mk.at);
    if (mk.state === 'done') c.state = c.status === 'pass' ? 'verified' : after && !c.unread ? 'reopened' : 'awaiting';
    else if (mk.state === 'attested') c.state = c.status !== 'none' || c.unread ? 'superseded' : now - new Date(mk.at) > 365 * DAY ? 'expired' : 'attested';
    else if (mk.state === 'exception') c.state = c.status === 'pass' ? 'superseded' : mk.until && new Date(mk.until) < now ? 'expired' : 'exception';
  }
  // ---------- Evidence source and age per check, from Inspector health ----------
  if (ih) {
    const capsOf = r => (input.stack ? (input.stack.systems.find(x => x.lpId === r.lpId) || {}).caps || [] : []);
    for (const c of checks) {
      const want = SOURCE[c.key];
      const rows = !want ? [] : ih.rows.filter(r => r.health !== 'Inactive' && (want instanceof RegExp ? want.test(r.inspector || '') : capsOf(r).some(x => want.includes(x))));
      if (!rows.length) continue;
      const days = rows.map(r => r.days).filter(d => d != null);   // null: never produced data (counted as stale below)
      const stale = rows.filter(r => r.health === 'Stale' || r.health === 'Failing');
      c.sources = { tools: [...new Set(rows.map(r => r.inspector))].slice(0, 4), days: days.length ? Math.max(...days) : null, stale: stale.length, of: rows.length };
    }
  }
  // Scores are built from Liongard data only: an attestation is shown beside a check, never counted as a pass.
  const eff = c => c.status;
  const scoreOf = (list, over = {}) => { const sc = list.filter(c => eff(c) !== 'none' || c.unread); return sc.length ? Math.round(sc.reduce((a, c) => a + (c.unread ? 0 : W[over[c.key] || eff(c)]), 0) / sc.length * 100) : null; };
  // ---------- Controls: each framework's own list, with a status rolled up from the checks behind it ----------
  // Worst of: any mapped check failing fails the control; a partial check, a check with no data, or a control Liongard
  // tests only in part makes it "partial" or "evidenced in part" (never a plain pass); no data at all is "not assessed".
  // Attest and not-assessed controls take what the MSP recorded: an attestation or their own evidence, kept separate
  // from Liongard's results and never counted as a technical pass. An accepted risk keeps the failing result beside it.
  const ctlKey = (fw, cid) => `c:${fw}:${cid}`;
  const controlsOf = fw => CATALOGUE[fw].map(ct => {
    const mk = marks[ctlKey(fw, ct.id)] || null;
    const strict = k => (STRICT[fw] || []).includes(k);
    const st = c => { const v = c.unread ? 'none' : c.status; return v === 'partial' && strict(c.key) ? 'fail' : v; };
    const res = ct.checks.map(k => checks.find(c => c.key === k)).filter(Boolean);
    const withData = ['full', 'partial'].includes(ct.rating) ? res.filter(c => st(c) !== 'none') : [];
    let status, why = '';
    if (ct.rating === 'attest') status = 'awaiting';
    else if (ct.rating === 'not_assessed') status = 'na';
    else if (!withData.length) { status = 'na'; why = 'No data: the tool behind this control isn’t connected to Liongard or couldn’t be read'; }
    else if (withData.some(c => st(c) === 'fail')) status = 'fail';
    else if (withData.some(c => st(c) === 'partial')) status = 'partial';
    else status = ct.rating === 'full' && withData.length === res.length ? 'pass' : 'inpart';
    let mark = null;
    if (mk) {
      const expired = !!(mk.until && new Date(mk.until) < now);
      mark = { ...mk, expired };
      if (mk.state === 'exception' && ['fail', 'partial'].includes(status) && !expired) status = 'risk';
      else if ((mk.state === 'attested' || mk.state === 'recorded') && ['awaiting', 'na'].includes(status)) status = expired ? 'expired' : mk.state;
    }
    return { id: ct.id, key: ctlKey(fw, ct.id), name: ct.name, summary: ct.summary, rating: ct.rating, group: groupOf(fw, ct), ra: ct.ra, tested: ct.tested, gap: ct.gap, source: ct.source,
      checks: withData.length ? withData.map(c => c.key) : ct.checks, status, why, mark, strict: res.some(c => strict(c.key) && c.status === 'partial') };
  });
  // Each framework: coverage (how many of its controls Liongard evidences) and the results over those, always together.
  // `score` is an internal technical-posture figure over evidenced controls (pass 1, partial 0.5, fail 0), for trends only.
  const CW = { pass: 1, partial: .5, inpart: .5, fail: 0, risk: 0 };
  const frameworks = FRAMEWORKS.map(f => {
    const controls = controlsOf(f.key);
    const cnt = (...st) => controls.filter(c => st.includes(c.status)).length;
    const ev = controls.filter(c => c.status in CW);
    const rel = checks.filter(c => (c.refs[f.key] || []).length);
    const unread = rel.filter(c => c.unread).length;
    const qs = POLICY.filter(q => (q.refs[f.key] || []).length);
    return { ...f, controls, total: controls.length, evidenced: ev.length, pass: cnt('pass'), part: cnt('partial', 'inpart'), fail: cnt('fail', 'risk'), risk: cnt('risk'),
      attested: cnt('attested'), recorded: cnt('recorded'), awaiting: cnt('awaiting'), expired: cnt('expired'), na: cnt('na'),
      score: ev.length ? Math.round(ev.reduce((a, c) => a + CW[c.status], 0) / ev.length * 100) : null, provisional: unread > 0, unread,
      checks: rel.map(c => ({ name: c.name, status: c.status, ref: c.refs[f.key].join(', ') })),
      policy: { total: qs.length, yes: qs.filter(q => (marks[`q:${q.key}`] || {}).state === 'yes').length, answered: qs.filter(q => marks[`q:${q.key}`]).length } };
  });
  // ---------- Profile: which frameworks this client is scoped to ----------
  const profile = input.profile || null;
  for (const f of frameworks) {
    const why = profile && RULES[f.key] ? RULES[f.key](profile) : null;
    const extra = profile && (profile.extra || []).includes(f.key), hidden = profile && (profile.hidden || []).includes(f.key);
    f.why = why || (extra ? 'Added by you' : '');
    f.scope = !profile ? 'all' : hidden ? 'out' : why || extra ? 'in' : 'out';
  }
  const inScope = frameworks.filter(f => f.scope !== 'out');
  // ---------- Posture score (0-10) overall and by area, over every check with data ----------
  const ten = v => v == null ? null : v / 10;   // scores are whole percentages, so this is one decimal place
  const areas = AREAS.map(([name, keys]) => { const list = checks.filter(c => keys.includes(c.key)); return { name, score: ten(scoreOf(list)), checks: list.length, keys }; }).filter(a => a.checks);
  const posture = ten(scoreOf(checks));
  // ---------- Fix once, improve many: what each open check would add to the in-scope frameworks if it passed ----------
  const gains = checks.filter(c => !c.unread && (c.status === 'fail' || c.status === 'partial') && c.state !== 'exception').map(c => {
    const per = inScope.filter(f => (c.refs[f.key] || []).length && f.score != null).map(f => {
      const rel = checks.filter(x => (x.refs[f.key] || []).length);
      return { key: f.key, name: f.name, pts: scoreOf(rel, { [c.key]: 'pass' }) - scoreOf(rel) };
    }).filter(g => g.pts > 0);
    return { key: c.key, name: c.name, fix: c.fix, gains: per, total: per.reduce((a, g) => a + g.pts, 0) };
  }).filter(g => g.total).sort((a, b) => b.total - a.total).slice(0, 5);
  // Every open check's total gain over the in-scope frameworks (the check × framework matrix sorts by it).
  for (const c of checks) {
    if (c.unread || !['fail', 'partial'].includes(c.status)) { c.gain = 0; continue; }
    c.gain = inScope.filter(f => (c.refs[f.key] || []).length && f.score != null).reduce((a, f) => { const rel = checks.filter(x => (x.refs[f.key] || []).length); return a + scoreOf(rel, { [c.key]: 'pass' }) - scoreOf(rel); }, 0);
  }
  // ---------- Heat map: each in-scope framework's score in each area (0-10), from the same checks ----------
  const target = profile && profile.target >= 1 && profile.target <= 10 ? profile.target : 8;
  const heat = inScope.map(f => ({ key: f.key, name: f.name, cells: AREAS.map(([area, keys]) => { const list = checks.filter(c => keys.includes(c.key) && (c.refs[f.key] || []).length); return { area, score: ten(scoreOf(list)), keys: list.map(c => c.key) }; }) }));
  // ---------- Remediation list: items the MSP added from the drill-down, checked against this pull ----------
  // An item is still affected while its check lists it. Done + no longer listed = verified fixed; done + still listed
  // on data pulled after it was marked = reopened; not marked but gone from the data = fixed (unconfirmed by anyone).
  const SEV_DEFAULT = { privMfa: 'Critical', leavers: 'High', mfa: 'High', edrAll: 'High', malware: 'High', os: 'High', assets: 'High', boundary: 'High', dmarc: 'High', backup: 'High', encrypt: 'Medium', patch: 'Medium', hostFw: 'Medium', stale: 'Medium', adminAcct: 'Medium', evidence: 'Medium', training: 'Low' };
  const remediation = Object.entries(input.remediation || {}).map(([id, r]) => {
    const c = checks.find(x => x.key === r.check);
    const known = c && !c.unread && c.status !== 'none';
    const affected = known ? (c.items || []).some(i => i.t === r.t) : null;
    const after = P && r.doneAt && new Date(P) > new Date(r.doneAt);
    const state = affected == null ? (r.status === 'done' ? 'awaiting' : r.status) : !affected ? (r.status === 'done' ? 'verified' : 'fixed') : r.status === 'done' ? (after ? 'reopened' : 'awaiting') : r.status;
    return { id, ...r, checkName: c ? c.name : r.checkName || r.check, state, affected };
  }).sort((a, b) => ['Critical', 'High', 'Medium', 'Low'].indexOf(a.sev) - ['Critical', 'High', 'Medium', 'Low'].indexOf(b.sev) || String(a.at).localeCompare(String(b.at)));
  const progress = ['Critical', 'High', 'Medium', 'Low'].map(sev => { const l = remediation.filter(r => r.sev === sev); return { sev, total: l.length, verified: l.filter(r => r.state === 'verified' || r.state === 'fixed').length, done: l.filter(r => r.state === 'awaiting').length, progress: l.filter(r => r.state === 'progress').length, open: l.filter(r => r.state === 'open' || r.state === 'reopened').length }; });
  // ---------- Trend: snapshots saved at each data pull (main process), plus this one ----------
  const snap = { at: P, posture, areas: Object.fromEntries(areas.map(a => [a.name, a.score])), fw: Object.fromEntries(frameworks.map(f => [f.key, f.score])), checks: Object.fromEntries(checks.map(c => [c.key, c.unread ? 'none' : eff(c)])) };
  const history = [...(input.history || []).filter(h => h && h.at && h.at !== P), ...(P ? [snap] : [])].sort((a, b) => a.at.localeCompare(b.at));
  // The baseline for "since last review": the snapshot nearest 90 days back, or the oldest one if history is shorter.
  const base = history.length > 1 ? history.slice(0, -1).reduce((a, h) => Math.abs(now - new Date(h.at) - 90 * DAY) < Math.abs(now - new Date(a.at) - 90 * DAY) ? h : a) : null;
  const improved = base ? checks.filter(c => ['fail', 'partial'].includes(base.checks && base.checks[c.key]) && eff(c) === 'pass').map(c => c.name) : [];
  const worse = base ? checks.filter(c => base.checks && base.checks[c.key] === 'pass' && ['fail', 'partial'].includes(c.status)).map(c => c.name) : [];
  const questions = POLICY.map(q => ({ ...q, answer: marks[`q:${q.key}`] || null }));

  const n = s => checks.filter(c => c.status === s).length;
  const riskN = checks.filter(c => c.status === 'fail' && c.mark && c.mark.state === 'exception').length;
  const fails = checks.filter(c => c.status === 'fail');
  const byCov = [...inScope].sort((a, b) => a.evidenced / a.total - b.evidenced / b.total);
  const summary = [
    `${n('pass')} of ${checks.length - n('none')} technical checks pass${n('partial') ? `, ${n('partial')} partly` : ''}. ${fails.length ? `Failing: ${fails.map(c => c.name).join('; ')}.` : 'Nothing is failing.'}`,
    ...inScope.slice(0, 3).map(f => `${f.name}: Liongard evidences ${f.evidenced} of ${f.total} ${f.unit}; ${f.pass} pass, ${f.part} in part, ${f.fail} fail. ${f.attested + f.recorded} recorded by you, ${f.awaiting + f.na + f.expired} still to answer.`),
    n('none') ? `No evidence for: ${checks.filter(c => c.status === 'none').map(c => c.name).join('; ')}. Connect the right tool to Liongard to cover ${n('none') > 1 ? 'them' : 'it'}.` : '',
    posture != null ? `Security posture ${posture.toFixed(1)} out of 10${base && base.posture != null ? ` (${posture >= base.posture ? 'up' : 'down'} ${Math.abs(posture - base.posture).toFixed(1)} since ${String(base.at).slice(0, 10)})` : ''}.` : '',
    checks.some(c => c.state === 'reopened') ? `${checks.filter(c => c.state === 'reopened').length} check${checks.filter(c => c.state === 'reopened').length > 1 ? 's were' : ' was'} marked done but Liongard’s data still shows ${checks.filter(c => c.state === 'reopened').length > 1 ? 'them' : 'it'} failing.` : '',
    'This is evidence of technical controls Liongard can see. Policies, people and process still need an assessor.',
  ].filter(Boolean);
  // What the evidence pack covers: the systems that reported, and when their data was read.
  const sys = (input.stack && input.stack.systems || []).filter(x => x.health !== 'Inactive');
  const ages = checks.map(c => c.sources && c.sources.days).filter(d => d != null);
  const scope = { endpoints: cov ? cov.managed.length + cov.unmanaged.length : null, identity: sys.filter(x => (x.caps || []).includes('identity')).length,
    network: net ? net.cards.length : null, domains: em ? em.domains.length : null, cloud: sys.filter(x => (x.caps || []).includes('cloud') || /Productivity suite/.test(x.role || '')).length,
    from: P && ages.length ? new Date(new Date(P) - Math.max(...ages) * DAY).toISOString() : P, to: P };
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, summary, scope,
    profile, target, heat, remediation, progress, severities: SEV_DEFAULT, options: { industries: INDUSTRIES, regions: REGIONS }, posture, areas, gains, history, snapshot: snap, base, improved, worse, questions,
    kpis: [
      { k: 'Checks passing', v: `${n('pass')} / ${checks.length - n('none')}`, s: `${n('partial')} partial, ${n('fail')} failing`, sev: n('fail') ? 'bad' : n('partial') ? 'warn' : 'ok' },
      { k: 'No evidence', v: n('none'), s: n('none') ? checks.filter(c => c.status === 'none').map(c => c.name).join('; ') : 'Every check had data', sev: 'info' },
      // Coverage and results per framework, never a single percentage: "evidences X of Y", then pass / in part / fail.
      { k: 'Least covered', v: byCov[0] ? `${byCov[0].evidenced} of ${byCov[0].total}` : '—', s: byCov[0] ? `${byCov[0].name} ${byCov[0].unit} evidenced by Liongard` : 'No framework in scope', sev: 'info' },
      // Distinct failing checks, not a sum over frameworks: per-framework failures stay in the framework rows.
      { k: 'Checks failing', v: n('fail'), s: `of ${checks.length - n('none')} checks with evidence${riskN ? `, ${riskN} with accepted risk` : ''} · per framework below`, sev: n('fail') - riskN > 0 ? 'bad' : 'ok' },
    ],
    // Launcher badge: with no client profile, ask for it rather than add failures up across every framework.
    badge: !profile || profile.fromDefaults ? { text: 'Set client profile', tone: 'review' }
      : n('fail') ? { text: `Checks failing: ${n('fail')} of ${checks.length - n('none')}`, tone: n('fail') - riskN > 0 ? 'act' : 'review' }
      : checks.length - n('none') ? { text: 'All clear', tone: 'ok' } : null,
    checks, frameworks,
  };
}

module.exports = { id: 'compliance', usesStack: true, collect, compute, MAP, POLICY, CATALOGUE, FRAMEWORKS };
