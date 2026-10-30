// Email & domain security: SPF, DKIM, DMARC, DNSSEC, registrar lock, name servers, MX and mail filtering, domain expiry
// and TLS certificates for every domain inspected, with the exact DNS records to publish. Uses the checks Liongard's
// Internet Domain/DNS inspector already runs (SPF lookup counts, void lookups, duplicate records, DKIM keys, DMARC pct and
// reporting), the TLS/SSL inspector for certificates, and the client's other mail tools from Liongard's metrics.
const { pMap } = require('../api');
const DAY = 864e5;
const DNS_Q = '{name: Name, si: SystemInfo.{registrar: Registrar, expires: DomainExpirationDate, emailExists: EmailExists, mailVendor: EmailHostingVendor, parked: IsParkedDomain, ' +
  'status: DomainStatus, ns: NameServerStr, dnsVendor: DNSHostingVendor, webVendor: WebsiteHostingVendor, hasTls: WebsiteHasTLS}, ' +
  'eso: EmailSecurityOverview, spf: SPFRecord, dmarc: DMARCRecord, dkim: DKIMFound, dnssec: DNSSEC, mx: DNSMXRecords[].{host: Record || data || Name, pref: Preference}, spoof: SpoofIntel, ' +
  'es: EmailSecurity.{lookups: spfRecords[0].DnsLookupCount, voids: spfRecords[0].VoidLookupCount, spfCount: length(spfRecords || `[]`), dmarcCount: length(dmarcRecords || `[]`), ' +
  'uniq: spfRecordUniqueness[0].result, syntax: spfRecordSyntaxCheck[0].result, lookupLimit: spfLookupCountValidation[0].result, voidLimit: spfVoidLookupLimit[0].result, noPtr: spfNoPtrModifier[0].result, ' +
  'postAll: spfPostAllMechanismCheck[0].result, dkimKey: dkimPublicKeyCheck[0].result, dkimSyntax: dkimSyntaxCheck[0].result, dmarcSyntax: dmarcSyntaxCheck[0].result, dmarcExt: dmarcExternalDomainPermission[0].result}, ' +
  'subs: length(Subdomains || `[]`)}';
const TLS_Q = 'SystemInfo.{name: Name, exists: SSLCertExists, expires: ExpiresOn, issuer: IssuerOrganizationName, match: SSLMatchNames, protocols: Protocols, cn: SubjectCommonName}';

async function collect(api, env) {
  const sys = (await api.systems(env.ID)).filter(s => s.enabled && s.systemDetailId);
  const ref = s => ({ systemId: s.systemId, systemDetailId: s.systemDetailId, inspectedOn: s.inspectedOn, lpId: s.lpId, inspectorId: s.inspectorId });
  const dns = await pMap(sys.filter(s => s.inspector === 'Internet Domain/DNS'), 8, async s => ({ ...(await api.evaluate(s.systemDetailId, DNS_Q).catch(err => ({ _error: String(err.message || err) }))), _lpName: s.name, _sys: ref(s) }));
  const tls = await pMap(sys.filter(s => s.inspector === 'TLS/SSL'), 8, async s => ({ ...(await api.evaluate(s.systemDetailId, TLS_Q).catch(err => ({ _error: String(err.message || err) }))), _lpName: s.name, _sys: ref(s) }));
  return { environment: env, dns, tls };
}

const yes = v => v === true || /^(yes|true)$/i.test(String(v || ''));
const lc = s => String(s || '').toLowerCase();
const clean = v => (v == null || /^(undefined|null|none)$/i.test(String(v).trim())) ? '' : String(v);   // Liongard sometimes returns "undefined" as text
const vendor = v => [...new Set(clean(v).split('|').map(x => x.trim()).filter(Boolean))].join(', ');
const passed = v => v == null ? null : /^pass/i.test(String(v));

// Where mail is delivered: the mail host, or a filtering gateway in front of it.
const MX_VENDORS = [[/protection\.outlook\.com/, 'Microsoft 365', 'host'], [/google(mail)?\.com|aspmx/, 'Google Workspace', 'host'], [/pphosted|ppe-hosted|proofpoint/, 'Proofpoint', 'gateway'],
  [/mimecast/, 'Mimecast', 'gateway'], [/barracuda/, 'Barracuda', 'gateway'], [/sophos/, 'Sophos Email', 'gateway'], [/vadesecure|vade\b/, 'Vade', 'gateway'], [/spamtitan|titanhq/, 'SpamTitan', 'gateway'],
  [/mailprotector/, 'Mailprotector', 'gateway'], [/appriver|zixmail/, 'AppRiver / Zix', 'gateway'], [/messagelabs|symantec/, 'Symantec', 'gateway'], [/iphmx|cisco/, 'Cisco Secure Email', 'gateway'],
  [/trendmicro|tmes/, 'Trend Micro', 'gateway'], [/forcepoint|mailcontrol/, 'Forcepoint', 'gateway'], [/hornetsecurity|antispameurope/, 'Hornetsecurity', 'gateway'], [/libraesva/, 'Libraesva', 'gateway'],
  [/zoho/, 'Zoho Mail', 'host'], [/secureserver|godaddy/, 'GoDaddy mail', 'host'], [/mailgun|sendgrid|amazonses/, 'Sending service', 'host']];
const mxVendor = host => { const h = lc(host); const m = MX_VENDORS.find(([re]) => re.test(h)); return m ? { name: m[1], kind: m[2] } : null; };

function compute(input) {
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const daysTo = iso => iso ? Math.floor((new Date(iso) - now) / DAY) : null;
  // A domain or certificate whose dataprint couldn't be read is listed as unread, never scored: an empty read would
  // otherwise show the domain as spoofable with no SPF or DMARC. Caches from before 0.5 held {} for a failed read.
  const unreadRec = d => d._error || !Object.keys(d).some(k => !k.startsWith('_'));
  const unread = [...(input.dns || []).filter(unreadRec).map(d => ({ name: lc(d._lpName), kind: 'Domain', sys: d._sys, error: d._error || 'No data returned' })),
    ...(input.tls || []).filter(unreadRec).map(t => ({ name: lc(t._lpName).replace(/^ssl\s*-\s*/, ''), kind: 'Certificate', sys: t._sys, error: t._error || 'No data returned' }))];
  const allTls = (input.tls || []).filter(t => !unreadRec(t)).map(t => {
    const days = t.exists !== false ? daysTo(t.expires) : null;
    const oldTls = t.protocols ? Object.entries(t.protocols).filter(([k, v]) => /^tls1(_[01])?$/.test(k) && /^supported/i.test(v)).map(([k]) => k.replace('tls1_', 'TLS 1.').replace(/^tls1$/, 'TLS 1.0')) : [];
    const site = lc(t._lpName).replace(/^ssl\s*-\s*/, '') || lc(t.name);
    const st = t.exists === false ? 'fail' : days == null ? 'none' : days < 0 ? 'fail' : days <= 30 || oldTls.length || t.match === false ? 'warn' : 'pass';
    return { site, name: lc(t.name), cn: Array.isArray(t.cn) ? t.cn.join(', ') : clean(t.cn), issuer: clean(t.issuer), expires: t.expires || null, days, oldTls, match: t.match, exists: t.exists !== false, state: st, sys: t._sys };
  }).sort((a, b) => (a.days ?? 1e9) - (b.days ?? 1e9));

  const hasFilterTool = !!(input.stack && input.stack.systems.some(s => s.health !== 'Inactive' && /Email security/.test(s.role)));
  const domains = (input.dns || []).filter(d => !unreadRec(d) && (d.name || d._lpName)).map(d => {
    const name = lc(d.name || d._lpName);
    const eso = d.eso || {}, si = { ...(d.si || {}) }; si.mailVendor = vendor(si.mailVendor);
    const es = d.es || {}, spoof = d.spoof || {};
    const mx = (Array.isArray(d.mx) ? d.mx : []).map(m => clean(m && m.host).replace(/\.$/, '')).filter(Boolean);
    const mxVendors = [...new Map(mx.map(mxVendor).filter(Boolean).map(v => [v.name, v])).values()];
    const nullMx = mx.length === 1 && /^\.?$/.test(mx[0]);
    const sends = (yes(si.emailExists) || mx.length > 0) && !nullMx;
    const spfRec = clean(d.spf) || clean(eso.SpfRecord) || clean(spoof.spfRecord);
    const dmarcRec = clean(d.dmarc) || clean(eso.DmarcRecord) || clean(spoof.dmarcRecord);
    const policy = (/\bp=(none|quarantine|reject)/i.exec(dmarcRec) || [])[1];
    const subPolicy = (/\bsp=(none|quarantine|reject)/i.exec(dmarcRec) || [])[1];
    const pct = +((/\bpct=(\d+)/i.exec(dmarcRec) || [])[1] ?? 100);
    const rua = /\brua=/i.test(dmarcRec);
    const dkimRec = clean(eso.DkimRecord);
    const dkimFound = d.dkim === true || /^found/i.test(eso.DkimRecordResult || '');
    const dkimValid = /found: valid/i.test(eso.DkimRecordResult || '') || (dkimFound && passed(es.dkimKey) === true);
    const dkimNull = dkimFound && dkimRec.split('\n').filter(Boolean).every(l => /p=\s*$/i.test(l.trim()));
    const dnssecOn = Array.isArray(d.dnssec) ? d.dnssec.length > 0 : yes(d.dnssec);
    const lookups = typeof es.lookups === 'number' ? es.lookups : null;
    const status = lc(si.status);
    const locked = /transferprohibited/.test(status) ? (/serverTransferProhibited/i.test(si.status) ? 'registry' : 'registrar') : status ? 'no' : null;
    const certs = allTls.filter(t => t.site === name || t.site.endsWith('.' + name) || t.name === name);
    const cert = certs.find(t => t.site === name || t.name === name) || certs[0];
    const regDays = daysTo(si.expires);

    // ---------- SPF ----------
    const spfIssues = [];
    if (es.spfCount > 1 || passed(es.uniq) === false) spfIssues.push('More than one SPF record (receivers treat this as no SPF)');
    if (lookups != null && lookups > 10 || passed(es.lookupLimit) === false) spfIssues.push(`${lookups ?? 'Over 10'} DNS lookups (the limit is 10, so SPF fails)`);
    else if (lookups != null && lookups >= 8) spfIssues.push(`${lookups} of 10 DNS lookups used`);
    if (passed(es.voidLimit) === false || (es.voids || 0) > 2) spfIssues.push(`${es.voids || 'Too many'} void lookups (includes that don’t resolve)`);
    if (passed(es.noPtr) === false) spfIssues.push('Uses the deprecated ptr mechanism');
    if (passed(es.postAll) === false) spfIssues.push('Mechanisms after "all" are ignored');
    if (passed(es.syntax) === false) spfIssues.push('Syntax error');
    const spfHard = spfIssues.some(i => /more than one|limit is 10|syntax/i.test(i));
    const spf = !spfRec ? ['fail', 'No SPF record', 'Not found']
      : spfHard ? ['fail', spfRec, spfIssues[0]]
      : /\+all\b/.test(spfRec) ? ['fail', spfRec, 'Allows anyone to send (+all)']
      : /\?all\b/.test(spfRec) ? ['fail', spfRec, 'Neutral (?all) protects nothing']
      : /-all\b/.test(spfRec) ? [spfIssues.length ? 'warn' : 'pass', spfRec, spfIssues[0] || `Hard fail (-all)${lookups != null ? `, ${lookups} of 10 lookups` : ''}`]
      : /~all\b/.test(spfRec) ? ['warn', spfRec, spfIssues[0] || 'Soft fail (~all)']
      : ['fail', spfRec, 'No -all or ~all'];

    // ---------- DKIM / DMARC ----------
    const dkim = !sends && dkimNull ? ['pass', 'Empty (null) DKIM keys published', 'Correct for a domain that doesn’t send']
      : !sends && !dkimFound ? ['none', 'No DKIM record', 'Not needed if the domain never sends']
      : dkimValid ? ['pass', 'Valid DKIM key found', 'Signing']
      : dkimFound ? ['fail', dkimNull ? 'Selectors found with empty keys' : 'DKIM record found', passed(es.dkimSyntax) === false ? 'Syntax error' : 'Found but not valid']
      : ['fail', 'No DKIM record', 'Not found (Liongard checks common selectors)'];
    const dmarcIssues = [];
    if (dmarcRec && pct < 100) dmarcIssues.push(`Applies to only ${pct}% of mail (pct=${pct})`);
    if (dmarcRec && subPolicy === 'none' && policy !== 'none') dmarcIssues.push('Subdomains are not protected (sp=none)');
    if (dmarcRec && !rua) dmarcIssues.push('No reports (rua) are sent anywhere');
    if (es.dmarcCount > 1) dmarcIssues.push('More than one DMARC record');
    if (passed(es.dmarcSyntax) === false) dmarcIssues.push('Syntax error');
    const dmarc = !dmarcRec ? ['fail', 'No DMARC record', 'Not found']
      : es.dmarcCount > 1 || passed(es.dmarcSyntax) === false ? ['fail', dmarcRec, dmarcIssues[0]]
      : (policy === 'reject' || policy === 'quarantine') ? [dmarcIssues.length ? 'warn' : 'pass', dmarcRec, `Enforced: p=${policy}${dmarcIssues.length ? `. ${dmarcIssues[0]}` : rua ? ', with reports' : ''}`]
      : ['warn', dmarcRec, `Monitor only (p=none)${rua ? '' : ' and no reports'}`];
    const certS = !cert ? ['none', 'No TLS/SSL inspector', '']
      : !cert.exists ? ['fail', 'No certificate found', '']
      : cert.days < 0 ? ['fail', `Expired ${fmt(cert.expires)}`, cert.issuer]
      : cert.state === 'warn' ? ['warn', `Expires ${fmt(cert.expires)} (${cert.days} days)`, [cert.issuer, cert.oldTls.length ? `${cert.oldTls.join(' and ')} still enabled` : '', cert.match === false ? 'Name doesn’t match' : ''].filter(Boolean).join(' · ')]
      : ['pass', `Expires ${fmt(cert.expires)}`, [cert.issuer, 'TLS 1.2+ only'].filter(Boolean).join(' · ')];
    const lock = locked === 'no' ? 'warn' : locked ? 'pass' : 'none';
    const spoofable = sends ? !(dmarc[0] === 'pass' || (dmarc[0] === 'warn' && policy !== 'none')) || spf[0] === 'fail' : !(policy === 'reject' && /-all/.test(spfRec));

    // ---------- Grade: sending domains are judged on anti-spoofing first ----------
    let score = 100;
    if (sends) {
      score -= { fail: 35, warn: 15 }[dmarc[0]] || 0;
      score -= { fail: 25, warn: 8 }[spf[0]] || 0;
      score -= { fail: 20 }[dkim[0]] || 0;
    } else {
      if (!/-all/.test(spfRec)) score -= 25;
      if (policy !== 'reject') score -= 30;
      if (!nullMx && !mx.length) score -= 0;
    }
    score -= { fail: 10, warn: 4 }[certS[0]] || 0;
    if (!dnssecOn) score -= 5;
    if (locked === 'no') score -= 5;
    if (regDays != null && regDays < 30) score -= 10;
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

    // ---------- What to fix, and the exact records ----------
    const fix = [], rec = [];
    if (!sends) {
      if (!/-all/.test(spfRec)) rec.push([`${name}`, 'TXT', 'v=spf1 -all']);
      if (policy !== 'reject') rec.push([`_dmarc.${name}`, 'TXT', 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;']);
      if (!mx.length) rec.push([`${name}`, 'MX', '0 .']);
      if (!dkimFound) rec.push([`*._domainkey.${name}`, 'TXT', 'v=DKIM1; p=']);
      if (rec.length) fix.push('This domain doesn’t appear to send email, so lock it down so nobody can spoof it');
    } else {
      if (!spfRec) fix.push(`Publish an SPF record that lists ${si.mailVendor ? `${titleCase(si.mailVendor)} (the mail host)` : 'every service that sends for this domain'}, ending in -all`);
      spfIssues.forEach(i => fix.push(`SPF: ${i.replace(/\s*\(.*\)$/, '')}${/lookups/.test(i) ? '. Remove unused includes or flatten the record' : ''}`));
      if (spf[0] === 'warn' && /~all/.test(spfRec)) fix.push('Once every sender is listed in SPF, change ~all to -all');
      if (!dmarcRec) { fix.push('Publish DMARC in monitor mode, review the reports for 2–4 weeks, then move to quarantine and reject'); rec.push([`_dmarc.${name}`, 'TXT', `v=DMARC1; p=none; rua=mailto:dmarc@${name}; fo=1`]); }
      else if (policy === 'none') fix.push('DMARC is monitor-only. Move to p=quarantine, then p=reject, once the reports are clean');
      dmarcIssues.forEach(i => fix.push(`DMARC: ${i}`));
      if (dkim[0] === 'fail') fix.push(`Turn on DKIM signing${si.mailVendor ? ` in ${titleCase(si.mailVendor)}` : ' at the mail provider'} and publish the key`);
      if (!mxVendors.some(v => v.kind === 'gateway') && !hasFilterTool) fix.push('No email filtering gateway in front of the mailbox. Consider one, or confirm the mail host’s own filtering is configured');
    }
    if (certS[0] === 'fail') fix.push('Install a valid TLS certificate');
    else if (cert && cert.days != null && cert.days <= 30) fix.push(`Renew the TLS certificate before ${fmt(cert.expires)}`);
    if (cert && cert.oldTls.length) fix.push(`Disable ${cert.oldTls.join(' and ')} on the web server`);
    if (regDays != null && regDays <= 60) fix.push(`Renew the domain registration before ${fmt(si.expires)}${si.registrar ? ` (${titleCase(si.registrar)})` : ''}`);
    if (locked === 'no') fix.push(`Turn on the registrar transfer lock${si.registrar ? ` at ${titleCase(si.registrar)}` : ''}`);
    if (!dnssecOn) fix.push(`Consider turning on DNSSEC${si.dnsVendor ? ` with the DNS host (${titleCase(vendor(si.dnsVendor))})` : ''}`);

    const host = (mxVendors.find(v => v.kind === 'host') || {}).name;   // the MX names the service better than the hosting company does
    return { name, sends, parked: yes(si.parked), mailVendor: host || (si.mailVendor ? titleCase(si.mailVendor) : ''), mx, mxVendors, nullMx,
      registrar: si.registrar ? titleCase(si.registrar) : '', regExpires: si.expires || null, regDays, locked,
      ns: clean(si.ns).toLowerCase(), dnsHost: si.dnsVendor ? titleCase(vendor(si.dnsVendor)) : '', webHost: si.webVendor ? titleCase(vendor(si.webVendor)) : '',
      lookups, spf, spfIssues, dkim, dmarc, dmarcIssues, policy: policy || '', pct, rua, dnssec: dnssecOn ? 'pass' : 'warn', lock, cert: certS, certs: certs.map(c => c.site),
      spoofable, grade, score, fix, rec, subs: d.subs || 0, sys: d._sys };
  }).sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));

  // ---------- The client's other mail tools ----------
  const st = input.stack;
  const live = st ? st.systems.filter(s => s.health !== 'Inactive') : [];
  const toolsBy = re => [...new Map(live.filter(s => re.test(s.role)).map(s => [s.inspector, { name: s.inspector, health: s.health, systemId: s.systemId, systemDetailId: s.systemDetailId }])).values()];
  const mxGateways = [...new Set(domains.flatMap(d => d.mxVendors.filter(v => v.kind === 'gateway').map(v => v.name)))];
  const mailTools = [
    { k: 'Mail host', tools: toolsBy(/Productivity suite/), seen: [...new Set(domains.flatMap(d => d.mxVendors.filter(v => v.kind === 'host').map(v => v.name)))] },
    { k: 'Email filtering', tools: toolsBy(/Email security/), seen: mxGateways },
    { k: 'DNS filtering', tools: toolsBy(/DNS filtering|Web security/) },
    { k: 'DNS host / edge', tools: toolsBy(/DNS & edge|Registrar/), seen: [...new Set(domains.map(d => d.dnsHost).filter(Boolean))].slice(0, 4) },
    { k: 'Security training', tools: toolsBy(/Security training/) },
  ];
  const fwd = st ? st.findings.filter(f => /external forward/i.test(f.label)).map(f => ({ system: f.system, inspector: f.inspector, value: f.value, list: f.list, systemId: f.systemId, systemDetailId: f.systemDetailId })) : [];

  // ---------- Fix pack: every record to publish, grouped by who hosts the DNS ----------
  const fixPack = [];
  for (const d of domains) for (const [host, type, value] of d.rec) fixPack.push({ domain: d.name, dnsHost: d.dnsHost || d.ns.split(',')[0] || 'Unknown DNS host', host, type, value });
  fixPack.sort((a, b) => a.dnsHost.localeCompare(b.dnsHost) || a.domain.localeCompare(b.domain));

  const sending = domains.filter(d => d.sends);
  const spoofSending = sending.filter(d => d.spoofable), spoofIdle = domains.filter(d => !d.sends && d.spoofable);
  const certDue = allTls.filter(t => t.state === 'fail' || (t.days != null && t.days <= 30));
  const regDue = domains.filter(d => d.regDays != null && d.regDays <= 60);
  const unlocked = domains.filter(d => d.locked === 'no');
  const lookupRisk = domains.filter(d => d.lookups != null && d.lookups >= 9);
  const summary = [
    `${domains.length} domain${domains.length === 1 ? '' : 's'}, ${sending.length} sending email${sending.length ? ` (${[...new Set(sending.map(d => d.mailVendor).filter(Boolean))].join(', ') || 'mail host not identified'})` : ''}.`,
    spoofSending.length + spoofIdle.length ? `${spoofSending.length + spoofIdle.length} domain${spoofSending.length + spoofIdle.length > 1 ? 's' : ''} can be spoofed${spoofSending.length ? `, ${spoofSending.length} of them sending email (${spoofSending.slice(0, 4).map(d => d.name).join(', ')}${spoofSending.length > 4 ? ' and more' : ''})` : ''}.` : '',
    !spoofSending.length && sending.length ? 'Every sending domain enforces DMARC.' : '',
    lookupRisk.length ? `SPF is at or over the 10-lookup limit on ${lookupRisk.map(d => d.name).join(', ')}.` : '',
    certDue.length ? `${certDue.length} certificate${certDue.length > 1 ? 's are' : ' is'} expired or due within 30 days.` : '',
    regDue.length ? `${regDue.length} domain registration${regDue.length > 1 ? 's renew' : ' renews'} within 60 days.` : '',
    unlocked.length ? `${unlocked.length} domain${unlocked.length > 1 ? 's have' : ' has'} no registrar transfer lock.` : '',
    fwd.length ? `${fwd.reduce((s, f) => s + (+f.value || 0), 0)} external mail forwarding rule${fwd.reduce((s, f) => s + (+f.value || 0), 0) === 1 ? '' : 's'} in ${fwd.map(f => f.inspector).join(', ')}.` : '',
  ].filter(Boolean);

  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, summary, unread,
    kpis: [
      { k: 'Domains', v: domains.length, s: `${sending.length} send${sending.length === 1 ? 's' : ''} email`, sev: 'info' },
      { k: 'Can be spoofed', v: spoofSending.length + spoofIdle.length, s: `${spoofSending.length} sending, ${spoofIdle.length} not sending`, sev: spoofSending.length ? 'bad' : spoofIdle.length ? 'warn' : 'ok' },
      { k: 'DMARC enforced', v: `${sending.filter(d => d.dmarc[0] === 'pass' || (d.dmarc[0] === 'warn' && d.policy && d.policy !== 'none')).length} / ${sending.length}`, s: 'Sending domains at quarantine or reject', sev: spoofSending.length ? 'bad' : 'ok' },
      { k: 'Certificates due', v: certDue.length, s: `Expired or within 30 days, of ${allTls.length}`, sev: certDue.some(t => t.state === 'fail') ? 'bad' : certDue.length ? 'warn' : 'ok' },
      { k: 'Registration & lock', v: regDue.length + unlocked.length, s: `${regDue.length} renewing within 60 days, ${unlocked.length} unlocked`, sev: regDue.length + unlocked.length ? 'warn' : 'ok' },
    ],
    domains, certs: allTls, mailTools, fwd, fixPack,
  };
}

function fmt(iso) { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }); }
function titleCase(s) { return String(s).toLowerCase().replace(/\b([a-z])/g, c => c.toUpperCase()).replace(/\bInc\b\.?/, 'Inc.').replace(/\bLlc\b/, 'LLC').replace(/\.Com\b/g, '.com'); }

module.exports = { id: 'email', usesStack: true, collect, compute, mxVendor };
