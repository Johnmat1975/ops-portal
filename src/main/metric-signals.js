// Reads Liongard metric values from any inspector and turns them into findings, expiry dates and versions.
// Liongard maintains 3,400+ metrics across 112 inspectors, but names and value types vary by vendor, so these
// rules work from the metric name and value shape. They are deliberately conservative: a metric only becomes a
// finding when its name says what is wrong (threats, failures, missing MFA, stale devices) and its value shows it.

const BAD = /threat|infect|malware|incident|compromis|stealer|breach|ransom|unwanted access|\bfail(ed|ure|ing|s)?\b|\berrors?\b|without (mfa|2fa|multi)|no (mfa|2fa)|(mfa|2fa) (not|disabled)|unhealthy|critical|violation|\bdown\b|offline|unprotected|infected/;
const WARN = /stale|inactive|dormant|disused|no recent (login|sign|check)|not (checked|reporting|seen|protected|enrolled|activated|licen[cs]ed|encrypted|registered|compliant|configured|signed)|missing|pending|outdated|out of date|upgradable|vulnerab|expired|expiring|past due|overdue|end of (life|support)|unsupported|\bdisabled\b|bypass|never (logged|signed)|without (filevault|bitlocker|disk encryption|encryption|anti.?virus|edr|agent)|password never expires|unassigned|over.?licen|risky|exposed|exposure|open port|guest (accounts?|users?)|external forward|quarantin|deferred|reboot required/;
const NOT_A_PROBLEM_COUNT = /total|capacity|bytes|\bsize\b|version|percent|%|ratio|days since|\bdays\b|memory|\bram\b|\bmb\b|\bgb\b|cpu|uptime|interval|threshold|limit|score/;
const CONTROL = /\bmfa\b|2fa|two.?factor|multi.?factor|encrypt|bitlocker|filevault|firewall|intrusion|\bips\b|anti.?virus enabled|anti.?malware service enabled|real.?time protection|tamper|defender healthy|secure boot|dnssec|dmarc exists|both present|dkim found|security defaults|lockout|password complexity|gatekeeper/;
const TRUE_IS_BAD = /expiring|expired|changes pending|out of date|outdated|vulnerable|anonymous|open relay|guest access enabled|public access enabled|exposed|smbv1 enabled|telnet enabled|legacy auth|(anydesk|teamviewer|screenconnect|splashtop|logmein|ammyy|vnc|rustdesk).*installed/;
// Names that look like problems but describe a good state or a setting.
const BENIGN = /without breach|count by user|reversible|missing (mac|hostname)|^disabled users|(count|number) of disabled users|\bdisabled users (count|list)|with(?!out)\b.*\benabled\b|(guest|legacy|smb\w*|telnet|autorun|remote)\b.*disabled|interface|purge|after delay|setting|policy count|polic(y|ies)$|\bgroups?\b count|failover|enabled count|online|(?<!un)healthy|\bactive (user|device|endpoint|computer)s?\b(?! with)/;
// Features that are risky when on (so "… Disabled" is the good state).
const RISKY = /legacy auth|smb ?v?1|telnet|guest access|autorun|anonymous|basic auth|remote registry/;
const EXPIRY = /expir|renew|warranty|end of (life|support)|valid (until|to)|not after|support end/;
const VERSION = /firmware|software version|os version|agent version|\bversion\b|operating system$/;

const isEmpty = v => v == null || v === '' || v === '-' || v === '--' || /^(null|undefined|none|n\/a|null\.null\.null|-)$/i.test(String(v).trim()) || (Array.isArray(v) && (!v.length || v.every(isEmpty)));
function norm(v) {
  if (typeof v === 'string') {
    const s = v.trim().replace(/^"|"$/g, '');
    if (/^(true|false|yes|no|enabled|disabled|on|off)$/i.test(s)) return /^(true|yes|enabled|on)$/i.test(s);
    if (/^-?\d+(\.\d+)?$/.test(s) && s.length < 12) return +s;
    return s;
  }
  if (Array.isArray(v) && v.length && v.every(x => typeof x === 'boolean')) return v.every(Boolean);   // e.g. [true] from per-interface checks
  if (Array.isArray(v) && v.length === 1 && Array.isArray(v[0]) && v[0].length === 1 && typeof v[0][0] === 'number') return v[0][0];
  return v;
}
// Metric names carry the inspector as a prefix ("SonicWall: ", "Duo Security | "). Drop it for display.
// Some metric names are machine-style ("iru.tenant.stale_checkin_7d_count"): turn those into words.
const shortName = n => {
  const s = String(n || '').trim();
  if (/^[\w.]+$/.test(s) && /[._]/.test(s)) { const w = s.split('.').pop().replace(/_/g, ' ').replace(/(\d+)d\b/, '$1-day').replace(/\bcheckin\b/, 'check-in'); return w.charAt(0).toUpperCase() + w.slice(1); }
  return s.replace(/^\s*[^:|]{2,40}?\s*[:|]\s*/, '').replace(/\s*\[(VI|RD|Power BI)\]\s*$/i, '').trim();
};
// For display only: "Stale Hosts Count (>7 days)" reads as "Stale hosts (>7 days)". Classification still uses the full name.
const plain = n => { const s = shortName(n).replace(/\s+(count|list|summary)(?=\s*(\(|$))/ig, '').replace(/^(count|number) of\s+/i, '').trim(); return s.charAt(0).toUpperCase() + s.slice(1); };
const stem = n => shortName(n).toLowerCase().replace(/\b(count|list|summary|total|number of|of)\b/g, '').replace(/[^a-z]+/g, ' ').trim();

function toDate(v, at) {
  if (typeof v === 'number') {
    if (v > 1e9 && v < 1e10) return new Date(v * 1000);   // epoch seconds
    if (v > 1e12 && v < 1e13) return new Date(v);
    return null;
  }
  if (typeof v !== 'string' || !/\d{4}|\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}/.test(v)) return null;
  const d = utcDate(v);
  return !d || d.getUTCFullYear() < 2000 || d.getUTCFullYear() > 2100 ? null : d;
}
// A date with no time zone ("03/15/2027", "2027-03-15 00:00:00", "Mar 15 2027") means that calendar day, wherever the
// MSP is. JavaScript reads those in the computer's local time, which puts them a day early east of UTC once turned into
// an ISO date. Read them as UTC instead. Strings with a zone (Z, +02:00, UTC, GMT) and ISO date-only strings are already exact.
function utcDate(v) {
  const s = String(v).trim().replace(/ UTC$/i, 'Z');
  const d = new Date(s);
  if (isNaN(d)) return null;
  if (/(Z|[+-]\d{2}:?\d{2}|GMT|UTC)$/i.test(s) || /^\d{4}-\d{2}-\d{2}$/.test(s)) return d;
  return new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()));
}

// One metric value -> zero or more signals.
function classify(metric, now = new Date()) {
  const name = String(metric.n || ''), label = shortName(name), n = label.toLowerCase();
  // A list sent as one text value ("HOST-A|HOST-B|HOST-C") is a list.
  const raw = typeof metric.v === 'string' && /\blist\b/.test(n) && /\|/.test(metric.v) ? metric.v.split('|').map(x => x.trim()).filter(Boolean) : metric.v;
  const v = norm(raw);
  if (isEmpty(v)) return [];
  const out = [];
  const listLen = Array.isArray(v) ? (metric.len ?? v.filter(x => !isEmpty(x)).length) : null;
  const count = typeof v === 'number' ? v : (listLen != null && /\blist\b|\bnames?\b|\busers?\b|\bdevices?\b|\baccounts?\b|\bendpoints?\b|\bcomputers?\b|\bmachines?\b|\bhosts?\b|\bagents?\b|\bclients?\b|\bservers?\b/.test(n) ? listLen : null);

  // Counts and lists that name a problem.
  const window = /\([^)]*\bdays?\)|\b(last|in|within|over|past|>) ?\d+ days?\b/g;   // a time window, not a duration
  if (count != null && count > 0 && !NOT_A_PROBLEM_COUNT.test(n.replace(/\bcount\b/, '').replace(window, ''))) {
    let sev = BAD.test(n) ? 'bad' : WARN.test(n) ? 'warn' : null;
    if (sev === 'bad' && /printer|quarantin/.test(n)) sev = 'warn';   // offline printers and quarantined (already handled) threats are worth a look, not an alarm
    if (sev && !BENIGN.test(n)) {
      out.push({ kind: 'finding', sev, label, value: count, list: Array.isArray(raw) ? raw.filter(x => !isEmpty(x)).slice(0, 25) : null, stem: stem(name) });
    }
  }
  // Booleans for controls that should be on, or conditions that should be off.
  if (typeof v === 'boolean') {
    if (v === false && CONTROL.test(n) && !/disabled|not |without|low cpu/.test(n)) out.push({ kind: 'finding', sev: 'warn', label, value: 'Off', stem: stem(name) });
    else if (v === false && /default password changed/.test(n)) out.push({ kind: 'finding', sev: 'warn', label: 'Default admin password not changed', value: 'No', stem: stem(name) });
    // "<protection> Disabled" = true means the protection is off; "<risky feature> Disabled" = false means the risky feature is on.
    else if (v === true && /\bdisabled\b/.test(n) && CONTROL.test(n) && !RISKY.test(n)) out.push({ kind: 'finding', sev: 'warn', label, value: 'Yes', stem: stem(name) });
    else if (v === false && /\bdisabled\b/.test(n) && RISKY.test(n)) out.push({ kind: 'finding', sev: 'warn', label, value: 'No (still on)', stem: stem(name) });
    else if (v === true && TRUE_IS_BAD.test(n) && !/not installed|\bdisabled\b/.test(n)) out.push({ kind: 'finding', sev: /expired|vulnerable|anonymous|open relay|smbv1|telnet/.test(n) ? 'bad' : 'warn', label, value: 'Yes', stem: stem(name) });
  }
  // Expiry dates (licences, warranties, subscriptions, certificates, domains).
  if (EXPIRY.test(n) && !/count|\blist\b|in \d+ days|or less|within/.test(n)) {
    let d = null;
    if (/days until|days (left|remaining)/.test(n) && typeof v === 'number') d = new Date((metric.at ? new Date(metric.at) : now).getTime() + v * 864e5);
    else if (!/days/.test(n)) d = toDate(v, metric.at);
    if (d) out.push({ kind: 'expiry', label, date: d.toISOString().slice(0, 10), days: Math.floor((d - now) / 864e5) });
  }
  // Versions, for drift across identical devices.
  if (VERSION.test(n) && !/count|\blist\b|summary|distinct/.test(n) && (typeof v === 'string' || typeof v === 'number') && String(v).length < 60) {
    out.push({ kind: 'version', label, value: String(v) });
  }
  return out;
}

// Short display form of a metric value, for drill-downs.
function display(v, name) {
  v = norm(v);
  if (isEmpty(v)) return '—';
  if (name && EXPIRY.test(name.toLowerCase()) && !/days|count/i.test(name)) { const d = toDate(v); if (d) return d.toISOString().slice(0, 10); }
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(2);
  if (typeof v === 'string') return v.length > 140 ? v.slice(0, 140) + '…' : v;
  if (Array.isArray(v)) return `${v.length} item${v.length === 1 ? '' : 's'}`;
  return `${Object.keys(v).length} fields`;
}

module.exports = { classify, display, shortName, plain, norm, isEmpty, utcDate };
