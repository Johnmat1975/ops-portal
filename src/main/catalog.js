// Reference data shared by panels. Keep vendor lists and dates here so rules stay readable.

// Tool categories, by Liongard inspector alias (case-insensitive substring match).
const TOOL_CATEGORIES = [
  { key: 'rmm', label: 'RMM', match: ['NinjaOne', 'Datto RMM', 'ConnectWise Automate', 'N-able', 'N-central', 'N-sight', 'Kaseya', 'Syncro', 'Atera', 'Continuum RMM', 'Pulseway', 'Action1', 'Intune'] },
  { key: 'edr', label: 'EDR / AV', match: ['CrowdStrike', 'SentinelOne', 'Sophos', 'Huntress', 'Defender for Endpoint', 'ESET', 'Bitdefender', 'Webroot', 'Malwarebytes', 'Datto EDR', 'Cylance', 'Carbon Black', 'Trend Micro', 'Acronis Cyber', 'Blackpoint', 'SonicWall Capture Client'] },
  { key: 'control', label: 'App control', match: ['ThreatLocker', 'AutoElevate', 'CyberFOX', 'Airlock'] },
  { key: 'hardening', label: 'Hardening', match: ['Senteon', 'CIS-CAT'] },
  { key: 'monitoring', label: 'Monitoring', match: ['LogicMonitor', 'PRTG', 'Domotz', 'Zabbix', 'Datadog'] },
  { key: 'agent', label: 'Liongard agent', match: ['Windows Workstation', 'Windows Server', 'macOS', 'Linux'] },
];
const DISCOVERY_SOURCES = ['Network Discovery', 'Auvik', 'UniFi', 'Cisco Meraki', 'EnGenius', 'LogicMonitor', 'Domotz', 'Lansweeper'];
const categoryOf = alias => { const a = String(alias || '').toLowerCase(); const c = TOOL_CATEGORIES.find(c => c.match.some(m => a.includes(m.toLowerCase()))); return c ? c.key : null; };

// Windows end-of-support dates (Microsoft lifecycle). Edition matters for Windows 11: Enterprise/Education get an extra year.
const WINDOWS_EOS = [
  { re: /windows 7\b/i, date: '2020-01-14', label: 'Windows 7' },
  { re: /windows 8\.1/i, date: '2023-01-10', label: 'Windows 8.1' },
  { re: /windows 10/i, date: '2025-10-14', label: 'Windows 10 (22H2)' },
  { re: /server 2008/i, date: '2020-01-14', label: 'Windows Server 2008' },
  { re: /server 2012/i, date: '2023-10-10', label: 'Windows Server 2012' },
  { re: /server 2016/i, date: '2027-01-12', label: 'Windows Server 2016' },
  { re: /server 2019/i, date: '2029-01-09', label: 'Windows Server 2019' },
  { re: /server 2022/i, date: '2031-10-14', label: 'Windows Server 2022' },
  { re: /server 2025/i, date: '2034-10-10', label: 'Windows Server 2025' },
];
// Windows 11 by build, used when the OS string is a bare build number like "10.0.22631".
const WIN11_BUILDS = { 22000: ['21H2', '2023-10-10', '2024-10-08'], 22621: ['22H2', '2024-10-08', '2025-10-14'], 22631: ['23H2', '2025-11-11', '2026-11-10'], 26100: ['24H2', '2026-10-13', '2027-10-12'] };
function osSupport(os) {
  const s = String(os || '');
  if (/LTSC/i.test(s) && /windows 11/i.test(s)) return { label: 'Windows 11 LTSC', date: '2034-10-10' };
  const hit = WINDOWS_EOS.find(w => w.re.test(s));
  if (hit) return { label: hit.label, date: hit.date };
  const b = (/10\.0\.(\d{5})/.exec(s) || [])[1];
  if (b && WIN11_BUILDS[b]) { const [rel, homePro, ent] = WIN11_BUILDS[b]; return { label: `Windows 11 ${rel}`, date: homePro, entDate: ent }; }
  if (b && +b < 22000) return { label: 'Windows 10 (22H2)', date: '2025-10-14' };
  return null;
}

// MITRE ATT&CK Enterprise v20.0 (checked against MITRE's STIX bundle enterprise-attack-20.0.json). v20.0 keeps the v19.2 tactics:
// Defense Evasion is split into Stealth (TA0005) and Defense Impairment (TA0112); T1562 was revoked in favour of T1685/T1686.
// Only techniques Liongard data can actually speak to are listed here. Every ID, name and tactic is tested against the fixture.
const ATTACK_VERSION = '20.0';
const ATTACK_TOTAL = 706;   // live (not revoked or deprecated) Enterprise techniques and sub-techniques in v20.0
const TACTICS = [['reconnaissance', 'Reconnaissance', 'TA0043'], ['resource-development', 'Resource Development', 'TA0042'], ['initial-access', 'Initial Access', 'TA0001'], ['execution', 'Execution', 'TA0002'], ['persistence', 'Persistence', 'TA0003'], ['privilege-escalation', 'Privilege Escalation', 'TA0004'], ['stealth', 'Stealth', 'TA0005'], ['defense-impairment', 'Defense Impairment', 'TA0112'], ['credential-access', 'Credential Access', 'TA0006'], ['discovery', 'Discovery', 'TA0007'], ['lateral-movement', 'Lateral Movement', 'TA0008'], ['collection', 'Collection', 'TA0009'], ['command-and-control', 'Command and Control', 'TA0011'], ['exfiltration', 'Exfiltration', 'TA0010'], ['impact', 'Impact', 'TA0040']];
const TECH = {
  'T1589.001': ['Gather Victim Identity Information: Credentials', ['reconnaissance']],
  'T1584.001': ['Compromise Infrastructure: Domains', ['resource-development']],
  'T1566': ['Phishing', ['initial-access']],
  'T1133': ['External Remote Services', ['persistence', 'initial-access']],
  'T1190': ['Exploit Public-Facing Application', ['initial-access']],
  'T1189': ['Drive-by Compromise', ['initial-access']],
  'T1199': ['Trusted Relationship', ['initial-access']],
  'T1200': ['Hardware Additions', ['initial-access']],
  'T1669': ['Wi-Fi Networks', ['initial-access']],
  'T1078.001': ['Valid Accounts: Default Accounts', ['stealth', 'persistence', 'privilege-escalation', 'initial-access']],
  'T1078.002': ['Valid Accounts: Domain Accounts', ['stealth', 'persistence', 'privilege-escalation', 'initial-access']],
  'T1078.003': ['Valid Accounts: Local Accounts', ['stealth', 'persistence', 'privilege-escalation', 'initial-access']],
  'T1078.004': ['Valid Accounts: Cloud Accounts', ['stealth', 'persistence', 'privilege-escalation', 'initial-access']],
  'T1203': ['Exploitation for Client Execution', ['execution']],
  'T1204': ['User Execution', ['execution']],
  'T1072': ['Software Deployment Tools', ['execution', 'lateral-movement']],
  'T1098': ['Account Manipulation', ['persistence', 'privilege-escalation']],
  'T1098.001': ['Account Manipulation: Additional Cloud Credentials', ['persistence', 'privilege-escalation']],
  'T1098.003': ['Account Manipulation: Additional Cloud Roles', ['persistence', 'privilege-escalation']],
  'T1136.001': ['Create Account: Local Account', ['persistence']],
  'T1136.002': ['Create Account: Domain Account', ['persistence']],
  'T1136.003': ['Create Account: Cloud Account', ['persistence']],
  'T1068': ['Exploitation for Privilege Escalation', ['privilege-escalation']],
  'T1036': ['Masquerading', ['stealth']],
  'T1564.008': ['Hide Artifacts: Email Hiding Rules', ['stealth']],
  'T1684.002': ['Social Engineering: Email Spoofing', ['stealth']],
  'T1556.006': ['Modify Authentication Process: Multi-Factor Authentication', ['defense-impairment', 'persistence', 'credential-access']],
  'T1556.009': ['Modify Authentication Process: Conditional Access Policies', ['defense-impairment', 'persistence', 'credential-access']],
  'T1484.001': ['Domain or Tenant Policy Modification: Group Policy Modification', ['defense-impairment', 'privilege-escalation']],
  'T1685': ['Disable or Modify Tools', ['defense-impairment']],
  'T1686': ['Disable or Modify System Firewall', ['defense-impairment']],   // change detection only (macOS / Linux host firewalls)
  'T1686.002': ['Disable or Modify System Firewall: Network Device Firewall', ['defense-impairment']],
  'T1686.003': ['Disable or Modify System Firewall: Windows Host Firewall', ['defense-impairment']],
  'T1601': ['Modify System Image', ['defense-impairment']],
  'T1689': ['Downgrade Attack', ['defense-impairment']],
  'T1110': ['Brute Force', ['credential-access']],
  'T1110.004': ['Brute Force: Credential Stuffing', ['credential-access']],
  'T1021.001': ['Remote Services: Remote Desktop Protocol', ['lateral-movement']],
  'T1021.004': ['Remote Services: SSH', ['lateral-movement']],
  'T1021.005': ['Remote Services: VNC', ['lateral-movement']],
  'T1210': ['Exploitation of Remote Services', ['lateral-movement']],
  'T1091': ['Replication Through Removable Media', ['lateral-movement', 'initial-access']],
  'T1114.003': ['Email Collection: Email Forwarding Rule', ['collection']],
  'T1052.001': ['Exfiltration Over Physical Medium: Exfiltration over USB', ['exfiltration']],
  'T1490': ['Inhibit System Recovery', ['impact']],
  'T1486': ['Data Encrypted for Impact', ['impact']],
  'T1485': ['Data Destruction', ['impact']],
};
// Mitigation names as MITRE publishes them. Each technique's mitigations in panels/cyber.js are ones STIX links to it ("mitigates").
const MITIGATIONS = { M1056: 'Pre-compromise', M1054: 'Software Configuration', M1017: 'User Training', M1032: 'Multi-factor Authentication', M1035: 'Limit Access to Resource Over Network', M1026: 'Privileged Account Management', M1027: 'Password Policies', M1036: 'Account Use Policies', M1047: 'Audit', M1018: 'User Account Management', M1051: 'Update Software', M1046: 'Boot Integrity', M1045: 'Code Signing', M1053: 'Data Backup',
  M1016: 'Vulnerability Scanning', M1021: 'Restrict Web-Based Content', M1030: 'Network Segmentation', M1034: 'Limit Hardware Installation', M1038: 'Execution Prevention', M1040: 'Behavior Prevention on Endpoint', M1041: 'Encrypt Sensitive Information', M1042: 'Disable or Remove Feature or Program', M1050: 'Exploit Protection', M1057: 'Data Loss Prevention' };

module.exports = { TOOL_CATEGORIES, DISCOVERY_SOURCES, categoryOf, osSupport, TACTICS, TECH, MITIGATIONS, ATTACK_VERSION, ATTACK_TOTAL };
