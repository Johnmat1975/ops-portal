// What each Liongard inspector does for a client, so every page can work with any stack.
// Each of the 117 inspectors in Liongard's catalogue (Oct 2026) maps to one or more capabilities.
// An inspector that isn't listed (a new one) falls back to its Liongard category, so it still shows up.

const CAPABILITIES = [
  { id: 'identity', label: 'Identity & access', q: 'Who can sign in, with what rights, and is MFA on?' },
  { id: 'email', label: 'Email & domains', q: 'Are domains, DNS, certificates and mail filtering in order?' },
  { id: 'security', label: 'Endpoint security', q: 'Is every device protected, and are there active threats?' },
  { id: 'management', label: 'Device management & patching', q: 'Are devices managed, checking in and patched?' },
  { id: 'backup', label: 'Backup & recovery', q: 'Are backups running and recent?' },
  { id: 'network', label: 'Firewall & network', q: 'Are firewalls, switches and Wi-Fi current and licensed?' },
  { id: 'monitoring', label: 'Monitoring & discovery', q: 'What is on the network, and is it being watched?' },
  { id: 'servers', label: 'Servers & virtualisation', q: 'Are hosts, VMs, storage and databases healthy?' },
  { id: 'cloud', label: 'Cloud & SaaS', q: 'What cloud platforms and file stores hold client data?' },
  { id: 'awareness', label: 'Training & dark web', q: 'Are users trained, and are their credentials exposed?' },
  { id: 'ai', label: 'AI services', q: 'Who uses AI services, and are they governed?' },
  { id: 'business', label: 'PSA, docs & billing', q: 'Is the client documented, ticketed and billed correctly?' },
  { id: 'voice', label: 'Telephony', q: 'Is the phone system licensed and locked down?' },
  { id: 'other', label: 'Other', q: 'Inspectors that don’t fit a capability yet.' },
];

const I = (caps, role) => ({ caps, role });
const INSPECTORS = {
  // Identity & access
  'Active Directory': I(['identity'], 'Directory'),
  'Microsoft 365': I(['identity', 'email', 'cloud'], 'Productivity suite'),
  'Microsoft 365 Education': I(['identity', 'email', 'cloud'], 'Productivity suite'),
  'Google Workspace': I(['identity', 'email', 'cloud'], 'Productivity suite'),
  'Duo Security': I(['identity'], 'MFA'),
  'JumpCloud': I(['identity', 'management'], 'Directory'),
  'OneLogin': I(['identity'], 'SSO'),
  'CIPP': I(['identity', 'cloud'], 'M365 management'),
  'Admin by Request': I(['security', 'identity'], 'Privilege management'),
  // Email & domains
  'Internet Domain/DNS': I(['email'], 'Domain & DNS'),
  'TLS/SSL': I(['email'], 'Certificates'),
  'GoDaddy': I(['email'], 'Registrar'),
  'Cloudflare': I(['email', 'network'], 'DNS & edge'),
  'Vade': I(['email', 'security'], 'Email security'),
  'Barracuda Email Gateway Defense': I(['email', 'security'], 'Email security'),
  // Endpoint security
  'CrowdStrike EDR': I(['security'], 'EDR'),
  'SentinelOne': I(['security'], 'EDR'),
  'Huntress': I(['security'], 'MDR'),
  'Sophos Central': I(['security'], 'EDR'),
  'Bitdefender GravityZone': I(['security'], 'EDR'),
  'Webroot': I(['security'], 'Antivirus'),
  'ESET Licensing': I(['security'], 'Antivirus'),
  'Sonicwall Capture Client': I(['security'], 'EDR'),
  'WithSecure': I(['security'], 'EDR'),
  'ThreatLocker': I(['security'], 'Application control'),
  'Senteon': I(['security'], 'Hardening'),
  'BitLyft': I(['security'], 'MDR / SIEM'),
  'Arctic Wolf': I(['security'], 'MDR'),
  'Qualys': I(['security'], 'Vulnerability scanning'),
  'Shodan': I(['security', 'monitoring'], 'External exposure'),
  // Device management & patching
  'NinjaOne': I(['management'], 'RMM'),
  'Datto RMM': I(['management'], 'RMM'),
  'ConnectWise Automate': I(['management'], 'RMM'),
  'ConnectWise Asio': I(['management'], 'RMM'),
  'N-able N-central': I(['management'], 'RMM'),
  'N-able RMM': I(['management'], 'RMM'),
  'Kaseya VSA': I(['management'], 'RMM'),
  'Syncro': I(['management', 'business'], 'RMM & PSA'),
  'Continuum RMM': I(['management'], 'RMM'),
  'Addigy': I(['management'], 'Mac MDM'),
  'Addigy (Legacy)': I(['management'], 'Mac MDM'),
  'Iru': I(['management'], 'Apple MDM'),
  'Jamf Pro': I(['management'], 'Apple MDM'),
  'ImmyBot': I(['management'], 'Deployment'),
  'Watchman Monitoring': I(['management', 'monitoring'], 'Device monitoring'),
  'Windows Workstation': I(['management', 'security'], 'Liongard agent'),
  'Windows Server': I(['management', 'security', 'servers'], 'Liongard agent'),
  'macOS': I(['management', 'security'], 'Liongard agent'),
  'Linux': I(['management', 'servers'], 'Liongard agent'),
  'Managed Printer': I(['management'], 'Printers'),
  // Backup & recovery
  'Cove Data Protection': I(['backup'], 'Backup'),
  'Datto BCDR': I(['backup'], 'BCDR'),
  'Veeam SPC': I(['backup'], 'Backup'),
  'Veeam Availability Console': I(['backup'], 'Backup'),
  'Axcient x360Recover': I(['backup'], 'BCDR'),
  'Acronis Cyber Cloud': I(['backup', 'security'], 'Backup & protection'),
  'StorageCraft SPX': I(['backup'], 'Backup'),
  'Slide': I(['backup'], 'BCDR'),
  // Firewall & network
  'SonicWall': I(['network'], 'Firewall'),
  'Fortinet Fortigate': I(['network'], 'Firewall'),
  'Fortinet FortiManager': I(['network'], 'Firewall management'),
  'Watchguard': I(['network'], 'Firewall'),
  'Palo Alto': I(['network'], 'Firewall'),
  'Palo Alto Panorama': I(['network'], 'Firewall management'),
  'PFSense': I(['network'], 'Firewall'),
  'Sophos Firewall': I(['network'], 'Firewall'),
  'Sophos SG': I(['network'], 'Firewall'),
  'Barracuda Firewall': I(['network'], 'Firewall'),
  'Cisco ASA': I(['network'], 'Firewall'),
  'Cisco Meraki': I(['network'], 'Firewall & Wi-Fi'),
  'Cisco IOS': I(['network'], 'Switching & routing'),
  'Cisco Small Business Switch': I(['network'], 'Switching'),
  'HP Procurve': I(['network'], 'Switching'),
  'Junos OS - Juniper Networks': I(['network'], 'Switching & routing'),
  'Datto Networking': I(['network'], 'Switching & Wi-Fi'),
  'EnGenius': I(['network'], 'Switching & Wi-Fi'),
  'Ubiquiti Unifi': I(['network'], 'Switching & Wi-Fi'),
  'UniFi Cloud': I(['network'], 'Switching & Wi-Fi'),
  'Corero SmartWall': I(['network', 'security'], 'DDoS protection'),
  'Cisco Umbrella': I(['network', 'security'], 'DNS filtering'),
  'iboss': I(['network', 'security'], 'Web security'),
  'Network IP': I(['network'], 'Public IP'),
  // Monitoring & discovery
  'Network Discovery': I(['monitoring'], 'Discovery'),
  'Auvik': I(['monitoring', 'network'], 'Network monitoring'),
  'Domotz': I(['monitoring', 'network'], 'Network monitoring'),
  'LogicMonitor': I(['monitoring'], 'Monitoring'),
  // Servers & virtualisation
  'Hyper-V': I(['servers'], 'Hypervisor'),
  'VMware ESXi': I(['servers'], 'Hypervisor'),
  'VMware vCenter': I(['servers'], 'Hypervisor management'),
  'SQL Server': I(['servers'], 'Database'),
  'Synology NAS': I(['servers', 'backup'], 'Storage'),
  // Cloud & SaaS
  'Amazon Web Services': I(['cloud'], 'Cloud platform'),
  'Azure': I(['cloud'], 'Cloud platform'),
  'DigitalOcean': I(['cloud'], 'Cloud platform'),
  'Nerdio Manager for MSP': I(['cloud'], 'Virtual desktops'),
  'Box.com': I(['cloud'], 'File storage'),
  'Dropbox': I(['cloud'], 'File storage'),
  'Google Drive': I(['cloud'], 'File storage'),
  'Egnyte': I(['cloud'], 'File storage'),
  'Slack': I(['cloud'], 'Collaboration'),
  // Training & dark web
  'KnowBe4': I(['awareness'], 'Security training'),
  'Nimblr': I(['awareness'], 'Security training'),
  'Dark Web Monitoring': I(['awareness', 'identity'], 'Dark web monitoring'),
  // AI services
  'Anthropic': I(['ai'], 'AI platform'),
  'OpenAI': I(['ai'], 'AI platform'),
  'GitHub Copilot': I(['ai'], 'AI coding assistant'),
  // PSA, docs & billing
  'HaloPSA': I(['business'], 'PSA'),
  'Autotask': I(['business'], 'PSA'),
  'ConnectWise Manage': I(['business'], 'PSA'),
  'Kaseya BMS': I(['business'], 'PSA'),
  'IT Glue': I(['business'], 'Documentation'),
  'Lexful': I(['business'], 'Documentation'),
  'Pax8': I(['business'], 'Distribution & billing'),
  'ControlMap': I(['business'], 'Compliance management'),
  'Roar': I(['business'], 'Liongard platform'),
  // Telephony
  '3CX': I(['voice'], 'Phone system'),
  '3CX (Legacy)': I(['voice'], 'Phone system'),
};

const FALLBACK = { cloud: 'cloud', network: 'network', endpoint: 'management', appservices: 'other' };

// Capabilities and role for an inspector alias. Unknown inspectors use their Liongard category.
function profileOf(alias, category) {
  const p = INSPECTORS[alias] || Object.entries(INSPECTORS).find(([k]) => k.toLowerCase() === String(alias || '').toLowerCase())?.[1];
  if (p) return { ...p, known: true };
  return { caps: [FALLBACK[String(category || '').toLowerCase()] || 'other'], role: 'Not mapped yet', known: false };
}
const capLabel = id => (CAPABILITIES.find(c => c.id === id) || { label: id }).label;

module.exports = { CAPABILITIES, INSPECTORS, profileOf, capLabel };
