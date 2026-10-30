// Function register: every panel as a saved question to Liongard, with the API calls behind it. No API calls of its own.
const LIST = [
  ['overview', 'Overview', 'Which areas of this client need attention right now, and where should I start?', 'Built from the Action plan and Cyber security, with the same data and rules', 'Daily check per client, account reviews, QBR opening slide'],
  ['actions', 'Action plan', 'What should we fix for this client, in what order, who owns it and how long will it take?', 'Built from the other pages with the same data and rules · v1 /tasks (Critical and High alerts)', 'Service desk and vCIO work queue · client remediation plan PDF'],
  ['stack', 'Customer stack', 'What does this client run, what does each tool do for them, and what do Liongard\u2019s metrics say is wrong, expiring or drifting?', 'v1 /launchpoints · v1 /timeline · v2 /metrics/evaluate/systems (any inspector)', 'Onboarding, QBR, account reviews'],
  ['cyber', 'Cyber security', 'Is this client exposed right now, which security-relevant changes landed together, and which attack techniques can Liongard see?', 'v1 /detections · v2 metrics (every inspector) · identity and device inventory · v1 /tasks', 'Threat hunting, incident triage, security reviews · PDF summary for the client'],
  ['coverage', 'Stack coverage', 'Which AV/EDR, RMM and backup products are on each device, which devices miss a required tool, and do the tools agree?', 'v2 device inventory · v2 metrics (device lists from every tool) · Windows agent dataprints · v1 /tasks', 'Onboarding checks, monthly hygiene, per-client coverage policy'],
  ['identity', 'Identity & access', 'Who can administer what across every tool, who lacks MFA where, which leavers still have access, and which accounts are stale?', 'v2 identity inventory · v2 metrics (admin, MFA, disabled and stale lists) · Duo dataprint · device inventory', 'Security review, offboarding checks · user access review PDF for client sign-off'],
  ['email', 'Email & domain security', 'Can each domain be spoofed, is mail filtered, and what exact records fix it?', 'Internet Domain/DNS (EmailSecurity checks, SpoofIntel, MX, registrar lock) · TLS/SSL · v2 metrics (mail tools)', 'Email security upsell, BEC prevention · DNS change request PDF'],
  ['compliance', 'Compliance at a glance', 'What technical-control evidence does Liongard hold for each framework, and where is there none?', 'Built from the other pages with the same data and coverage policy', 'QBR, compliance conversations · evidence pack PDF per framework'],
  ['licences', 'Licence reconciliation', 'What is this client paying for that nobody uses, who is missing a seat, which seats belong to nobody, and what does it cost?', 'M365, KnowBe4, Duo, ThreatLocker, NinjaOne, CrowdStrike, Anthropic, AD dataprints · v2 metrics (other tools)', 'Licence true-up, QBR cost savings · true-up PDF for client approval'],
  ['ai', 'AI usage', 'Who uses Claude and ChatGPT, what does it cost, how old are the keys, and are those accounts protected?', 'Anthropic / OpenAI dataprints · identity inventory · Duo', 'AI governance'],
  ['network', 'Network & firmware', 'Is every firewall, switch and access point healthy, licensed and on consistent firmware, and who can administer them?', 'SonicWall, Barracuda, Meraki dataprints · v2 metrics (every other network vendor) · device inventory', 'Network hygiene, project pipeline'],
  ['lifecycle', 'Lifecycle & renewals', 'What expires or reaches end of support in the next 12 months, across every tool?', 'Device inventory · vendor dataprints · DNS and TLS · v2 metrics (every other inspector)', 'Refresh and renewal pipeline · renewal forecast PDF and calendar (.ics)'],
  ['inspectors', 'Inspector health', 'Which inspectors are failing, stale or not on a schedule?', 'v1 /launchpoints · v1 /timeline', 'Platform hygiene, data trust'],
  ['wallboard', 'Wallboard', 'What’s open and what’s stale right now?', 'v1 /tasks · inspector health · email · v2 metrics', 'Service desk screen (auto-refresh, full screen)'],
  ['changes', 'Change pulse', 'What really changed in the last 90 days, apart from counters and routine churn?', 'v1 /detections', 'QBR, root-cause analysis'],
  ['lookup', 'Lookup', 'Show me everything about one person, device or domain.', 'v2 inventory · the other pages', 'Service desk triage'],
];
// Every page reads the client's other inspectors through v2 /metrics/evaluate/systems, links into Liongard, and exports
// PDF (executive summary and full report), HTML and CSV; several add a client-facing PDF (access review, DNS change request,
// licence true-up, renewal forecast, compliance evidence pack).
async function collect(api, env) { return { environment: env }; }
function compute(input) {
  return { environment: input.environment, pulledOn: input.pulledOn, source: input.source, rows: LIST.map(([id, name, q, calls, use]) => ({ id, name, q, calls, use })) };
}
module.exports = { id: 'register', collect, compute };
