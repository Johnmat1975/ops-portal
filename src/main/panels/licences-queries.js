// JMESPath run against each system's latest dataprint via
// POST /api/v2/dataprints/evaluate/{systemDetailId}.
// Keys are Liongard inspector aliases; systems are found by alias, never by a hard-coded ID,
// because system IDs change when a launchpoint is re-created.
// Each query returns the shape the reconciliation rules in licences.js expect
// (same shape as the test fixtures -> data.*).

module.exports = {
  'Microsoft 365': {
    key: 'm365',
    query: '{lic: Licensing[].{sku: skuPartNumber, name: ProductFriendlyName, enabled: prepaidUnits.enabled, consumed: consumedUnits}, ' +
           'users: Users[].{n: displayName, upn: userPrincipalName, en: accountEnabled, prod: Assigned_Products, ' +
           'last: signInActivity.lastSignInDateTime, lastNI: signInActivity.lastNonInteractiveSignInDateTime}}',
  },
  'KnowBe4': {
    key: 'kb4',
    query: '{acct: AccountInfo.{seats: number_of_seats, level: subscription_level, ends: subscription_end_date}, ' +
           'users: Users[].{e: email, s: status, last: last_sign_in, archived: archived_at}, ' +
           'training: TrainingEnrollments[].{e: user.email, s: status, done: completion_date}}',
  },
  'Duo Security': {
    key: 'duo',
    query: '{info: SystemInfo.{user_count: user_count, admin_count: admin_count}, ' +
           'users: Users[].{u: username, e: email, s: status, enr: is_enrolled, last: last_login}}',
  },
  'ThreatLocker': {
    key: 'threatlocker',
    query: '{billing: billingMethod, computers: computers[].{n: computerName, os: operatingSystem, last: lastCheckin}, ' +
           'mobile: mobileDevices[].{n: name, os: deviceOperatingSystem, s: statusString, last: lastCheckIn}}',
  },
  'NinjaOne': {
    key: 'ninja',
    query: 'Devices[].{n: systemName, last: LastContact_r}',
  },
  'CrowdStrike EDR': {
    key: 'crowdstrike',
    query: 'DevicesDetails[].{n: hostname, last: last_seen}',
  },
  'Anthropic': {
    key: 'anthropic',
    query: '{users: Users[].{id: id, e: email, r: role}, keys: APIKeys[].{by: created_by.id, s: status}}',
  },
  'Active Directory': {
    key: 'ad',
    query: 'Users[].{u: UserName, en: Enabled, last: LastLogonDate}',
  },
};
