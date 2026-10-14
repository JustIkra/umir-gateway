import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync, statSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const args = Object.fromEntries(process.argv.slice(2).reduce((out, value, i, all) => {
  if (i % 2 === 0) out.push([value.replace(/^--/, ''), all[i + 1]]);
  return out;
}, []));
for (const name of ['origin', 'mailpit', 'credentials', 'state-dir']) {
  if (!args[name]) throw new Error(`Missing --${name}`);
}
const origin = new URL(args.origin).origin;
const credentials = JSON.parse(readFileSync(args.credentials, 'utf8'));
if (statSync(args.credentials).mode & 0o077) throw new Error('Credentials file must be private');
const directory = path.resolve(args['state-dir']);
mkdirSync(directory, { recursive: true, mode: 0o700 });
if (statSync(directory).mode & 0o077) throw new Error('State directory must be private');
const statePath = path.join(directory, 'state.json');
const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {
  origin, ids: {}, actors: {}, completed: {}, attempts: {}, rows: [],
  email: `facade-${randomUUID()}@example.invalid`, password: randomBytes(12).toString('hex'),
};
assert.equal(state.origin, origin, 'Retained attempts belong to another origin');

function save() {
  const temporary = `${statePath}.writing`;
  writeFileSync(temporary, JSON.stringify(state), { mode: 0o600, flag: 'w' });
  renameSync(temporary, statePath);
}
function id(label) {
  if (!state.ids[label]) { state.ids[label] = randomUUID(); save(); }
  return state.ids[label];
}
function actor(name) { return state.actors[name] ??= { cookies: {}, csrf: '' }; }
function noInternalTokens(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assert(!['sessionToken', 'preauthToken', 'token', 'serviceKey', 'verifier', 'encryptedResponse'].includes(key), 'Internal credential in public response');
    noInternalTokens(child);
  }
}
function exchange(url, method = 'GET', headers = {}, body) {
  return new Promise((resolve, reject) => {
    const request = (url.protocol === 'https:' ? https : http).request(url, {
      method, headers: { ...headers, ...(body === undefined ? {} : { 'Content-Length': Buffer.byteLength(body) }) }, timeout: 8000,
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 8 << 20) response.destroy();
        else chunks.push(chunk);
      });
      response.on('error', () => reject(new Error('Response interrupted; retain attempt')));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', () => reject(new Error('Transport failed; retain attempt')));
    request.on('timeout', () => request.destroy());
    request.end(body);
  });
}
async function call(label, name, method, route, input, status = 200, code, headers = {}, cache = true) {
  if (cache && state.completed[label]) return state.completed[label];
  const who = actor(name);
  const body = typeof input === 'string' ? input : input === undefined ? undefined : JSON.stringify(input);
  const attempt = { method, route, body };
  if (state.attempts[label]) assert(JSON.stringify(attempt) === JSON.stringify(state.attempts[label]), 'Retained payload changed');
  else { state.attempts[label] = attempt; save(); }
  const result = await exchange(new URL(route, origin), method, {
    Cookie: Object.entries(who.cookies).map(([key, value]) => `${key}=${value}`).join('; '),
    Origin: origin, 'Content-Type': 'application/json', 'X-CSRF-Token': who.csrf, ...headers,
  }, body);
  let value;
  try { value = result.text ? JSON.parse(result.text) : null; }
  catch { throw new Error(`${label}: expected JSON, got HTTP ${result.status}`); }
  noInternalTokens(value);
  assert((Array.isArray(status) ? status : [status]).includes(result.status), `${label}: HTTP ${result.status}, code ${value?.code ?? 'none'}`);
  if (code) assert.equal(value?.code, code, `${label}: wrong error code`);
  for (const cookie of result.headers['set-cookie'] ?? []) {
    const [pair] = cookie.split(';');
    const [key, ...parts] = pair.split('=');
    const value = parts.join('=');
    assert(cookie.includes('HttpOnly') && cookie.includes('SameSite=Strict') && cookie.includes('Path=/'), `${label}: unsafe cookie`);
    if (origin.startsWith('https:')) assert(cookie.includes('Secure'), `${label}: insecure cookie`);
    if (value) who.cookies[key] = value;
    else delete who.cookies[key];
  }
  if (value?.csrfToken) who.csrf = value.csrfToken;
  if (value?.session?.csrfToken) who.csrf = value.session.csrfToken;
  state.rows.push({ label, method, path: route.split('?')[0], status: result.status, code: value?.code, pass: true });
  if (cache) state.completed[label] = value ?? { noContent: true };
  save();
  process.stdout.write(`${label}: ${result.status}${code ? ` ${code}` : ''}\n`);
  return value;
}
const command = (label, input = {}) => ({ commandID: id(label), ...input });
async function login(name, login, password) {
  await call(`${name}-csrf`, name, 'GET', '/api/v2/csrf');
  return call(`${name}-login`, name, 'POST', '/api/v2/session', command(`${name}-login`, { login, password, rememberMe: false }));
}
async function ready(label, org, operation) {
  const route = `/api/v2/orgs/${org}/lifecycle/${operation.operationID}`;
  for (let i = 0; i < 120; i++) {
    const value = await call(`${label}-${i}`, 'admin', 'GET', route, undefined, 200, undefined, {}, false);
    assert.equal(value.operationID, operation.operationID);
    assert.equal(value.orgID, org);
    if (value.lifecycle === 'ready' || value.lifecycle === 'deleted') {
      assert.equal(value.services.length, value.restaurantIDs.length * 3);
      const expected = value.lifecycle === 'deleted' ? 'closed' : 'ready';
      assert(value.services.every((peer) => peer.state === expected && peer.epoch && peer.lifecycleVersion === value.lifecycleVersion), 'Peer readiness mismatch');
      return value;
    }
    await delay(500);
  }
  throw new Error(`${label}: lifecycle did not settle`);
}
async function waitUntil(instant) {
  while (Date.now() <= Date.parse(instant)) await delay(Math.min(1000, Date.parse(instant) - Date.now() + 50));
}
async function otp(email, challengeID) {
  for (let i = 0; i < 60; i++) {
    const listing = await exchange(new URL('/api/v1/messages', args.mailpit));
    assert.equal(listing.status, 200, 'Mailpit unavailable');
    const messages = JSON.parse(listing.text).messages;
    for (const message of messages) {
      if (!message.To?.some((to) => to.Address === email) || !message.MessageID?.includes(`registration.${challengeID}.`)) continue;
      const response = await exchange(new URL(`/api/v1/message/${message.ID}`, args.mailpit));
      const data = JSON.parse(response.text);
      const grouped = data.Text?.match(/\b([0-9]{3})\s+([0-9]{3})\b/);
      const code = grouped ? grouped[1] + grouped[2] : undefined;
      if (code) return code;
    }
    await delay(500);
  }
  throw new Error('Synthetic OTP mail not received');
}
async function verify(label, name, challenge) {
  const code = await otp(state.email, challenge.challengeID);
  return call(label, name, 'POST', `/api/v2/challenges/${challenge.challengeID}/verify`, command(label, { challengeID: challenge.challengeID, code }));
}
async function rateLimitedCall(label, name, route, input) {
  for (let i = 0; i < 60; i++) {
    const result = await call(i === 0 ? label : `${label}-retry-${i}`, name, 'POST', route, input, [200, 429]);
    if (result.code !== 'RateLimited') return result;
    assert.equal(result.outcome, 'not_committed', 'Cannot retry an uncertain rate-limit response');
    await delay(15000);
  }
  throw new Error(`${label}: rate limit did not settle; retain attempt`);
}
function namespace(operationID, orgID = '', restaurantID = '') {
  return Buffer.from(JSON.stringify({ operationID, orgID, restaurantID })).toString('base64url');
}

async function passwordLimit() {
  const firstRow = state.rows.length;
  await login('password-limit-sibling', state.email, `${state.password}B`);
  for (let i = 1; i <= 4; i++) {
    await call(`password-limit-wrong-${i}`, 'reset-password-user', 'PATCH', '/api/v2/me/password', command(`password-limit-wrong-${i}`, { currentPassword: 'incorrect-password', newPassword: `${state.password}C` }), 400, 'CurrentPasswordIncorrect');
  }
  const revoked = await call('password-limit-threshold', 'reset-password-user', 'PATCH', '/api/v2/me/password', command('password-limit-threshold', { currentPassword: 'incorrect-password', newPassword: `${state.password}C` }), 429, 'PasswordChangeRateLimited');
  assert.equal(revoked.sessionRevoked, true, 'Threshold did not report revocation');
  assert(revoked.details?.retryAfterSeconds > 0, 'Threshold delay missing');
  assert(!Object.keys(actor('reset-password-user').cookies).some((name) => name.endsWith('umir_operator_session')), 'Revoked session cookie was retained');
  await call('password-limit-revoked-me', 'reset-password-user', 'GET', '/api/v2/me', undefined, 401, 'Unauthenticated');
  const cooldown = await call('password-limit-sibling-cooldown', 'password-limit-sibling', 'PATCH', '/api/v2/me/password', command('password-limit-sibling-cooldown', { currentPassword: `${state.password}B`, newPassword: `${state.password}C` }), 429, 'PasswordChangeRateLimited');
  assert.equal(cooldown.sessionRevoked, false, 'Cooldown revoked the sibling session');
  await call('password-limit-sibling-me', 'password-limit-sibling', 'GET', '/api/v2/me');
  const rows = state.rows.filter((row) => row.label.startsWith('password-limit-'));
  const freshRequests = state.rows.length - firstRow;
  assert(rows.length >= 10, 'Password cooldown phase evidence missing');
  writeFileSync(path.join(directory, 'password-limit-report.json'), JSON.stringify({ result: 'passed', freshRequests, evidence: freshRequests ? 'Current HTTP observations' : 'Retained observations; no HTTP requests in this invocation', coverage: 'Real Auth password threshold, revocation cookie and sibling cooldown through Nginx/Gateway.', rows }, null, 2) + '\n', { mode: 0o600 });
  process.stdout.write('Password cooldown acceptance passed\n');
}

try {
  if (args.phase === 'password-limit') {
    await passwordLimit();
  } else {
    const admin = await login('admin', credentials.login, credentials.password);
    assert(admin.user?.userID && admin.session?.csrfToken, 'Login view missing');
    await call('admin-me', 'admin', 'GET', '/api/v2/me');
    await call('admin-access', 'admin', 'GET', '/api/v2/access');
    const organization = await call('create-org', 'admin', 'POST', '/api/v2/orgs', command('create-org', { name: 'Facade acceptance', timeZone: 'Europe/Moscow', firstRestaurantName: 'First' }), 201);
    const org = organization.orgID;
    const restaurant = organization.restaurantIDs[0];
    await ready('org-ready', org, organization);
    const profile = await call('organization', 'admin', 'GET', `/api/v2/orgs/${org}`);
    await call('settings', 'admin', 'PATCH', `/api/v2/orgs/${org}/settings`, command('settings', { expectedSettingsVersion: profile.settings.settingsVersion, timeZone: 'Europe/Moscow' }));
    const second = await call('create-restaurant', 'admin', 'POST', `/api/v2/orgs/${org}/restaurants`, command('create-restaurant', { name: 'Second' }), 201);
    await ready('restaurant-ready', org, second);
    const invitation = await call('invite', 'admin', 'POST', `/api/v2/orgs/${org}/invitations`, command('invite', { email: state.email, assignments: [{ restaurantID: restaurant, roles: ['Warehouse', 'Waiter'] }] }), 201);
    await call('invited-csrf', 'invited', 'GET', '/api/v2/csrf');
    const challenge = await call('begin-invitation', 'invited', 'POST', `/api/v2/invitations/${invitation.invitationID}/challenges`, command('begin-invitation', { invitationID: invitation.invitationID }));
    await call('resend-too-soon', 'invited', 'POST', `/api/v2/challenges/${challenge.challengeID}/resend`, command('resend-too-soon'), 429, 'RateLimited');
    const cancelInvite = await call('invite-cancel', 'admin', 'POST', `/api/v2/orgs/${org}/invitations`, command('invite-cancel', { email: `cancel-${id('cancel-email')}@example.invalid`, assignments: [{ restaurantID: restaurant, roles: ['Waiter'] }] }), 201);
    await call('cancel-invitation', 'admin', 'DELETE', `/api/v2/orgs/${org}/invitations/${cancelInvite.invitationID}`, command('cancel-invitation'));
    await waitUntil(challenge.resendAvailableAt);
    const resend = await call('resend-challenge', 'invited', 'POST', `/api/v2/challenges/${challenge.challengeID}/resend`, command('resend-challenge'));
    await waitUntil(resend.resendAvailableAt);
    await call('resend-invitation', 'admin', 'POST', `/api/v2/orgs/${org}/invitations/${invitation.invitationID}/resend`, command('resend-invitation'));
    const proof = await verify('verify-invitation', 'invited', challenge);
    const newUser = await call('complete-invited', 'invited', 'POST', `/api/v2/challenges/${challenge.challengeID}/complete`, command('complete-invited', { challengeID: challenge.challengeID, proof: proof.proof, password: state.password, displayName: 'Facade User' }));
    assert.equal(newUser.user.email, state.email);
    const access = await call('invited-access', 'invited', 'GET', '/api/v2/access');
    const membership = access.memberships.find((m) => m.orgID === org && m.userID === newUser.user.userID);
    assert(membership.assignments.some((a) => a.roles.includes('Waiter') && a.roles.includes('Warehouse')), 'Combined roles lost');
    await call('role-denial', 'invited', 'POST', `/api/v2/orgs/${org}/restaurants`, command('role-denial', { name: 'Forbidden' }), 403, 'Forbidden');
    await call('scope-denial', 'invited', 'GET', `/api/v2/orgs/${id('foreign-org')}`, undefined, 403, 'Forbidden');
    await call('origin-denial', 'admin', 'POST', `/api/v2/orgs/${org}/restaurants`, command('origin-denial', { name: 'Forbidden' }), 403, 'InvalidOrigin', { Origin: 'https://foreign.invalid' });
    await call('csrf-denial', 'admin', 'POST', `/api/v2/orgs/${org}/restaurants`, command('csrf-denial', { name: 'Forbidden' }), 403, 'InvalidCsrfToken', { 'X-CSRF-Token': 'wrong' });
    await call('strict-json', 'admin', 'POST', `/api/v2/orgs/${org}/restaurants`, `{"commandID":"${id('strict-json')}","name":"one","name":"two"}`, 400, 'InvalidArgument');
    await call('wrong-path-body', 'invited', 'POST', `/api/v2/challenges/${challenge.challengeID}/verify`, command('wrong-path-body', { challengeID: id('other-challenge'), code: '000000' }), 400, 'InvalidArgument');
    const changed = await call('membership-update', 'admin', 'PUT', `/api/v2/orgs/${org}/memberships/${membership.membershipID}`, command('membership-update', { expectedMembershipVersion: membership.membershipVersion, orgRoles: [], assignments: [{ restaurantID: restaurant, roles: ['Waiter', 'Warehouse'] }, { restaurantID: second.restaurantIDs[0], roles: ['Waiter'] }] }));
    const assignment = changed.assignments.find((a) => a.restaurantID === second.restaurantIDs[0]);
    await call('assignment-revoke', 'admin', 'DELETE', `/api/v2/orgs/${org}/memberships/${membership.membershipID}/assignments/${assignment.assignmentID}`, command('assignment-revoke', { expectedAssignmentVersion: assignment.assignmentVersion }));
    const updatedAccess = await call('invited-access-after-revoke', 'invited', 'GET', '/api/v2/access');
    const activeMembership = updatedAccess.memberships.find((m) => m.membershipID === membership.membershipID);
    await call('membership-revoke', 'admin', 'DELETE', `/api/v2/orgs/${org}/memberships/${membership.membershipID}`, command('membership-revoke', { expectedMembershipVersion: activeMembership.membershipVersion }));
    const otherOrganization = await call('create-other-org', 'admin', 'POST', '/api/v2/orgs', command('create-other-org', { name: 'Other facade scope', timeZone: 'Europe/Moscow', firstRestaurantName: 'Other' }), 201);
    await ready('other-org-ready', otherOrganization.orgID, otherOrganization);
    const freshInvitation = await call('invite-existing', 'admin', 'POST', `/api/v2/orgs/${otherOrganization.orgID}/invitations`, command('invite-existing', { email: state.email, assignments: [{ restaurantID: otherOrganization.restaurantIDs[0], roles: ['Waiter'] }] }), 201);
    const existingChallenge = await rateLimitedCall('begin-existing', 'invited', `/api/v2/invitations/${freshInvitation.invitationID}/challenges`, command('begin-existing', { invitationID: freshInvitation.invitationID }));
    const existingProof = await verify('verify-existing', 'invited', existingChallenge);
    await call('accept-existing', 'invited', 'POST', `/api/v2/invitations/${freshInvitation.invitationID}/accept`, command('accept-existing', { challengeID: existingChallenge.challengeID, proof: existingProof.proof }));
    const displayName = await call('display-name', 'invited', 'PATCH', '/api/v2/me/display-name', command('display-name', { displayName: 'Updated Facade User' }));
    assert.equal(displayName.displayName, 'Updated Facade User');
    const lookupRoute = `/api/v2/commands?namespace=${namespace('displayName')}&commandID=${encodeURIComponent(id('display-name'))}`;
    const recovered = await call('command-recovery', 'invited', 'GET', lookupRoute);
    assert.equal(recovered.state, 'completed');
    assert.equal(recovered.commandID, id('display-name'));
    assert.equal(recovered.response.body.displayName, 'Updated Facade User');
    await call('payload-conflict', 'invited', 'PATCH', '/api/v2/me/display-name', { commandID: id('display-name'), displayName: 'Different User' }, 409, 'CommandConflict');
    const products = await call('warehouse-products', 'admin', 'GET', `/api/v2/r/${restaurant}/warehouse/products`);
    const inventory = await call('warehouse-inventory', 'admin', 'GET', `/api/v2/r/${restaurant}/warehouse/inventory`);
    assert.equal(products.context.tenantID, restaurant);
    assert.equal(inventory.context.tenantID, restaurant);
    assert(Array.isArray(products.result.items) && Array.isArray(inventory.result.items), 'Warehouse read models missing');
    const currentSettings = await call('settings-current', 'admin', 'GET', `/api/v2/orgs/${org}`);
    await call('settings-live-refresh', 'admin', 'PATCH', `/api/v2/orgs/${org}/settings`, command('settings-live-refresh', { expectedSettingsVersion: currentSettings.settings.settingsVersion, timeZone: 'Europe/Berlin' }));
    await ready('settings-readiness', org, organization);
    const refreshed = await call('warehouse-after-settings', 'admin', 'GET', `/api/v2/r/${restaurant}/warehouse/products`);
    assert.equal(refreshed.context.settings.timeZone, 'Europe/Berlin');
    await call('password-change', 'invited', 'PATCH', '/api/v2/me/password', command('password-change', { currentPassword: state.password, newPassword: `${state.password}A` }), 204);
    await login('password-user', state.email, `${state.password}A`);
    await call('logout-all', 'password-user', 'POST', '/api/v2/sessions/logout-all', command('logout-all'));
    await call('logout-all-denies', 'password-user', 'GET', '/api/v2/me', undefined, 401, 'Unauthenticated');
    await call('email-csrf', 'email', 'GET', '/api/v2/csrf');
    const emailChallenge = await rateLimitedCall('email-login-begin', 'email', '/api/v2/email-challenges', command('email-login-begin', { email: state.email, purpose: 'login' }));
    const emailProof = await verify('email-login-verify', 'email', emailChallenge);
    await call('email-login-complete', 'email', 'POST', `/api/v2/email-challenges/${emailChallenge.challengeID}/complete`, command('email-login-complete', { challengeID: emailChallenge.challengeID, proof: emailProof.proof, purpose: 'login', rememberMe: true }));
    await call('logout', 'email', 'DELETE', '/api/v2/session', undefined, 204);
    await call('reset-csrf', 'reset', 'GET', '/api/v2/csrf');
    const reset = await rateLimitedCall('reset-begin', 'reset', '/api/v2/email-challenges', command('reset-begin', { email: state.email, purpose: 'password_reset' }));
    const resetProof = await verify('reset-verify', 'reset', reset);
    await call('reset-complete', 'reset', 'POST', `/api/v2/email-challenges/${reset.challengeID}/complete`, command('reset-complete', { challengeID: reset.challengeID, proof: resetProof.proof, purpose: 'password_reset', newPassword: `${state.password}B` }));
    await login('reset-password-user', state.email, `${state.password}B`);
    const deletion = await call('delete-restaurant', 'admin', 'DELETE', `/api/v2/orgs/${org}/restaurants/${second.restaurantIDs[0]}`, command('delete-restaurant'), 202);
    await ready('deleted-restaurant', org, deletion);
    const orgDeletion = await call('delete-org', 'admin', 'DELETE', `/api/v2/orgs/${org}`, command('delete-org'), 202);
    await ready('deleted-org', org, orgDeletion);
    await call('global-user-preserved', 'reset-password-user', 'GET', '/api/v2/me');
    const remainingAccess = await call('other-scope-preserved', 'reset-password-user', 'GET', '/api/v2/access');
    assert(remainingAccess.memberships.some((m) => m.orgID === otherOrganization.orgID && m.state === 'active'), 'Other organization access lost');
    const report = { result: 'passed', timeZone: 'Europe/Moscow', coverage: 'Executable Gateway through Nginx, real Auth/Warehouse, local synthetic SMTP. No browser/full J1/E/J2 claim.', rows: state.rows };
    writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    process.stdout.write(`Facade acceptance passed: ${state.rows.length} recorded requests\n`);
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
