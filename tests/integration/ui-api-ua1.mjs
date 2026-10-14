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
async function call(label, name, method, route, input, status = 200, code, headers = {}, cache = method !== 'GET') {
  const who = actor(name);
  const body = typeof input === 'string' ? input : input === undefined ? undefined : JSON.stringify(input);
  const attempt = { method, route, body };
  if (method !== 'GET' && state.attempts[label]) assert(JSON.stringify(attempt) === JSON.stringify(state.attempts[label]), 'Retained payload changed');
  state.attempts[label] = attempt; save();
  if (cache && state.completed[label]) { state.rows.push({label, method, path:route.split('?')[0], retained:true}); save(); return state.completed[label]; }
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
  state.authPending ??= {};
  if(!state.authPending[name]) {
    state.authPending[name]=randomUUID();
    state.actors[name]={cookies:{},csrf:''};save();
  }
  const label=name+'-auth-'+state.authPending[name];
  if(!state.completed[label+'-csrf']) await call(label+'-csrf',name,'GET','/api/v2/csrf',undefined,200,undefined,{},true);
  const result=await call(label+'-login',name,'POST','/api/v2/session',command(label+'-login',{login,password,rememberMe:false}),200,undefined,{},false);
  delete state.authPending[name];save();return result;
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
async function challengeCode(email, challengeID) {
  for(let n=0;n<60;n++) {
    const list=JSON.parse((await exchange(new URL('/api/v1/messages',args.mailpit))).text);
    for(const item of list.messages) {
      if(!item.To?.some(to=>to.Address===email)||!item.MessageID?.includes('registration.'+challengeID+'.'))continue;
      const mail=JSON.parse((await exchange(new URL('/api/v1/message/'+item.ID,args.mailpit))).text);
      const match=mail.Text?.match(/\b([0-9]{3})\s+([0-9]{3})\b/);
      if(match)return match[1]+match[2];
    }
    await delay(500);
  }
  throw Error('Synthetic OTP missing; retain command');
}
function retainedInput(label,input={}) {
  return state.attempts[label]?.body ? JSON.parse(state.attempts[label].body) : command(label,input);
}
const observed = {};
function evidence(id, checks) {
  observed[id] = {status:'partial', checks, observationCount: state.rows.length};
  writeFileSync(path.join(directory, 'ua1-observations.json'), JSON.stringify({profile:'UA1', coverage:'Configured public HTTP origin and synthetic SMTP; launcher source/image/topology identities required; additional fault/time/source qualifications pending', observed}, null, 2)+'\n', {mode:0o600});
}
async function linkMessage(email, invitationID, jobID) {
  for(let n=0;n<60;n++) {
    const listing=JSON.parse((await exchange(new URL('/api/v1/messages',args.mailpit))).text);
    for(const item of listing.messages) {
      if(!item.To?.some(to=>to.Address===email)||!item.MessageID?.includes('invitation.'+jobID))continue;
      const message=JSON.parse((await exchange(new URL('/api/v1/message/'+item.ID,args.mailpit))).text);
      if(message.Text?.includes('/invite/'+invitationID))return message;
    }
    await delay(500);
  }
  throw Error('Synthetic invitation mail was not received');
}
try {
  if(['roles','cursor-capacity','contact-snapshot'].includes(args.phase)) {
    state.oneShotStarts ??= {};
    assert(!state.oneShotStarts[args.phase], 'One-shot phase already started; retain its commands/evidence and use a separate qualification state');
    state.oneShotStarts[args.phase]=true;save();
  }
  if(args.phase==='contact-snapshot') {
    const admin=await login('admin',credentials.login,credentials.password);
    const member=await login('member',state.roleEmail,state.password);
    const org=state.completed['ua1-org'].orgID;
    const route='/api/v2/orgs/'+org+'/members?limit=1';
    const first=await call('ua1-contact-first-'+id('contact-run'),'admin','GET',route);
    const next=route+'&cursor='+encodeURIComponent(first.nextCursor);
    const before=await call('ua1-contact-before-'+id('contact-run'),'admin','GET',next);
    assert.equal(before.items.length,1);
    const target=before.items[0].membership.userID;
    assert(target===member.user.userID || target===admin.user.userID);
    const selected=target===member.user.userID?'member':'admin';
    const newName='UA1 contact '+randomUUID().slice(0,8);
    assert.notEqual(before.items[0].displayName,newName);
    const changed=await call('ua1-contact-rename-'+id(newName),selected,'PATCH','/api/v2/me/display-name',command('ua1-contact-rename-'+id(newName),{displayName:newName}));
    assert.equal(changed.userID,target);
    assert.equal(changed.displayName,newName);
    const after=await call('ua1-contact-after-'+id('contact-run'),'admin','GET',next);
    assert.deepEqual(after,before);
    const fresh=await call('ua1-contact-fresh-'+id('contact-run'),'admin','GET','/api/v2/orgs/'+org+'/members');
    assert.equal(fresh.items.find(item=>item.membership.userID===target).displayName,newName);
    evidence('UA1-R06',['exact changed user bound to continuation row','captured row/context unchanged','fresh list shows new name']);
    writeFileSync(path.join(directory,'ua1-contact-report.json'),JSON.stringify({profile:'UA1',result:'observations_completed',observed},null,2)+'\n',{mode:0o600});
  } else if(args.phase==='roles') {
    await login('admin',credentials.login,credentials.password);
    const accepted=state.completed['ua1-org'];assert(accepted);
    const org=accepted.orgID, restaurant=accepted.restaurantIDs[0];
    state.roleEmail ??= 'role-'+id('role-email')+'@example.invalid';save();
    const invitation=await call('ua1-role-invite','admin','POST','/api/v2/orgs/'+org+'/invitations',retainedInput('ua1-role-invite',{email:state.roleEmail,assignments:[{restaurantID:restaurant,roles:['Warehouse','Waiter']}]}),201);
    if(!state.completed['ua1-role-complete']) {
      await call('ua1-role-csrf','member','GET','/api/v2/csrf');
      const challenge=await call('ua1-role-begin','member','POST','/api/v2/invitations/'+invitation.invitationID+'/challenges',retainedInput('ua1-role-begin',{invitationID:invitation.invitationID}));
      await call('ua1-role-no-proof','member','POST','/api/v2/challenges/'+challenge.challengeID+'/complete',retainedInput('ua1-role-no-proof',{challengeID:challenge.challengeID,proof:'unverified-proof',password:state.password,displayName:'UA1 member'}),404,'NotFound');
      const code=await challengeCode(state.roleEmail,challenge.challengeID);
      const verified=await call('ua1-role-verify','member','POST','/api/v2/challenges/'+challenge.challengeID+'/verify',retainedInput('ua1-role-verify',{challengeID:challenge.challengeID,code}));
      await call('ua1-role-complete','member','POST','/api/v2/challenges/'+challenge.challengeID+'/complete',retainedInput('ua1-role-complete',{challengeID:challenge.challengeID,proof:verified.proof,password:state.password,displayName:'UA1 member'}));
      evidence('UA1-M08',['invitation ID and unverified proof cannot complete enrollment','real email-bound OTP/proof required']);
    }
    await login('member',state.roleEmail,state.password);
    const access=await call('ua1-role-access','member','GET','/api/v2/access');
    const membership=access.memberships.find(m=>m.orgID===org);assert(membership);
    const route='/api/v2/r/'+restaurant+'/warehouse/products/'+encodeURIComponent('UA1 '+id('product')+' # %2F')+'/batches';
    if(!state.completed['ua1-role-waiter']) {
      assert(membership.assignments[0].roles.includes('Warehouse')&&membership.assignments[0].roles.includes('Waiter'));
      await call('ua1-role-batches','member','GET',route);
    }
    await call('ua1-role-contact-denied','member','GET','/api/v2/orgs/'+org+'/members',undefined,403,'Forbidden');
    await call('ua1-role-invitations-denied','member','GET','/api/v2/orgs/'+org+'/invitations',undefined,403,'Forbidden');
    const contacts=await call('ua1-role-contacts','admin','GET','/api/v2/orgs/'+org+'/members');
    const person=contacts.items.find(row=>row.membership.userID===state.completed['ua1-role-complete'].user.userID);
    assert.equal(person.email,state.roleEmail);
    assert.equal(person.membership.orgID,org);
    evidence('UA1-R01',['real verified User contact join','legacy null retained','own-org assignments only']);
    const first=await call('ua1-role-capture','admin','GET','/api/v2/orgs/'+org+'/members?limit=1');
    const before=await call('ua1-role-capture-before','admin','GET','/api/v2/orgs/'+org+'/members?limit=1&cursor='+encodeURIComponent(first.nextCursor));
    const name=state.completed['ua1-role-name'] ? 'UA1 member second name' : 'UA1 member renamed';
    await call('ua1-role-name-'+id(name),'member','PATCH','/api/v2/me/display-name',command('ua1-role-name-'+id(name),{displayName:name}));
    const after=await call('ua1-role-capture-after','admin','GET','/api/v2/orgs/'+org+'/members?limit=1&cursor='+encodeURIComponent(first.nextCursor));
    assert.deepEqual(before,after);
    if(before.items.some(item=>item.membership.userID===person.membership.userID)) evidence('UA1-R06',['changed contact lies on the captured continuation','real profile mutation preserves captured names/order/versions/context']);
    const waiter=await call('ua1-role-waiter','admin','PUT','/api/v2/orgs/'+org+'/memberships/'+membership.membershipID,retainedInput('ua1-role-waiter',{expectedMembershipVersion:membership.membershipVersion,orgRoles:[],assignments:[{restaurantID:restaurant,roles:['Waiter']}]}));
    assert(waiter.assignments[0].roles.includes('Waiter')&&!waiter.assignments[0].roles.includes('Warehouse'));
    await call('ua1-role-stock-denied','member','GET',route,undefined,403,'Forbidden');
    evidence('UA1-B08',['combined Warehouse/Waiter grant reads stock','fresh Waiter-only grant denies stock after real membership update']);
    evidence('UA1-R02',['real joined combined roles and exact version','updated role union reflected by current authorization']);
    evidence('UA1-R05',['employee denied Admin contacts/invitations']);
    writeFileSync(path.join(directory,'ua1-roles-report.json'),JSON.stringify({profile:'UA1',result:'observations_completed',observed,coverage:'Role/contact/profile subset; cross-org Admin and cached Admin/session revocation remain pending'},null,2)+'\n',{mode:0o600});
  } else if(args.phase==='cursor-capacity') {
    await login('admin',credentials.login,credentials.password);
    const accepted=state.completed['ua1-org'];
    assert(accepted,'Run the initial phase first');
    const product='UA1 '+id('product')+' # %2F';
    const route='/api/v2/r/'+accepted.restaurantIDs[0]+'/warehouse/products/'+encodeURIComponent(product)+'/batches?limit=1';
    const captures=[];
    for(let n=0;n<128;n++) {
      const page=await call('ua1-capacity-'+n,'admin','GET',route,undefined,[200,503]);
      if(page.code) {
        assert.equal(page.code,'LimitExceeded');
        assert(captures.length>0 && captures.length<=128);
        break;
      }
      assert.equal(page.result.items.length,1);
      assert(page.result.nextCursor);captures.push(page.result.nextCursor);
    }
    await call('ua1-capacity-exhausted','admin','GET',route,undefined,503,'LimitExceeded');
    const first=await call('ua1-capacity-retained','admin','GET',route+'&cursor='+encodeURIComponent(captures[0]));
    assert.equal(first.result.items.length,1);
    assert.equal(first.result.nextCursor,undefined);
    evidence('UA1-P02',['real Warehouse active snapshot ceiling reached without truncation','existing retained capture remains readable','end omits cursor']);
    writeFileSync(path.join(directory,'ua1-capacity-report.json'),JSON.stringify({profile:'UA1',result:'observations_completed',captures:captures.length,observed,coverage:'Warehouse capacity subset; Auth/bytes/rows and exact expiry remain separate evidence'},null,2)+'\n',{mode:0o600});
  } else {
  await login('admin',credentials.login,credentials.password);
  const accepted=await call('ua1-org','admin','POST','/api/v2/orgs',command('ua1-org',{name:'UA1 qualification',timeZone:'Europe/Moscow',firstRestaurantName:'UA1 first'}),201);
  await ready('ua1-ready',accepted.orgID,accepted);
  const org=accepted.orgID, restaurant=accepted.restaurantIDs[0];
  const prefix='/api/v2/r/'+restaurant+'/warehouse';
  const contacts=await call('ua1-contacts','admin','GET','/api/v2/orgs/'+org+'/members');
  assert.equal(contacts.context.orgID,org);
  assert.equal(contacts.items.length,1);
  assert.equal(contacts.items[0].email,null);
  assert(contacts.items[0].displayName);
  evidence('UA1-R01',['real bootstrap User join','nullable legacy email','own organization context','no internal credential fields']);
  const products=await call('ua1-products','admin','GET',prefix+'/products');
  const epoch=products.context.runtimeEpoch;
  state.runtimeEpochs ??= {};
  if(state.runtimeEpochs[restaurant]) assert.equal(epoch,state.runtimeEpochs[restaurant],'Runtime changed; retain commands and start a separate reset qualification phase');
  state.runtimeEpochs[restaurant]=epoch;save();
  const headers={'X-Umir-Runtime-Epoch':epoch};
  const product='UA1 '+id('product')+' # %2F';
  await call('ua1-product-register','admin','POST',prefix+'/products',command('ua1-product-register',{productID:product,name:'UA1 milk',baseUnit:'ml'}),200,undefined,headers);
  const batchPath=prefix+'/products/'+encodeURIComponent(product)+'/batches';
  if(!state.completed['ua1-delivery']) {
    const empty=await call('ua1-batches-empty','admin','GET',batchPath);
    assert.deepEqual(empty.result.items,[]);
    state.facts ??= {};state.facts.emptyProductObserved=true;save();
  } else {
    assert(state.facts?.emptyProductObserved || state.facts?.stock,'Missing retained initial empty-product observation');
    state.rows.push({label:'ua1-batches-empty',method:'GET',retained:true});save();
  }
  await call('ua1-batches-missing','admin','GET',prefix+'/products/missing-'+id('missing')+'/batches',undefined,404,'NotFound');
  evidence('UA1-B03',['existing product returns empty200','authorized missing product404']);
  const base=state.completed['ua1-time'] ?? {instant:new Date().toISOString()};
  state.completed['ua1-time']=base;save();
  const line=(days)=>({productID:product,quantity:'1500',manufacturedAt:{instant:new Date(Date.parse(base.instant)-days*86400000).toISOString()},receivedAt:base,shelfLife:{value:'1',unit:'day'}});
  await call('ua1-delivery','admin','POST',prefix+'/deliveries',command('ua1-delivery',{deliveryID:id('delivery'),number:'UA1',createdAt:base,expectedSettingsVersion:products.context.settings.settingsVersion,lines:[line(2),line(0),line(0)]}),200,undefined,headers);
  state.facts ??= {};
  const retainedStock=!!state.facts.stock;
  const all=state.facts.stock?.all ?? await call('ua1-batches-all','admin','GET',batchPath);
  assert.equal(all.context.runtimeEpoch,epoch);
  if(retainedStock){state.rows.push({label:'ua1-stock-capture',retained:true,method:'GET'});save();}
  assert.equal(all.result.productID,product);
  assert.equal(all.result.items.length,3);
  assert(all.result.items.every(row=>row.batch.productID===product&&BigInt(row.batch.remainingQuantity)>0n&&row.baseUnit==='ml'));
  assert.equal(all.result.items[0].status,'pending_writeoff');
  assert(all.result.items.slice(1).every(row=>row.status==='available'));
  assert.equal(all.result.page.stateVersion,all.context.stateVersion);
  assert.equal(all.result.page.prefixSequence,all.context.stateVersion);
  evidence('UA1-B01',['available and pending_writeoff positive rows','complete units/string quantities','product and capture binding']);
  const captured=state.facts.stock?.captured ?? [];let cursor;
  if(!retainedStock) do {
    const page=await call('ua1-fefo-page-'+captured.length,'admin','GET',batchPath+'?limit=1'+(cursor?'&cursor='+encodeURIComponent(cursor):''));
    captured.push(...page.result.items);cursor=page.result.nextCursor;
  } while(cursor);
  assert.deepEqual(captured,all.result.items);
  const compare=(a,b)=>Date.parse(a.batch.expiresAt)-Date.parse(b.batch.expiresAt)||Date.parse(a.batch.receivedAt)-Date.parse(b.batch.receivedAt)||Buffer.compare(Buffer.from(a.batch.batchID),Buffer.from(b.batch.batchID));
  assert.deepEqual([...captured].sort(compare),captured);
  evidence('UA1-B02',['real delivery ties','FEFO before limit1 paging','no missing/duplicate rows','end omits cursor']);
  const stable=state.facts.stock?.stable ?? await call('ua1-capture-before-write','admin','GET',batchPath+'?limit=1');
  state.facts.stock ??= {all,captured,stable};save();
  const pending=all.result.items[0].batch.batchID;
  await call('ua1-writeoff','admin','POST',prefix+'/writeoffs',command('ua1-writeoff',{batchID:pending}),200,undefined,headers);
  const continuation=await call('ua1-capture-after-write','admin','GET',batchPath+'?limit=1&cursor='+encodeURIComponent(stable.result.nextCursor),undefined,[200,409]);
  if(continuation.code==='RefreshRequired') { assert.equal(continuation.details?.refreshRequired,true); evidence('UA1-P02',['retained cursor expires explicitly without implicit refresh']); }
  else assert.deepEqual(continuation.context,stable.context);
  const refreshed=await call('ua1-refresh-after-write','admin','GET',batchPath);
  assert.equal(refreshed.result.items.length,2);
  assert(!refreshed.result.items.some(row=>row.batch.batchID===pending));
  evidence('UA1-B04',['first read performs expiry','read preserves positive pending stock','real confirmed writeoff zero row omitted on refresh']);
  if(!continuation.code) evidence('UA1-B06',['capture identity stable after real writeoff mutation','fresh capture returns new state']);
  await call('ua1-cursor-limit-mismatch','admin','GET',batchPath+'?limit=2&cursor='+encodeURIComponent(stable.result.nextCursor),undefined,409,'RefreshRequired');
  evidence('UA1-P01',['limit-bound cursor rejected without implicit refresh']);
  for(const route of [batchPath,'/api/v2/orgs/'+org+'/members','/api/v2/orgs/'+org+'/invitations']) {
    for(const query of ['limit=0','limit=501','limit=01','limit=1&limit=2','cursor=','foreign=1'])await call('ua1-query-'+id(route+query),'admin','GET',route+'?'+query,undefined,400,'InvalidArgument');
    await call('ua1-get-body-'+id(route),'admin','GET',route,{},400,'InvalidArgument');
  }
  evidence('UA1-P03',['three real routes reject unknown/duplicate/invalid limits and empty cursor','GET bodies rejected']);
  const input=command('ua1-create-invitation',{email:state.email,assignments:[{restaurantID:restaurant,roles:['Waiter','Warehouse']}]});
  const invitation=await call('ua1-create-invitation','admin','POST','/api/v2/orgs/'+org+'/invitations',input,201);
  const list=await call('ua1-invitations','admin','GET','/api/v2/orgs/'+org+'/invitations');
  const row=list.items.find(item=>item.invitation.invitationID===invitation.invitationID);
  assert(row?.linkDelivery?.jobID);
  state.facts.linkJobID ??= row.linkDelivery.jobID;save();
  const jobID=state.facts.linkJobID;
  const replay=await call('ua1-create-replay','admin','POST','/api/v2/orgs/'+org+'/invitations',input,201,undefined,{},false);
  assert.deepEqual(replay,invitation);
  const replayList=await call('ua1-create-replay-observation','admin','GET','/api/v2/orgs/'+org+'/invitations');
  assert.equal(replayList.items.filter(item=>item.invitation.invitationID===invitation.invitationID).length,1);
  assert.equal(replayList.items.find(item=>item.invitation.invitationID===invitation.invitationID).linkDelivery.jobID,state.completed['ua1-resend-link']?.mailJobs[0].jobID ?? jobID);
  await call('ua1-create-conflict','admin','POST','/api/v2/orgs/'+org+'/invitations',{...input,email:'other-'+id('other-email')+'@example.invalid'},409,'CommandConflict');
  const mail=await linkMessage(state.email,invitation.invitationID,jobID);
  assert(mail.MessageID?.includes(jobID));
  assert(mail.Text.includes(origin+'/invite/'+invitation.invitationID));
  assert(!mail.Text.includes('proof='));
  evidence('UA1-M01',['201 Invitation shape','safe link job observation','real SMTP link matching durable job']);
  evidence('UA1-M03',['exact retained create returns same invitation','changed payload409','unchanged original link job observed in one invitation row']);
  evidence('UA1-M07',['configured public origin appears in actual SMTP link']);
  evidence('UA1-M09',['synthetic SMTP confirmed link delivery']);
  evidence('UA1-M14',['real SMTP plain-text URL and Message-ID/job correlation','synthetic recipient','text contains no proof= parameter']);
  const resendPath='/api/v2/orgs/'+org+'/invitations/'+invitation.invitationID+'/resend-link';
  await call('ua1-resend-origin','admin','POST',resendPath,command('ua1-resend-origin'),403,'InvalidOrigin',{Origin:'https://hostile.invalid'});
  const deniedOrigin=await call('ua1-denied-origin-observation','admin','GET','/api/v2/orgs/'+org+'/invitations');
  const beforeDenied=row.invitation;
  const afterOrigin=deniedOrigin.items.find(item=>item.invitation.invitationID===invitation.invitationID);
  assert.deepEqual(afterOrigin.invitation,beforeDenied);
  assert.equal(afterOrigin.linkDelivery.jobID,row.linkDelivery.jobID);
  await call('ua1-resend-csrf','admin','POST',resendPath,command('ua1-resend-csrf'),403,'InvalidCsrfToken',{'X-CSRF-Token':'invalid'});
  const deniedCSRF=await call('ua1-denied-csrf-observation','admin','GET','/api/v2/orgs/'+org+'/invitations');
  const afterCSRF=deniedCSRF.items.find(item=>item.invitation.invitationID===invitation.invitationID);
  assert.deepEqual(afterCSRF.invitation,beforeDenied);
  assert.equal(afterCSRF.linkDelivery.jobID,row.linkDelivery.jobID);
  await call('ua1-resend-cooldown','admin','POST',resendPath,command('ua1-resend-cooldown'),429,'RateLimited');
  await waitUntil(invitation.resendAvailableAt);
  const receipt=await call('ua1-resend-link','admin','POST',resendPath,command('ua1-resend-link'));
  assert.equal(receipt.resourceID,invitation.invitationID);
  assert.equal(receipt.mailJobs.length,1);
  assert.notEqual(receipt.mailJobs[0].jobID,jobID);
  const repeat=await call('ua1-resend-link-replay','admin','POST',resendPath,command('ua1-resend-link'));
  assert.deepEqual(repeat,receipt);
  const later=await call('ua1-invitations-after-resend','admin','GET','/api/v2/orgs/'+org+'/invitations');
  const latest=later.items.find(item=>item.invitation.invitationID===invitation.invitationID);
  assert.equal(latest.invitation.expiresAt,invitation.expiresAt);
  assert(BigInt(latest.invitation.version)>BigInt(invitation.version));
  assert(Date.parse(latest.invitation.resendAvailableAt)>Date.parse(invitation.resendAvailableAt));
  assert.equal(latest.linkDelivery.jobID,receipt.mailJobs[0].jobID);
  evidence('UA1-R03',['real invitation list','latest accepted link job distinct from original','no OTP job selected']);
  evidence('UA1-M04',['resend before challenge','one stable receipt job','version/cooldown advances','deadline unchanged']);
  evidence('UA1-M05',['fresh create cooldown429','same resend replay accepted inside cooldown']);
  evidence('UA1-M13',['invalid Origin/CSRF403 at configured public boundary','invitation body and latest jobID unchanged after each rejection']);
  await call('ua1-cancel','admin','DELETE','/api/v2/orgs/'+org+'/invitations/'+invitation.invitationID,command('ua1-cancel'));
  await call('ua1-resend-cancelled','admin','POST',resendPath,command('ua1-resend-cancelled'),404,'NotFound');
  writeFileSync(path.join(directory,'ua1-runtime-report.json'),JSON.stringify({profile:'UA1',result:'observations_completed',coverage:'Recorded checks only; row statuses partial; not all34 acceptance rows, browser, original all67 or J1/E/J2',requests:state.rows,observed},null,2)+'\n',{mode:0o600});
  process.stdout.write('UA1 real-service observations completed\n');
  }
} catch(error) {
  save();process.stderr.write(error.message+'\n');process.exitCode=1;
}
