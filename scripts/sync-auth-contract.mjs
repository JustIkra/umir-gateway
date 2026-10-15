import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const [publicPath, privatePath, outputPath] = process.argv.slice(2);
if (!publicPath || !privatePath || !outputPath) {
  throw new Error('Usage: node scripts/sync-auth-contract.mjs PUBLIC PRIVATE OUTPUT');
}
const publicBytes = readFileSync(publicPath);
const privateBytes = readFileSync(privatePath);
const publicAPI = JSON.parse(publicBytes);
const privateAPI = JSON.parse(privateBytes);
if (publicAPI.info.version !== '2.0.0-FIN.1' || privateAPI.info.version !== '2.0.0-FIN.1') throw Error('Expected composed FIN1 profiles');
const operations = {};
const schemas = {};
const include = (value) => {
  if (!value || typeof value !== 'object') return;
  if (value.$ref) {
    const name = value.$ref.replace('#/components/schemas/', '');
    if (!privateAPI.components.schemas[name]) throw new Error(`Unknown schema ${name}`);
    if (!(name in schemas)) {
      schemas[name] = privateAPI.components.schemas[name];
      include(schemas[name]);
    }
  }
  for (const child of Object.values(value)) include(child);
};
for (const [privatePath, methods] of Object.entries(privateAPI.paths)) {
  if (!privatePath.startsWith('/internal/auth/v1/public/')) continue;
  const path = privatePath.replace('/internal/auth/v1/public', '/api/v2');
  for (const [method, privateOp] of Object.entries(methods)) {
    const publicOp = publicAPI.paths[path]?.[method];
    if (!publicOp?.operationId) throw new Error(`Missing public operation ${method} ${path}`);
    const status = Object.keys(privateOp.responses).find((s) => /^2\d\d$/.test(s));
    const op = {
      path, method: method.toUpperCase(), status: Number(status),
      parameters: (publicOp.parameters ?? []).map((p) => p.$ref
        ? publicAPI.components.parameters[p.$ref.split('/').pop()] : p),
      request: publicOp.requestBody?.content?.['application/json']?.schema,
      response: privateOp.responses[status]?.content?.['application/json']?.schema,
    };
    const privateRequest = privateOp.requestBody?.content?.['application/json']?.schema;
    if (JSON.stringify(op.request) !== JSON.stringify(privateRequest)) {
      throw new Error(`Different request schemas ${path}`);
    }
    include(op);
    operations[publicOp.operationId] = op;
  }
}
include({ $ref: '#/components/schemas/Error' });
for (const [name, schema] of Object.entries(schemas)) {
  if (publicAPI.components.schemas[name] && JSON.stringify(schema) !== JSON.stringify(publicAPI.components.schemas[name])) {
    throw new Error(`Different public/private schema ${name}`);
  }
}
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
writeFileSync(outputPath, JSON.stringify({
  source: { publicSHA256: hash(publicBytes), privateSHA256: hash(privateBytes) },
  operations, components: { schemas },
}, null, 2) + '\n');
