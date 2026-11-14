// Test bridge: invokes real frontend modules with Node WebCrypto. Outputs public material only.
const { build } = require('../../frontend/node_modules/esbuild');
const { webcrypto } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const built = await build({ stdin: { contents: `export { canonicalizePopPayload } from './frontend/src/crypto/canonicalJson'; export { createProofOfPossession, verifyProofOfPossession } from './frontend/src/crypto/pop'; export { generateRsaPssKeypair } from './frontend/src/crypto/keygen';`, resolveDir: path.resolve(__dirname, '../..') }, bundle: true, write: false, platform: 'node', format: 'cjs' });
  const module = { exports: {} };
  new Function('module', 'exports', built.outputFiles[0].text)(module, module.exports);
  const api = module.exports;
  globalThis.window = { crypto: webcrypto, btoa, atob };
  if (input.action === 'canonical') {
    console.log(JSON.stringify(input.payloads.map(payload => Buffer.from(api.canonicalizePopPayload(payload)).toString('base64'))));
  } else if (input.action === 'sign') {
    const bundle = await api.generateRsaPssKeypair(false);
    const payload = { ...input.payload, fingerprint: bundle.fingerprint };
    const signature = await api.createProofOfPossession(bundle.keyPair.privateKey, payload);
    console.log(JSON.stringify({ payload, signature, public_key_pem: bundle.spkiPem, canonical_b64: Buffer.from(api.canonicalizePopPayload(payload)).toString('base64') }));
  } else if (input.action === 'verify') {
    const publicKey = await webcrypto.subtle.importKey('spki', Buffer.from(input.spki_b64, 'base64'), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
    console.log(JSON.stringify({ valid: await api.verifyProofOfPossession(publicKey, input.payload, input.signature) }));
  } else throw new Error('Unknown test action');
})().catch(error => { console.error(error.message); process.exit(1); });
