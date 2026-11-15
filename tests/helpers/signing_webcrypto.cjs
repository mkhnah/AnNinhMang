// Private CryptoKey stays in this process. Real frontend modules are bundled, never reimplemented.
const { build } = require('../../frontend/node_modules/esbuild');
const { webcrypto } = require('node:crypto');
const path = require('node:path');
const readline = require('node:readline');
(async () => {
  globalThis.window = { crypto: webcrypto, btoa, atob };
  const built = await build({ stdin: { contents: `export { generateRsaPssKeypair } from './frontend/src/crypto/keygen'; export { createProofOfPossession } from './frontend/src/crypto/pop'; export { signManifest } from './frontend/src/crypto/signer'; export { canonicalizeManifest } from './frontend/src/crypto/manifestCanonicalizer';`, resolveDir: path.resolve(__dirname, '../..') }, bundle:true, write:false, platform:'node', format:'cjs' });
  const mod = {exports:{}};
  new Function('module','exports',built.outputFiles[0].text)(mod,mod.exports);
  const api = mod.exports;
  let bundle;
  for await (const line of readline.createInterface({ input: process.stdin })) {
    try {
      const input = JSON.parse(line);
      let result;
      if (input.action === 'keygen') {
        bundle = await api.generateRsaPssKeypair(false);
        result = { public_key_pem: bundle.spkiPem, fingerprint: bundle.fingerprint };
      } else if (input.action === 'pop') result = {signature:await api.createProofOfPossession(bundle.keyPair.privateKey,input.payload)};
      else if (input.action === 'sign') result = {signature:await api.signManifest(input.payload,bundle.keyPair.privateKey)};
      else if (input.action === 'canonical') result = {bytes:Buffer.from(api.canonicalizeManifest(input.payload)).toString('base64')};
      else throw new Error('Unknown action');
      console.log(JSON.stringify(result));
    } catch(error) { console.log(JSON.stringify({error:error.message})); }
  }
})().catch(error=>{console.error(error.message);process.exit(1);});
