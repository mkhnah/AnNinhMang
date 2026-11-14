#!/usr/bin/env node
/** Node WebCrypto measurements only; no claims about browser performance. */
const { webcrypto } = require('node:crypto');
const { build } = require('../frontend/node_modules/esbuild');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
(async () => {
    const built = await build({ stdin: { contents: `export { generateRsaPssKeypair } from './frontend/src/crypto/keygen'; export { createEncryptedKeyBackup } from './frontend/src/crypto/keyBackup'; export { restoreEncryptedKeyBackup } from './frontend/src/crypto/keyRestore'; export { computeFingerprint, exportSpkiDer } from './frontend/src/crypto/spki';`, resolveDir: path.resolve(__dirname, '..') }, bundle: true, write: false, platform: 'node', format: 'cjs' });
    const module = { exports: {} };
    new Function('module', 'exports', built.outputFiles[0].text)(module, module.exports);
    const api = module.exports;
    globalThis.window = { crypto: webcrypto, btoa, atob };
    const rssBefore = process.memoryUsage().rss;
    const cpuBefore = process.cpuUsage();
    const results = {};
    async function measure(stage, action) {
        const start = performance.now();
        const value = await action();
        (results[stage] ||= []).push(performance.now() - start);
        return value;
    }
    // Three sequential synthetic keypairs only, no load or stress test.
    for (let i = 0; i < 3; i++) {
        const key = await measure('rsa3072_keygen', () => api.generateRsaPssKeypair(true));
        await measure('spki_export_and_fingerprint', async () => api.computeFingerprint(await api.exportSpkiDer(key.keyPair.publicKey)));
        const salt = webcrypto.getRandomValues(new Uint8Array(16));
        const password = await webcrypto.subtle.importKey('raw', new TextEncoder().encode('Synthetic-benchmark-passphrase'), 'PBKDF2', false, ['deriveKey']);
        await measure('pbkdf2_sha256_600000', () => webcrypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, password, { name: 'AES-GCM', length: 256 }, false, ['encrypt']));
        const backup = await measure('backup_total_default_600000', () => api.createEncryptedKeyBackup(key.keyPair.privateKey, key.fingerprint, 'Synthetic-benchmark-passphrase'));
        await measure('restore_total_default_600000', () => api.restoreEncryptedKeyBackup(backup, 'Synthetic-benchmark-passphrase'));
    }
    const cpu = process.cpuUsage(cpuBefore);
    const report = {
        runtime: `Node ${process.version} WebCrypto`, platform: `${os.platform()} ${os.release()} ${os.arch()}`, physical_memory_bytes: os.totalmem(),
        method: 'Three sequential samples using actual frontend crypto modules bundled in memory. Node WebCrypto, not a real browser. No IndexedDB/browser timing. No SLA or browser extrapolation. Keygen stage includes public export/fingerprint. Backup/restore include the default 600000-iteration KDF.',
        rss_before_bytes: rssBefore, rss_end_bytes: process.memoryUsage().rss, peak_rss_bytes: null, peak_rss_status: 'Not measured', cpu_seconds: (cpu.user + cpu.system) / 1e6,
        results: Object.fromEntries(Object.entries(results).map(([stage, samples]) => [stage, { samples_ms: samples, mean_ms: samples.reduce((a,b) => a+b,0) / samples.length, median_ms: [...samples].sort((a,b) => a-b)[1] }])),
    };
    const output = path.resolve(__dirname, '../docs/phase3-benchmark-node.json');
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report, null, 2));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
