import { describe, it, expect } from 'vitest';
import { generateRsaPssKeypair } from '../keygen';
import { exportSpkiDer, spkiDerToPem, computeFingerprint, arrayBufferToBase64, base64ToArrayBuffer, toCryptoBytes } from '../spki';
import { canonicalizePopPayload } from '../canonicalJson';
import type { PopPayload } from '../pop';
import vectors from '../../../../tests/fixtures/pop-v1.json';
import { createProofOfPossession, verifyProofOfPossession } from '../pop';
import { createEncryptedKeyBackup, constructBackupAad } from '../keyBackup';
import { restoreEncryptedKeyBackup } from '../keyRestore';
import {
    saveKeyToKeystore,
    getKeyFromKeystore,
    listKeysForUser,
    removeKeyFromKeystore,
} from '../keyStorage';

describe('Phase 3 Client-Side Cryptography Test Suite', () => {
    // -------------------------------------------------------------
    // 1. SPKI & Canonical Formatting
    // -------------------------------------------------------------
    describe('SPKI, Fingerprint & Canonicalization', () => {
        it('matches the shared PoP v1 golden vectors', () => {
            for (const vector of vectors.valid) {
                expect(new TextDecoder().decode(canonicalizePopPayload(vector.payload))).toBe(vector.canonical_utf8);
                expect(arrayBufferToBase64(canonicalizePopPayload(vector.payload))).toBe(vector.canonical_b64);
            }
        });
        it('rejects values and fields outside the PoP v1 contract', () => {
            for (const payload of vectors.invalid) {
                expect(() => canonicalizePopPayload(payload)).toThrow();
            }
        });

        it('base64 <-> ArrayBuffer conversion preserves all bytes exactly', () => {
            const rawBytes = new Uint8Array([0, 1, 2, 253, 254, 255, 42, 69]);
            const b64 = arrayBufferToBase64(rawBytes);
            const recovered = new Uint8Array(base64ToArrayBuffer(b64));
            expect(recovered).toEqual(rawBytes);
        });

        it('spkiDerToPem wraps base64 lines at 64 characters and includes standard headers', () => {
            const dummyDer = new Uint8Array(128).fill(0xaa);
            const pem = spkiDerToPem(dummyDer);
            expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true);
            expect(pem.endsWith('\n-----END PUBLIC KEY-----')).toBe(true);

            const lines = pem.split('\n').slice(1, -1);
            for (let i = 0; i < lines.length - 1; i++) {
                expect(lines[i].length).toBe(64);
            }
        });
    });

    // -------------------------------------------------------------
    // 2. RSA-PSS 3072-bit Key Generation
    // -------------------------------------------------------------
    describe('Key Generation (RSA-PSS 3072-bit)', () => {
        it('generates a compliant RSA-PSS 3072-bit key pair with Mode B (extractable)', async () => {
            const bundle = await generateRsaPssKeypair(true);

            expect(bundle.algorithm).toBe('RSA-PSS-3072');
            expect(bundle.fingerprint).toMatch(/^[0-9a-f]{64}$/);
            expect(bundle.spkiPem).toContain('-----BEGIN PUBLIC KEY-----');

            const privAlg = bundle.keyPair.privateKey.algorithm as RsaHashedKeyAlgorithm;
            expect(privAlg.name).toBe('RSA-PSS');
            expect(privAlg.modulusLength).toBe(3072);
            expect((privAlg.hash as KeyAlgorithm).name).toBe('SHA-256');
            expect(bundle.keyPair.privateKey.extractable).toBe(true);

            const pubAlg = bundle.keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm;
            expect(pubAlg.modulusLength).toBe(3072);
        }, 15000);

        it('generates a compliant Mode A (non-extractable) key pair', async () => {
            const bundle = await generateRsaPssKeypair(false);
            expect(bundle.keyPair.privateKey.extractable).toBe(false);
            expect(bundle.keyPair.publicKey.extractable).toBe(true);
        }, 15000);
    });

    // -------------------------------------------------------------
    // 3. Proof-of-Possession (PoP)
    // -------------------------------------------------------------
    describe('Proof-of-Possession (PoP)', () => {
        it('generates a valid PoP signature verifiable with the public key', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const payload = {
                schema_version: 1,
                purpose: 'REGISTER_KEY',
                challenge_id: 'ch-test-1234',
                challenge_nonce: 'nonce-abcd-ef01',
                user_id: 'user-crypto-qa',
                algorithm: 'RSA-PSS-3072',
                fingerprint: bundle.fingerprint,
            } satisfies PopPayload;

            const sigB64 = await createProofOfPossession(bundle.keyPair.privateKey, payload);
            expect(sigB64.length).toBeGreaterThan(100);

            const isValid = await verifyProofOfPossession(bundle.keyPair.publicKey, payload, sigB64);
            expect(isValid).toBe(true);
        }, 15000);

        it('fails verification if PoP payload is tampered', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const payload = {
                schema_version: 1,
                purpose: 'REGISTER_KEY',
                challenge_id: 'ch-test-1234',
                challenge_nonce: 'nonce-abcd-ef01',
                user_id: 'user-crypto-qa',
                algorithm: 'RSA-PSS-3072',
                fingerprint: bundle.fingerprint,
            } satisfies PopPayload;

            const sigB64 = await createProofOfPossession(bundle.keyPair.privateKey, payload);

            // Attacker alters purpose or user_id
            const tamperedPayload = { ...payload, user_id: 'attacker-account' };
            const isValid = await verifyProofOfPossession(bundle.keyPair.publicKey, tamperedPayload, sigB64);
            expect(isValid).toBe(false);
        }, 15000);
    });

    // -------------------------------------------------------------
    // 4. Backup, Encryption & Strict Restore Validation
    // -------------------------------------------------------------
    describe('Key Backup, Encryption (AES-256-GCM + PBKDF2) & Restore Validation', () => {
        const PASSPHRASE = 'CorrectPassphrase#2026';

        it('performs complete round-trip backup and restore with self-test verification', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const backup = await createEncryptedKeyBackup(
                bundle.keyPair.privateKey,
                bundle.fingerprint,
                PASSPHRASE,
                100000
            );

            expect(backup.format).toBe('DOCSIGN_ENCRYPTED_PKCS8');
            expect(backup.version).toBe(1);
            expect(backup.algorithm).toBe('RSA-PSS-3072');
            expect(backup.cipher).toBe('AES-256-GCM');
            expect(backup.kdf).toBe('PBKDF2-HMAC-SHA256');
            expect(backup.iterations).toBe(100000);
            expect(backup.public_key_fingerprint).toBe(bundle.fingerprint);

            const restored = await restoreEncryptedKeyBackup(backup, PASSPHRASE);
            expect(restored.fingerprint).toBe(bundle.fingerprint);
            expect(restored.algorithm).toBe('RSA-PSS-3072');
            expect(restored.spkiPem).toBe(bundle.spkiPem);

            // Verify restored private key can sign
            const testPayload = new TextEncoder().encode('Signature Verification Post Restore');
            const sig = await window.crypto.subtle.sign(
                { name: 'RSA-PSS', saltLength: 32 },
                restored.privateKey,
                testPayload
            );
            const verified = await window.crypto.subtle.verify(
                { name: 'RSA-PSS', saltLength: 32 },
                bundle.keyPair.publicKey,
                sig,
                testPayload
            );
            expect(verified).toBe(true);
        }, 20000);

        it('rejects restoration with wrong passphrase (AES-GCM tag mismatch)', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const backup = await createEncryptedKeyBackup(
                bundle.keyPair.privateKey,
                bundle.fingerprint,
                PASSPHRASE,
                100000
            );

            await expect(
                restoreEncryptedKeyBackup(backup, 'WrongPassphrase#9999')
            ).rejects.toThrow(/Giải mã thất bại/i);
        }, 20000);

        it('rejects restoration with tampered ciphertext', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const backup = await createEncryptedKeyBackup(
                bundle.keyPair.privateKey,
                bundle.fingerprint,
                PASSPHRASE,
                100000
            );

            const ctBytes = new Uint8Array(base64ToArrayBuffer(backup.ciphertext_b64));
            ctBytes[10] ^= 0xff; // Flip bits in ciphertext
            const tamperedBackup = {
                ...backup,
                ciphertext_b64: arrayBufferToBase64(ctBytes),
            };

            await expect(
                restoreEncryptedKeyBackup(tamperedBackup, PASSPHRASE)
            ).rejects.toThrow(/Giải mã thất bại/i);
        }, 20000);

        it('rejects restoration with tampered AAD / fingerprint metadata', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const backup = await createEncryptedKeyBackup(
                bundle.keyPair.privateKey,
                bundle.fingerprint,
                PASSPHRASE,
                100000
            );

            // Tamper fingerprint in metadata
            const tamperedBackup = {
                ...backup,
                public_key_fingerprint: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            };

            await expect(
                restoreEncryptedKeyBackup(tamperedBackup, PASSPHRASE)
            ).rejects.toThrow(/Giải mã thất bại/i);
        }, 20000);

        it('rejects invalid backup schema attributes (format, version, algorithm, cipher, kdf)', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const validBackup = await createEncryptedKeyBackup(
                bundle.keyPair.privateKey,
                bundle.fingerprint,
                PASSPHRASE,
                100000
            );

            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, format: 'INVALID_FORMAT' }, PASSPHRASE)
            ).rejects.toThrow(/Định dạng sao lưu không được hỗ trợ/);

            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, version: 2 }, PASSPHRASE)
            ).rejects.toThrow(/Phiên bản sao lưu.*không tương thích/);

            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, algorithm: 'RSA-PSS-2048' }, PASSPHRASE)
            ).rejects.toThrow(/Thuật toán.*không được hỗ trợ/);

            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, cipher: 'AES-128-CBC' }, PASSPHRASE)
            ).rejects.toThrow(/Thuật toán mã hóa.*không được hỗ trợ/);

            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, kdf: 'MD5' }, PASSPHRASE)
            ).rejects.toThrow(/KDF.*không được hỗ trợ/);
        }, 20000);

        it('rejects invalid salt length, IV length, or iterations out of [100000, 2000000]', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const validBackup = await createEncryptedKeyBackup(
                bundle.keyPair.privateKey,
                bundle.fingerprint,
                PASSPHRASE,
                100000
            );

            // Iterations < 100,000
            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, iterations: 99999 }, PASSPHRASE)
            ).rejects.toThrow(/Số vòng lặp KDF phải là số nguyên/);

            // Iterations > 2,000,000
            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, iterations: 2000001 }, PASSPHRASE)
            ).rejects.toThrow(/Số vòng lặp KDF phải là số nguyên/);

            // Salt != 16 bytes
            const badSalt = arrayBufferToBase64(new Uint8Array(8));
            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, salt_b64: badSalt }, PASSPHRASE)
            ).rejects.toThrow(/Kích thước salt PBKDF2 không đúng/);

            // IV != 12 bytes
            const badIv = arrayBufferToBase64(new Uint8Array(16));
            await expect(
                restoreEncryptedKeyBackup({ ...validBackup, iv_b64: badIv }, PASSPHRASE)
            ).rejects.toThrow(/Kích thước IV AES-GCM không đúng/);
        }, 20000);

        // -------------------------------------------------------------
        // FIX 2 SPECIFIC: Strict RSA-2048 Key Rejection
        // -------------------------------------------------------------
        it('[FIX 2] Strictly rejects restored keys if modulusLength != 3072 (e.g. RSA-2048 bypass attack)', async () => {
            // Generate an RSA-2048 key
            const rsa2048Key = await window.crypto.subtle.generateKey(
                {
                    name: 'RSA-PSS',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256',
                },
                true,
                ['sign', 'verify']
            );

            const spkiDer2048 = await exportSpkiDer(rsa2048Key.publicKey);
            const fp2048 = await computeFingerprint(spkiDer2048);

            // Export PKCS#8
            const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', rsa2048Key.privateKey);

            // Manually encrypt as if it was a valid backup JSON claiming to be RSA-PSS-3072
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const iv = window.crypto.getRandomValues(new Uint8Array(12));

            const importedPw = await window.crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(PASSPHRASE),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            const aesKey = await window.crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                importedPw,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );
            const aad = constructBackupAad(fp2048);
            const ct = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv, additionalData: toCryptoBytes(aad), tagLength: 128 },
                aesKey,
                pkcs8
            );

            const maliciousBackup = {
                format: 'DOCSIGN_ENCRYPTED_PKCS8' as const,
                version: 1 as const,
                algorithm: 'RSA-PSS-3072' as const, // Forged metadata claim
                cipher: 'AES-256-GCM' as const,
                kdf: 'PBKDF2-HMAC-SHA256' as const,
                iterations: 100000,
                salt_b64: arrayBufferToBase64(salt),
                iv_b64: arrayBufferToBase64(iv),
                ciphertext_b64: arrayBufferToBase64(ct),
                public_key_fingerprint: fp2048,
            };

            await expect(
                restoreEncryptedKeyBackup(maliciousBackup, PASSPHRASE)
            ).rejects.toThrow(/2048-bit.*từ chối/i);
        }, 20000);
    });

    // -------------------------------------------------------------
    // 5. IndexedDB Key Storage & Durability
    // -------------------------------------------------------------
    describe('IndexedDB Key Storage', () => {
        const USER_ID = 'user-indexeddb-test-uuid';

        it('persists, reads back, lists, and removes a key record durably', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const record = {
                fingerprint: bundle.fingerprint,
                userId: USER_ID,
                algorithm: 'RSA-PSS-3072' as const,
                privateKey: bundle.keyPair.privateKey,
                publicKey: bundle.keyPair.publicKey,
                spkiPem: bundle.spkiPem,
                extractable: true,
                createdAt: new Date().toISOString(),
            };

            // Save
            await saveKeyToKeystore(record);

            // Read back
            const retrieved = await getKeyFromKeystore(bundle.fingerprint);
            expect(retrieved).not.toBeNull();
            expect(retrieved?.fingerprint).toBe(bundle.fingerprint);
            expect(retrieved?.userId).toBe(USER_ID);

            // List for user
            const list = await listKeysForUser(USER_ID);
            expect(list.length).toBeGreaterThanOrEqual(1);
            expect(list.some((k) => k.fingerprint === bundle.fingerprint)).toBe(true);

            // Remove
            await removeKeyFromKeystore(bundle.fingerprint);
            const afterRemoval = await getKeyFromKeystore(bundle.fingerprint);
            expect(afterRemoval).toBeNull();
        }, 15000);
    });
});
