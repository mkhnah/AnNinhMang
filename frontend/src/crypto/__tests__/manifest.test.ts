import { describe, it, expect } from 'vitest';
import vectors from '../../../../tests/fixtures/jcs-v1/vectors.json';
import {
    canonicalizeManifest,
    canonicalizeManifestToString,
    canonicalizeManifestToUtf8,
    computeManifestSha256,
} from '../manifestCanonicalizer';
import { generateRsaPssKeypair } from '../keygen';
import { signManifest, verifyManifestSignature } from '../signer';
import { SignedManifest } from '../../types/signature';

describe('Phase 4: RFC 8785 JCS & RSA-PSS Client Signing Engine', () => {
    describe('RFC 8785 JSON Canonicalization Scheme (JCS)', () => {
        it('produces exact byte-for-byte canonical output for all golden vectors', () => {
            for (const vec of vectors) {
                const canonicalStr = canonicalizeManifestToString(vec.input);
                expect(canonicalStr).toBe(vec.expected_canonical);

                const utf8Bytes = canonicalizeManifestToUtf8(vec.input);
                const decoded = new TextDecoder('utf-8').decode(utf8Bytes);
                expect(decoded).toBe(vec.expected_canonical);
            }
        });

        it('computes deterministic SHA-256 hash of canonical manifest bytes', async () => {
            const manifestInput = vectors[0].input as unknown as SignedManifest;
            const hash1 = await computeManifestSha256(manifestInput);
            const hash2 = await computeManifestSha256(manifestInput);

            expect(hash1).toHaveLength(64);
            expect(hash1).toMatch(/^[0-9a-f]{64}$/);
            expect(hash1).toBe(hash2);
        });

        it('rejects objects with NaN or Infinity numbers', () => {
            expect(() => canonicalizeManifest({ invalid_val: NaN })).toThrow();
            expect(() => canonicalizeManifest({ invalid_val: Infinity })).toThrow();
            expect(() => canonicalizeManifest({ invalid_val: -Infinity })).toThrow();
        });
    });

    describe('RSA-PSS 3072-bit Detached Manifest Signing & Verification', () => {
        it('signs canonical manifest and verifies successfully with public key', async () => {
            // Generate RSA-PSS 3072 key pair
            const bundle = await generateRsaPssKeypair(true);
            const manifest: SignedManifest = {
                manifest_version: 1,
                document_version_id: '7f8b86d6-0562-4318-9719-74d320295874',
                document_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
                key_id: '19bfae79-5095-4682-8959-19ffcf6fa505',
                signer_fingerprint: '8cf55227bf317c24f6050b1d3d63b92cbddf6a8e83b482bcf0ebca1c88820cfb',
                algorithm: 'RSA-PSS-3072',
                signing_nonce: 'e_zL7Qc7t3uX6G9yD4vN8mK2pL5wR1tY0oP9aB3cV8s',
                signing_timestamp: '2026-11-15T00:00:00.000Z',
                signing_context: 'DOCSIGN_DOCUMENT_SIGNATURE_V1',
            };

            const sigB64 = await signManifest(manifest, bundle.keyPair.privateKey);
            expect(typeof sigB64).toBe('string');
            expect(sigB64.length).toBeGreaterThan(100);

            // Verifies with matching public key
            const isValid = await verifyManifestSignature(manifest, sigB64, bundle.keyPair.publicKey);
            expect(isValid).toBe(true);
        });

        it('fails verification if document_sha256 in manifest is tampered', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const manifest: SignedManifest = {
                manifest_version: 1,
                document_version_id: '7f8b86d6-0562-4318-9719-74d320295874',
                document_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
                key_id: '19bfae79-5095-4682-8959-19ffcf6fa505',
                signer_fingerprint: '8cf55227bf317c24f6050b1d3d63b92cbddf6a8e83b482bcf0ebca1c88820cfb',
                algorithm: 'RSA-PSS-3072',
                signing_nonce: 'e_zL7Qc7t3uX6G9yD4vN8mK2pL5wR1tY0oP9aB3cV8s',
                signing_timestamp: '2026-11-15T00:00:00.000Z',
                signing_context: 'DOCSIGN_DOCUMENT_SIGNATURE_V1',
            };

            const sigB64 = await signManifest(manifest, bundle.keyPair.privateKey);

            // Tampered document SHA-256
            const tamperedManifest: SignedManifest = {
                ...manifest,
                document_sha256: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            };

            const isValid = await verifyManifestSignature(tamperedManifest, sigB64, bundle.keyPair.publicKey);
            expect(isValid).toBe(false);
        });

        it('fails verification if nonce or timestamp is tampered', async () => {
            const bundle = await generateRsaPssKeypair(true);
            const manifest: SignedManifest = {
                manifest_version: 1,
                document_version_id: '7f8b86d6-0562-4318-9719-74d320295874',
                document_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
                key_id: '19bfae79-5095-4682-8959-19ffcf6fa505',
                signer_fingerprint: '8cf55227bf317c24f6050b1d3d63b92cbddf6a8e83b482bcf0ebca1c88820cfb',
                algorithm: 'RSA-PSS-3072',
                signing_nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                signing_timestamp: '2026-11-15T00:00:00.000Z',
                signing_context: 'DOCSIGN_DOCUMENT_SIGNATURE_V1',
            };

            const sigB64 = await signManifest(manifest, bundle.keyPair.privateKey);

            const replayedWithDifferentNonce: SignedManifest = {
                ...manifest,
                signing_nonce: 'different_nonce_replayed_attack',
            };

            const isValid = await verifyManifestSignature(
                replayedWithDifferentNonce,
                sigB64,
                bundle.keyPair.publicKey
            );
            expect(isValid).toBe(false);
        });

        it('fails verification if a different key pair is used to verify', async () => {
            const bundleA = await generateRsaPssKeypair(true);
            const bundleB = await generateRsaPssKeypair(true);

            const manifest: SignedManifest = {
                manifest_version: 1,
                document_version_id: '7f8b86d6-0562-4318-9719-74d320295874',
                document_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
                key_id: '19bfae79-5095-4682-8959-19ffcf6fa505',
                signer_fingerprint: '8cf55227bf317c24f6050b1d3d63b92cbddf6a8e83b482bcf0ebca1c88820cfb',
                algorithm: 'RSA-PSS-3072',
                signing_nonce: 'e_zL7Qc7t3uX6G9yD4vN8mK2pL5wR1tY0oP9aB3cV8s',
                signing_timestamp: '2026-11-15T00:00:00.000Z',
                signing_context: 'DOCSIGN_DOCUMENT_SIGNATURE_V1',
            };

            const sigB64 = await signManifest(manifest, bundleA.keyPair.privateKey);

            const isValid = await verifyManifestSignature(manifest, sigB64, bundleB.keyPair.publicKey);
            expect(isValid).toBe(false);
        });
    });
});
