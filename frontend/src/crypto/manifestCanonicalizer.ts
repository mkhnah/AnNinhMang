import { toCryptoBytes } from './spki';
import canonicalize from 'canonicalize';
import { SignedManifest } from '../types/signature';

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) Implementation for Client.
 * Uses official reference implementation to produce strictly deterministic UTF-8 bytes:
 * - Deterministic UTF-16 lexicographical property ordering
 * - ECMAScript standard number serialization
 * - Removal of all insignificant whitespace
 * - Strict rejection of NaN, Infinity, and undefined
 */
export function canonicalizeManifest(manifest: SignedManifest | Record<string, unknown>): Uint8Array {
    if (!manifest || typeof manifest !== 'object') {
        throw new TypeError('Manifest must be a non-null object');
    }

    // Deep check for invalid numbers (NaN, Infinity)
    validateNoIllegalNumbers(manifest);

    const canonicalString = canonicalize(manifest);
    if (canonicalString === undefined) {
        throw new TypeError('Failed to canonicalize manifest: unsupported types or undefined');
    }

    return new TextEncoder().encode(canonicalString);
}

export function canonicalizeManifestToUtf8(manifest: SignedManifest | Record<string, unknown>): Uint8Array {
    return canonicalizeManifest(manifest);
}

export async function computeManifestSha256(manifest: SignedManifest | Record<string, unknown>): Promise<string> {
    const bytes = canonicalizeManifest(manifest);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', toCryptoBytes(bytes));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function canonicalizeManifestToString(manifest: SignedManifest | Record<string, unknown>): string {
    if (!manifest || typeof manifest !== 'object') {
        throw new TypeError('Manifest must be a non-null object');
    }
    validateNoIllegalNumbers(manifest);
    const result = canonicalize(manifest);
    if (result === undefined) {
        throw new TypeError('Failed to canonicalize manifest');
    }
    return result;
}

function validateNoIllegalNumbers(val: unknown): void {
    if (typeof val === 'string') {
        for (let i = 0; i < val.length; i++) {
            const n = val.charCodeAt(i);
            if (n >= 0xd800 && n <= 0xdbff) {
                const next = val.charCodeAt(++i);
                if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('Lone surrogate');
            } else if (n >= 0xdc00 && n <= 0xdfff) throw new TypeError('Lone surrogate');
        }
    } else if (typeof val === 'number') {
        if (!Number.isFinite(val)) {
            throw new TypeError('RFC 8785 forbids NaN and Infinity in canonical JSON');
        }
    } else if (Array.isArray(val)) {
        for (const item of val) {
            validateNoIllegalNumbers(item);
        }
    } else if (val !== null && typeof val === 'object') {
        for (const key of Object.keys(val)) {
            validateNoIllegalNumbers(key);
            validateNoIllegalNumbers((val as Record<string, unknown>)[key]);
        }
    }
    else if (val !== null && typeof val !== 'boolean') {
        throw new TypeError('Unsupported JSON type');
    }
}
