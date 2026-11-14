/** PoP schema v1 only. Not a general RFC 8785 implementation. */
export interface PopPayload {
    schema_version: 1;
    purpose: 'REGISTER_KEY';
    challenge_id: string;
    challenge_nonce: string;
    user_id: string;
    algorithm: 'RSA-PSS-3072';
    fingerprint: string;
}
const fields = ['algorithm', 'challenge_id', 'challenge_nonce', 'fingerprint', 'purpose', 'schema_version', 'user_id'] as const;

function fullMatch(pattern: RegExp, value: unknown): boolean {
    return typeof value === 'string' && pattern.exec(value)?.[0] === value;
}

export function canonicalizePopPayload(input: unknown): Uint8Array<ArrayBuffer> {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Invalid PoP payload');
    const obj = input as Record<string, unknown>;
    const names = Object.keys(obj).sort();
    if (names.length !== fields.length || names.some((name, i) => name !== fields[i])) throw new TypeError('Invalid PoP fields');
    if (obj.schema_version !== 1 || obj.purpose !== 'REGISTER_KEY' || obj.algorithm !== 'RSA-PSS-3072') throw new TypeError('Unsupported PoP schema/purpose/algorithm');
    for (const field of ['challenge_id', 'user_id']) {
        if (!fullMatch(/^[A-Za-z0-9_-]{1,64}$/, obj[field])) throw new TypeError('Invalid PoP identifier');
    }
    if (!fullMatch(/^[A-Za-z0-9_-]{8,128}$/, obj.challenge_nonce)) throw new TypeError('Invalid PoP nonce');
    if (!fullMatch(/^[a-f0-9]{64}$/, obj.fingerprint)) throw new TypeError('Invalid PoP fingerprint');
    const ordered = Object.fromEntries(fields.map(field => [field, obj[field]]));
    return new TextEncoder().encode(JSON.stringify(ordered));
}
