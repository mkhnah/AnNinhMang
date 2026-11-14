import { canonicalizePopPayload } from "./canonicalJson";
import { arrayBufferToBase64, base64ToArrayBuffer, toCryptoBytes } from "./spki";

import type { PopPayload } from './canonicalJson';
export type { PopPayload } from './canonicalJson';

/**
 * Creates a Proof-of-Possession (PoP) signature over a canonically formatted challenge payload.
 * Salt length is strictly fixed to 32 bytes (256 bits) to match the PoP v1 contract with Python cryptography.
 */
export async function createProofOfPossession(
    privateKey: CryptoKey,
    payload: PopPayload
): Promise<string> {
    const canonicalBytes = canonicalizePopPayload(payload);

    const signatureBuffer = await window.crypto.subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        privateKey,
        toCryptoBytes(canonicalBytes)
    );

    return arrayBufferToBase64(new Uint8Array(signatureBuffer));
}

/**
 * Verifies a Proof-of-Possession signature against the public key and payload.
 */
export async function verifyProofOfPossession(
    publicKey: CryptoKey,
    payload: PopPayload,
    signatureB64: string
): Promise<boolean> {
    const canonicalBytes = canonicalizePopPayload(payload);
    const signatureBytes = base64ToArrayBuffer(signatureB64);

    try {
        return await window.crypto.subtle.verify(
            {
                name: "RSA-PSS",
                saltLength: 32,
            },
            publicKey,
            toCryptoBytes(signatureBytes),
            toCryptoBytes(canonicalBytes)
        );
    } catch {
        return false;
    }
}
