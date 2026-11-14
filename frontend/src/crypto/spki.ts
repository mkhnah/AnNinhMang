/**
 * SPKI and Cryptographic Byte Encodings
 * Handles export of SubjectPublicKeyInfo (SPKI) DER bytes,
 * standard PEM line wrapping (RFC 7468), and SHA-256 fingerprint generation.
 */

/** Owned typed-array view accepted by browser WebCrypto and Node across JS realms. */
export function toCryptoBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    return new Uint8Array(bytes);
}

export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

export function base64ToArrayBuffer(base64: string): Uint8Array {
    const cleanBase64 = base64.replace(/\s+/g, "");
    const binary = window.atob(cleanBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    return new Uint8Array(exported);
}

export async function computeFingerprint(spkiDer: Uint8Array): Promise<string> {
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", toCryptoBytes(spkiDer));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toLowerCase();
}

export function spkiDerToPem(spkiDer: Uint8Array): string {
    const b64 = arrayBufferToBase64(spkiDer);
    // Wrap at 64 characters
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
}

export function pemToSpkiDer(pem: string): Uint8Array {
    const cleaned = pem
        .replace(/-----BEGIN [A-Z0-9_-]+-----/g, "")
        .replace(/-----END [A-Z0-9_-]+-----/g, "")
        .replace(/\s+/g, "");
    return base64ToArrayBuffer(cleaned);
}
