import { exportSpkiDer, computeFingerprint, spkiDerToPem } from "./spki";

export interface GeneratedKeyBundle {
    keyPair: CryptoKeyPair;
    algorithm: "RSA-PSS-3072";
    extractable: boolean;
    spkiDer: Uint8Array;
    spkiPem: string;
    fingerprint: string;
}

/**
 * Generates an asymmetric RSA-PSS 3072-bit keypair using the browser's WebCrypto API.
 * The private key is generated directly inside the browser's cryptographic boundary
 * and is never transmitted to the backend server.
 * 
 * @param extractable If true (Mode B), allows exporting PKCS#8 for encrypted password backup.
 *                    If false (Mode A), key cannot be exported via WebCrypto.
 */
export async function generateRsaPssKeypair(extractable: boolean): Promise<GeneratedKeyBundle> {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 3072,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
            hash: "SHA-256",
        },
        extractable,
        ["sign", "verify"]
    );

    const spkiDer = await exportSpkiDer(keyPair.publicKey);
    const fingerprint = await computeFingerprint(spkiDer);
    const spkiPem = spkiDerToPem(spkiDer);

    return {
        keyPair,
        algorithm: "RSA-PSS-3072",
        extractable,
        spkiDer,
        spkiPem,
        fingerprint,
    };
}
