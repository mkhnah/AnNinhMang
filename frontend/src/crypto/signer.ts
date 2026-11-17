import { validateSignedManifest } from './manifestBinding';
import { SignedManifest } from '../types/signature';
import { canonicalizeManifest } from './manifestCanonicalizer';
import { arrayBufferToBase64, base64ToArrayBuffer, toCryptoBytes } from './spki';

/**
 * Client-Side RSA-PSS Signing Engine.
 * Signs RFC 8785 canonical manifest bytes strictly using WebCrypto API.
 * The Private Key never leaves browser memory / IndexedDB.
 */
export async function signManifest(
    manifest: SignedManifest,
    privateKey: CryptoKey
): Promise<string> {
    validateSignedManifest(manifest);
    // 1. Strict schema and context validation
    if (!manifest || (manifest.manifest_version !== 1 && manifest.manifest_version !== 2)) {
        throw new Error('Phiên bản manifest không hợp lệ.');
    }

    if (manifest.signing_context !== `DOCSIGN_DOCUMENT_SIGNATURE_V${manifest.manifest_version}`) {
        throw new Error('Signing context không hợp lệ. Từ chối ký ngoài ngữ cảnh quy định.');
    }

    if (manifest.algorithm !== 'RSA-PSS-3072') {
        throw new Error(`Thuật toán '${manifest.algorithm}' không được hỗ trợ trong phiên bản hiện tại.`);
    }

    // 2. Validate private key properties
    if (privateKey.type !== 'private') {
        throw new Error('Khóa cung cấp không phải là Private Key.');
    }

    const privAlg = privateKey.algorithm as RsaHashedKeyAlgorithm;
    if (privAlg.name !== 'RSA-PSS') {
        throw new Error(`Thuật toán khóa '${privAlg.name}' không phải RSA-PSS.`);
    }

    if (privAlg.modulusLength !== 3072) {
        throw new Error(`Độ dài khóa RSA (${privAlg.modulusLength}-bit) không đạt chuẩn 3072-bit.`);
    }

    if ((privAlg.hash as KeyAlgorithm).name !== 'SHA-256') {
        throw new Error('Thuật toán băm của khóa không phải SHA-256.');
    }

    // 3. RFC 8785 JCS Canonicalization
    const canonicalBytes = canonicalizeManifest(manifest);

    // 4. Cryptographic RSA-PSS signature with salt length 32 bytes (256 bits)
    const signatureBuffer = await window.crypto.subtle.sign(
        {
            name: 'RSA-PSS',
            saltLength: 32,
        },
        privateKey,
        toCryptoBytes(canonicalBytes)
    );

    // 5. Export as Base64 string
    return arrayBufferToBase64(new Uint8Array(signatureBuffer));
}

/**
 * Verifies manifest signature on client against public key (used for self-test).
 */
export async function verifyManifestSignature(
    manifest: SignedManifest,
    signatureB64: string,
    publicKey: CryptoKey
): Promise<boolean> {
    const canonicalBytes = canonicalizeManifest(manifest);
    const signatureBytes = base64ToArrayBuffer(signatureB64);

    try {
        return await window.crypto.subtle.verify(
            {
                name: 'RSA-PSS',
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
