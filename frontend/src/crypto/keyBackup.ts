import { arrayBufferToBase64, toCryptoBytes } from "./spki";

export interface EncryptedKeyBackup {
    format: "DOCSIGN_ENCRYPTED_PKCS8";
    version: 1;
    algorithm: "RSA-PSS-3072";
    kdf: "PBKDF2-HMAC-SHA256";
    iterations: number;
    salt_b64: string;
    cipher: "AES-256-GCM";
    iv_b64: string;
    ciphertext_b64: string;
    public_key_fingerprint: string;
}

export function constructBackupAad(fingerprint: string): Uint8Array {
    return new TextEncoder().encode(`DOCSIGN:BACKUP:v1:RSA-PSS-3072:${fingerprint.toLowerCase()}`);
}

/**
 * Creates a password-encrypted PKCS#8 backup of the private key using:
 * - KDF: PBKDF2-HMAC-SHA256 (default 600,000 iterations, 16-byte random salt)
 * - Cipher: AES-256-GCM (12-byte random IV, 128-bit authentication tag)
 * - AAD: Cryptographically binds the backup metadata and public key fingerprint
 * 
 * Sensitive memory buffers are zeroized upon completion.
 */
export async function createEncryptedKeyBackup(
    privateKey: CryptoKey,
    fingerprint: string,
    passphrase: string,
    iterations = 600000
): Promise<EncryptedKeyBackup> {
    if (!privateKey.extractable) {
        throw new Error("Khóa này được tạo ở chế độ không thể xuất (Mode A - Non-extractable). Không thể sao lưu.");
    }

    if (!passphrase || passphrase.length < 8) {
        throw new Error("Mật khẩu bảo vệ bản sao lưu phải có ít nhất 8 ký tự.");
    }

    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) {
        throw new Error("Số vòng lặp KDF phải nằm trong khoảng từ 100,000 đến 2,000,000.");
    }

    // 1. Export private key in PKCS#8 DER format
    const pkcs8Buffer = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    const pkcs8Bytes = new Uint8Array(pkcs8Buffer);

    try {
        // 2. Generate random 16-byte salt
        const salt = window.crypto.getRandomValues(new Uint8Array(16));

        // 3. Derive AES-GCM 256-bit key from passphrase via PBKDF2
        const passphraseBytes = new TextEncoder().encode(passphrase);
        const importedPassphraseKey = await window.crypto.subtle.importKey(
            "raw",
            passphraseBytes,
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        const derivedAesKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: iterations,
                hash: "SHA-256",
            },
            importedPassphraseKey,
            {
                name: "AES-GCM",
                length: 256,
            },
            false,
            ["encrypt"]
        );

        // 4. Generate random 12-byte IV (96-bit standard for GCM)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // 5. Construct AAD binding to prevent header tampering
        const aad = constructBackupAad(fingerprint);

        // 6. Encrypt PKCS#8 payload
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                additionalData: toCryptoBytes(aad),
                tagLength: 128,
            },
            derivedAesKey,
            pkcs8Buffer
        );

        const encryptedBytes = new Uint8Array(encryptedBuffer);

        return {
            format: "DOCSIGN_ENCRYPTED_PKCS8",
            version: 1,
            algorithm: "RSA-PSS-3072",
            kdf: "PBKDF2-HMAC-SHA256",
            iterations: iterations,
            salt_b64: arrayBufferToBase64(salt),
            cipher: "AES-256-GCM",
            iv_b64: arrayBufferToBase64(iv),
            ciphertext_b64: arrayBufferToBase64(encryptedBytes),
            public_key_fingerprint: fingerprint.toLowerCase(),
        };
    } finally {
        // Sensitive memory hygiene: zeroize raw PKCS#8 bytes
        pkcs8Bytes.fill(0);
    }
}
