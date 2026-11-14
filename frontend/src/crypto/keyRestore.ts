import { base64ToArrayBuffer, computeFingerprint, exportSpkiDer, spkiDerToPem, toCryptoBytes } from "./spki";
import { constructBackupAad } from "./keyBackup";

export interface RestoredKeyBundle {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    fingerprint: string;
    spkiPem: string;
    algorithm: "RSA-PSS-3072";
}

/**
 * Restores a private key from an encrypted JSON backup file (.pem.enc).
 * - Verifies backup schema and limits (iterations, file size, versions)
 * - Derives AES-256-GCM key from passphrase and salt
 * - Decrypts and verifies AES-GCM authentication tag and AAD
 * - Reconstructs public key and verifies fingerprint matches backup metadata
 * - Performs self-test signature round-trip to guarantee key integrity
 */
export async function restoreEncryptedKeyBackup(
    backupInput: unknown,
    passphrase: string
): Promise<RestoredKeyBundle> {
    // 1. Schema and format validation
    if (!backupInput || typeof backupInput !== "object" || Array.isArray(backupInput)) {
        throw new Error("Dữ liệu sao lưu không đúng định dạng JSON.");
    }

    const backup = backupInput as Record<string, unknown>;

    if (backup.format !== "DOCSIGN_ENCRYPTED_PKCS8") {
        throw new Error(`Định dạng sao lưu không được hỗ trợ: '${backup.format}'`);
    }

    if (backup.version !== 1) {
        throw new Error(`Phiên bản sao lưu '${backup.version}' không tương thích (chỉ hỗ trợ phiên bản 1)`);
    }

    if (backup.algorithm !== "RSA-PSS-3072") {
        throw new Error(`Thuật toán '${backup.algorithm}' không được hỗ trợ`);
    }

    if (backup.cipher !== "AES-256-GCM") {
        throw new Error(`Thuật toán mã hóa '${backup.cipher}' không được hỗ trợ`);
    }

    if (backup.kdf !== "PBKDF2-HMAC-SHA256") {
        throw new Error(`KDF '${backup.kdf}' không được hỗ trợ`);
    }

    if (
        typeof backup.iterations !== "number" ||
        !Number.isInteger(backup.iterations) ||
        backup.iterations < 100000 ||
        backup.iterations > 2000000
    ) {
        throw new Error("Số vòng lặp KDF phải là số nguyên trong khoảng [100000, 2000000].");
    }

    if (typeof backup.salt_b64 !== "string" || typeof backup.iv_b64 !== "string" || typeof backup.ciphertext_b64 !== "string" || typeof backup.public_key_fingerprint !== "string") {
        throw new Error("Tệp sao lưu bị thiếu các trường tham số mật mã bắt buộc.");
    }

    const hexRegex = /^[0-9a-f]{64}$/i;
    if (!hexRegex.test(backup.public_key_fingerprint) || backup.public_key_fingerprint.length !== 64) {
        throw new Error("Định dạng fingerprint trong tệp sao lưu không hợp lệ (phải là 64 ký tự hex SHA-256).");
    }

    if (!passphrase) {
        throw new Error("Vui lòng nhập mật khẩu giải mã.");
    }

    // 2. Decode binary fields
    const salt = base64ToArrayBuffer(backup.salt_b64);
    const iv = base64ToArrayBuffer(backup.iv_b64);
    const ciphertext = base64ToArrayBuffer(backup.ciphertext_b64);

    if (salt.byteLength !== 16) {
        throw new Error("Kích thước salt PBKDF2 không đúng (yêu cầu chính xác 16 bytes).");
    }

    if (iv.byteLength !== 12) {
        throw new Error("Kích thước IV AES-GCM không đúng (yêu cầu chính xác 12 bytes / 96-bit).");
    }

    if (ciphertext.byteLength < 17) {
        throw new Error("Dữ liệu bản mã quá ngắn (tối thiểu 17 bytes bao gồm 16-byte authentication tag).");
    }

    // 3. Derive AES key via PBKDF2
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
            salt: toCryptoBytes(salt),
            iterations: backup.iterations,
            hash: "SHA-256",
        },
        importedPassphraseKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["decrypt"]
    );

    // 4. Decrypt PKCS#8 with AAD
    const aad = constructBackupAad(backup.public_key_fingerprint);
    let decryptedBuffer: ArrayBuffer;
    try {
        decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: toCryptoBytes(iv),
                additionalData: toCryptoBytes(aad),
                tagLength: 128,
            },
            derivedAesKey,
            toCryptoBytes(ciphertext)
        );
    } catch {
        throw new Error(
            "Giải mã thất bại: Mật khẩu không đúng hoặc nội dung tệp sao lưu đã bị chỉnh sửa (AES-GCM Tag Mismatch)."
        );
    }

    const decryptedBytes = new Uint8Array(decryptedBuffer);

    try {
        // 5. Import private key into WebCrypto
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            decryptedBuffer,
            {
                name: "RSA-PSS",
                hash: "SHA-256",
            },
            true,
            ["sign"]
        );

        // Strict cryptographic parameters validation (rejection of RSA-2048 or unsupported specs)
        const privAlg = privateKey.algorithm as RsaHashedKeyAlgorithm;
        if (privAlg.name !== "RSA-PSS") {
            throw new Error(`Thuật toán khóa '${privAlg.name}' không phải là RSA-PSS.`);
        }

        if (privAlg.modulusLength !== 3072) {
            throw new Error(
                `Kích thước khóa RSA (${privAlg.modulusLength}-bit) không đạt chuẩn yêu cầu bảo mật 3072-bit. Khóa 2048-bit hoặc kích thước khác bị từ chối tuyệt đối.`
            );
        }

        if (privAlg.hash && (privAlg.hash as KeyAlgorithm).name !== "SHA-256") {
            throw new Error("Thuật toán băm của khóa không phải SHA-256.");
        }

        if (privAlg.publicExponent) {
            const exp = new Uint8Array(privAlg.publicExponent);
            const is65537 = exp.length === 3 && exp[0] === 1 && exp[1] === 0 && exp[2] === 1;
            if (!is65537) {
                throw new Error("Số mũ công khai e phải bằng 65537.");
            }
        }

        // 6. Reconstruct public key from private key JWK export
        const jwk = await window.crypto.subtle.exportKey("jwk", privateKey);
        const publicJwk: JsonWebKey = {
            kty: jwk.kty,
            n: jwk.n,
            e: jwk.e,
            alg: "PS256",
            ext: true,
            key_ops: ["verify"],
        };

        const publicKey = await window.crypto.subtle.importKey(
            "jwk",
            publicJwk,
            {
                name: "RSA-PSS",
                hash: "SHA-256",
            },
            true,
            ["verify"]
        );

        // 7. Verify computed fingerprint matches metadata
        const spkiDer = await exportSpkiDer(publicKey);
        const computedFingerprint = await computeFingerprint(spkiDer);

        if (computedFingerprint !== backup.public_key_fingerprint.toLowerCase()) {
            throw new Error(
                `Fingerprint của khóa giải mã (${computedFingerprint}) không khớp với thông tin trong tệp sao lưu (${backup.public_key_fingerprint}).`
            );
        }

        // 8. Self-test signature round-trip to guarantee key integrity
        const testNonce = window.crypto.getRandomValues(new Uint8Array(32));
        const testSignature = await window.crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            privateKey,
            toCryptoBytes(testNonce)
        );

        const isValid = await window.crypto.subtle.verify(
            { name: "RSA-PSS", saltLength: 32 },
            publicKey,
            testSignature,
            toCryptoBytes(testNonce)
        );

        if (!isValid) {
            throw new Error("Kiểm tra tự kiểm (self-test) chữ ký số RSA-PSS thất bại trên cặp khóa được khôi phục.");
        }

        const spkiPem = spkiDerToPem(spkiDer);

        return {
            privateKey,
            publicKey,
            fingerprint: computedFingerprint,
            spkiPem,
            algorithm: "RSA-PSS-3072",
        };
    } finally {
        // Sensitive memory hygiene: zeroize decrypted bytes
        decryptedBytes.fill(0);
    }
}
