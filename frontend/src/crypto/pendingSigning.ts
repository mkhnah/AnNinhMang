import { SignatureSubmitRequest } from '../types/signature';
import { validateSignedManifest } from './manifestBinding';

// Public evidence only. No CryptoKey, private bytes, token or passphrase is persisted here.
export interface SigningAttempt {
    request: SignatureSubmitRequest;
    hash: string;
    documentId: string;
    userId: string;
}
const cacheKey = (userId: string, documentId: string, versionId: string) =>
    `docsign.pending.v1/${userId}/${documentId}/${versionId}`;
export function rememberAttempt(attempt: SigningAttempt): void {
    sessionStorage.setItem(cacheKey(attempt.userId, attempt.documentId, attempt.request.version_id), JSON.stringify(attempt));
}
export function forgetAttempt(attempt: SigningAttempt): void {
    try {
        sessionStorage.removeItem(cacheKey(attempt.userId, attempt.documentId, attempt.request.version_id));
    } catch {
        // Keeping stale public context is safe: reopening requires reconciliation, never a new signature.
    }
}
export function restoreAttempt(userId: string, documentId: string, versionId: string): SigningAttempt | null {
    const raw = sessionStorage.getItem(cacheKey(userId, documentId, versionId));
    if (!raw) return null;
    const attempt: SigningAttempt = JSON.parse(raw);
    validateSignedManifest(attempt.request.manifest);
    if (attempt.userId !== userId || attempt.documentId !== documentId || attempt.request.version_id !== versionId || attempt.request.manifest.document_version_id !== versionId || attempt.request.key_id !== attempt.request.manifest.key_id || !/^[a-f0-9]{64}$/.test(attempt.hash) || !/^[A-Za-z0-9+/]{512}$/.test(attempt.request.signature_b64)) throw new Error('Context khôi phục không hợp lệ; cần kiểm tra trạng thái phiên bản trên server');
    return attempt;
}
