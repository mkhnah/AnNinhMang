import { SignedManifest } from '../types/signature';
import { StoredKeyRecord } from './keyStorage';
import { computeFingerprint, exportSpkiDer } from './spki';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hex = /^[0-9a-f]{64}$/;
const fields = ['manifest_version', 'document_version_id', 'document_sha256', 'key_id', 'signer_fingerprint', 'algorithm', 'signing_nonce', 'signing_timestamp', 'signing_context'];
export function validateSignedManifest(value: unknown): asserts value is SignedManifest {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Manifest không hợp lệ');
    const m = value as Record<string, unknown>;
    if (Object.keys(m).length !== fields.length || fields.some(f => !Object.prototype.hasOwnProperty.call(m, f))) throw new Error('Manifest thiếu hoặc thừa trường');
    if (m.manifest_version !== 1 || m.algorithm !== 'RSA-PSS-3072' || m.signing_context !== 'DOCSIGN_DOCUMENT_SIGNATURE_V1') throw new Error('Manifest version, algorithm hoặc context không hợp lệ');
    for (const f of ['document_version_id', 'key_id']) if (typeof m[f] !== 'string' || !uuid.test(m[f])) throw new Error('UUID không hợp lệ');
    for (const f of ['document_sha256', 'signer_fingerprint']) if (typeof m[f] !== 'string' || !hex.test(m[f])) throw new Error('SHA-256 không hợp lệ');
    if (typeof m.signing_nonce !== 'string' || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(m.signing_nonce)) throw new Error('Nonce không hợp lệ');
    const t = m.signing_timestamp;
    if (typeof t !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(t) || !Number.isFinite(Date.parse(t)) || new Date(t).toISOString() !== t) throw new Error('Timestamp UTC không hợp lệ');
}

export interface ManifestSelection {
    versionId: string;
    metadataHash: string;
    previewHash: string;
    keyId: string;
    fingerprint: string;
    userId: string;
}
export async function validateManifestBinding(manifest: SignedManifest, selection: ManifestSelection, record: StoredKeyRecord): Promise<void> {
    validateSignedManifest(manifest);
    if (!hex.test(selection.previewHash) || manifest.document_version_id !== selection.versionId || manifest.document_sha256 !== selection.previewHash || manifest.document_sha256 !== selection.metadataHash || manifest.key_id !== selection.keyId || manifest.signer_fingerprint !== selection.fingerprint || record.userId !== selection.userId || record.fingerprint !== selection.fingerprint || record.algorithm !== 'RSA-PSS-3072') throw new Error('Manifest không khớp PDF hoặc khóa đã chọn');
    const alg = record.publicKey.algorithm as RsaHashedKeyAlgorithm;
    if (record.publicKey.type !== 'public' || alg.name !== 'RSA-PSS' || alg.modulusLength !== 3072 || alg.hash.name !== 'SHA-256') throw new Error('Public Key không hợp lệ');
    const actual = await computeFingerprint(await exportSpkiDer(record.publicKey));
    if (actual !== manifest.signer_fingerprint) throw new Error('Fingerprint Public Key không khớp');
}
