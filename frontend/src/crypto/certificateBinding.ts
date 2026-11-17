import 'reflect-metadata';
import { X509Certificate, SubjectAlternativeNameExtension } from '@peculiar/x509';
import { SignedManifest } from '../types/signature';
import { computeFingerprint } from './spki';

export async function validateCertificateBinding(manifest: SignedManifest, pem: string, issuerPem: string, userId: string): Promise<void> {
    if (manifest.manifest_version !== 2) throw new Error('Cần manifest v2 có chứng chỉ');
    if (pem.length > 16384 || issuerPem.length > 16384) throw new Error('Chứng chỉ vượt giới hạn');
    const cert = new X509Certificate(pem);
    const issuer = new X509Certificate(issuerPem);
    const fingerprint = await computeFingerprint(new Uint8Array(cert.rawData));
    const spkiFingerprint = await computeFingerprint(new Uint8Array(cert.publicKey.rawData));
    const san = cert.getExtension(SubjectAlternativeNameExtension);
    const expectedUri = /^[a-f0-9]{8}-/.test(userId) ? `urn:uuid:${userId}` : `https://docsign.invalid/accounts/${encodeURIComponent(userId)}`;
    const names = san?.names.items;
    if (fingerprint !== manifest.certificate_sha256 || spkiFingerprint !== manifest.signer_fingerprint || manifest.signer_user_id !== userId
        || names?.length !== 1 || names[0].value !== expectedUri) throw new Error('Chứng chỉ không khớp khóa hoặc danh tính trong manifest');
    const now = Date.now();
    if (now < cert.notBefore.getTime() || now >= cert.notAfter.getTime() || now < issuer.notBefore.getTime() || now >= issuer.notAfter.getTime()) throw new Error('Chứng chỉ chưa hiệu lực hoặc đã hết hạn');
    if (!await cert.verify({publicKey: issuer})) throw new Error('Chữ ký CA trên chứng chỉ không hợp lệ');
}
