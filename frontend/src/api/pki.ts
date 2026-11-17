import api from './client';
import { CertificateDto, IdentityReview, PkiResult, Authority } from '../types/pki';
export const pkiApi = {
    certificatesForKey: async (keyId: string) => (await api.get<{items:CertificateDto[]}>('/certificates/me', {params:{key_id:keyId,limit:100}})).data.items,
    certificates: async (admin = false, offset = 0, userId = '') => (await api.get<{ items: CertificateDto[]; total: number }>(
        admin ? '/admin/pki/certificates' : '/certificates/me', { params: { limit: 20, offset, ...(userId ? {user_id: userId} : {}) } })).data,
    challenge: async (keyId: string, certificateId?: string) => (await api.post<{challenge_id: string; payload: Record<string, string | number | null>}>(
        '/certificates/challenge', {key_id: keyId, purpose: certificateId ? 'RENEW_CERT' : 'ISSUE_CERT', certificate_id: certificateId || null})).data,
    issue: async (path: string, body: unknown) => (await api.post<CertificateDto>(path, body)).data,
    revoke: async (id: string, reason: string) => (await api.post<CertificateDto>(`/certificates/${id}/revoke`, {reason})).data,
    download: async (id: string) => (await api.get<string>(`/certificates/${id}/download`)).data,
    verifyCertificate: async (pem: string, signal?: AbortSignal) => (await api.post<PkiResult>('/verify/certificate', {certificate_pem: pem}, {signal})).data,
    verifySignature: async (pem: string, signaturePackage: string, signal?: AbortSignal) => (await api.post<PkiResult>(
        '/verify/signature', {certificate_pem: pem, signature_package: signaturePackage}, {signal})).data,
    reviews: async (admin = false, offset = 0) => (await api.get<IdentityReview[]>(admin ? '/admin/pki/identity-requests' : '/pki/identity-requests', {params: {offset, limit: 20}})).data,
    requestReview: async (fullName: string, reference: string) => (await api.post('/pki/identity-requests', {full_name: fullName, evidence_reference: reference})).data,
    decide: async (id: string, status: string, reason: string) => (await api.post(`/admin/pki/identity-requests/${id}/decision`, {status, reason})).data,
    authorities: async () => (await api.get<Authority[]>('/admin/pki/authorities')).data,
    readiness: async () => (await api.get<{enabled: boolean; ready: boolean; subject?: string; fingerprint?: string; code: string}>('/admin/pki/status')).data,
    updateAuthority: async (id: string, trust: string, enabled: boolean) => (await api.post(`/admin/pki/authorities/${id}`, {trust_status: trust, issuance_enabled: enabled})).data,
    possessionChallenge: async (certificateId: string) => (await api.post<{challenge_id: string; payload: Record<string, string>}>('/pki/possession/challenge', {certificate_id: certificateId})).data,
    possessionVerify: async (id: string, signature: string) => (await api.post<PkiResult>('/pki/possession/verify', {challenge_id: id, signature_b64: signature})).data,
};
