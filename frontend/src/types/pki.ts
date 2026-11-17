export interface CertificateDto {
    id: string; key_id: string; user_id: string; ca_id: string; serial: string;
    fingerprint: string; certificate_pem: string; subject: string;
    not_before: string; not_after: string; issued_at: string;
    revoked_at: string | null; revocation_reason: string | null; status: string;
    identity_assurance: 'ACCOUNT_BOUND' | 'ADMIN_REVIEWED'; reviewed_at?: string | null;
}
export interface IdentityReview {
    id: string; user_id: string; claims: { full_name: string; evidence_reference: string };
    status: 'PENDING' | 'APPROVED' | 'REJECTED'; reason: string | null;
    reviewer_id: string | null; reviewed_at: string | null; created_at: string;
}
export interface PkiResult {
    verified: boolean; certificate_binding: string; certificate_chain: string;
    certificate_validity: string; certificate_revocation: string; identity_binding: string;
    identity_assurance: string; trust_scope: string; fingerprint: string | null;
    subject: string | null; issuer: string | null; not_before: string | null; not_after: string | null;
    user_id: string | null; checked_at: string; revocation_source: string;
    cryptographic_validity?: string; purpose?: string; possession?: string; possession_verified_at?: string;
    message_sha256?: string;
    serial?: string | null;
    document_integrity?: string;
    warnings?: string[];
    timestamp_status?: string;
    timestamp_trust?: string;
    trusted_timestamp?: string | null;
    timestamp_authority?: string | null;
    timestamp_scope?: string | null;
}
export interface Authority {
    id: string; fingerprint: string; subject: string; not_after: string;
    issuance_enabled: boolean; trust_status: 'TRUSTED' | 'RETIRED' | 'COMPROMISED';
}
