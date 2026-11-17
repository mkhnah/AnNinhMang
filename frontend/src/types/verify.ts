import { SignedManifest } from './signature';

export type CryptographicValidity = 'VALID' | 'INVALID' | 'UNVERIFIABLE';
export type DocumentIntegrity = 'UNCHANGED' | 'TAMPERED' | 'UNKNOWN';
export type KeyOwnership = 'VERIFIED_POP' | 'UNVERIFIED' | 'UNKNOWN';
export type CertificateTrust = 'SELF_REGISTERED' | 'TRUSTED_CA' | 'UNKNOWN';
export type KeyRevocationStatus = 'ACTIVE' | 'REVOKED' | 'UNKNOWN';
export type TimestampTrustLevel = 'DECLARED' | 'SERVER_RECORDED' | 'TRUSTED_TSA' | 'UNKNOWN';
export type VerificationMode = 'INTERNAL' | 'INDEPENDENT_DETACHED';
export type VerificationSummaryStatus =
    | 'VERIFIED'
    | 'INTEGRITY_COMPROMISED'
    | 'SIGNATURE_INVALID'
    | 'UNVERIFIABLE'
    | 'REVOKED_KEY';

export interface SixDimensionalResults {
    timestamp_status?: 'ABSENT' | 'VALID' | 'INVALID';
    timestamp_authority?: string | null;
    timestamp_authority_fingerprint?: string | null;
    timestamp_scope?: string | null;
    timestamp_serial?: string | null;
    certificate_binding?: string;
    certificate_chain?: string;
    certificate_validity?: string;
    certificate_revocation?: string;
    identity_binding?: string;
    identity_assurance?: string;
    trust_scope?: string;
    certificate_sha256?: string | null;
    cryptographic_validity: CryptographicValidity;
    document_integrity: DocumentIntegrity;
    key_ownership: KeyOwnership;
    certificate_trust: CertificateTrust;
    key_revocation_status: KeyRevocationStatus;
    revoked_at?: string | null;
    revocation_checked_at?: string | null;
    revocation_source?: string | null;
    declared_timestamp?: string | null;
    server_recorded_at?: string | null;
    server_timestamp?: string | null;
    key_registry_binding?: string;
    verification_time: string;
    trusted_timestamp?: string | null;
    timestamp_trust_level: TimestampTrustLevel;
}

export interface VerificationResultResponse {
    verification_id: string;
    verification_receipt?: string | null;
    receipt_expires_at?: string | null;
    evidence_consistency?: 'CONSISTENT' | 'INCONSISTENT' | 'NOT_APPLICABLE';
    warning_codes?: string[];
    verification_mode: VerificationMode;
    summary_status: VerificationSummaryStatus;
    results: SixDimensionalResults;
    document_version_id?: string | null;
    document_hash_expected: string;
    document_hash_computed: string;
    signer_fingerprint?: string | null;
    key_id?: string | null;
    signature_algorithm: string;
    signature_format: string;
    warnings: string[];
}

export interface SignaturePackage {
    timestamp_token_b64?: string | null;
    certificate_pem?: string;
    issuer_chain_pem?: string[];
    package_version: number;
    signature_format: string;
    manifest: SignedManifest;
    signature_b64: string;
    public_key_spki_pem?: string | null;
    created_at?: string | null;
}

export interface VerificationReportResponse {
    report_version: number;
    report_id: string;
    generated_at: string;
    verification_result: VerificationResultResponse;
    evidence_source: string;
    disclaimer: string;
}
