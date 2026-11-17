export interface SignedManifestV1 {
    manifest_version: 1;
    document_version_id: string;
    document_sha256: string;
    key_id: string;
    signer_fingerprint: string;
    algorithm: 'RSA-PSS-3072' | 'ECDSA-P256';
    signing_nonce: string;
    signing_timestamp: string;
    signing_context: 'DOCSIGN_DOCUMENT_SIGNATURE_V1';
}

export interface SignedManifestV2 extends Omit<SignedManifestV1, 'manifest_version' | 'signing_context'> {
    manifest_version: 2;
    signing_context: 'DOCSIGN_DOCUMENT_SIGNATURE_V2';
    signer_user_id: string;
    certificate_sha256: string;
}
export type SignedManifest = SignedManifestV1 | SignedManifestV2;

export interface PrepareSignResponse {
    manifest: SignedManifest;
    manifest_sha256: string;
    expires_at: string;
    certificate_pem?: string | null;
    issuer_certificate_pem?: string | null;
}

export interface SignatureSubmitRequest {
    version_id: string;
    key_id: string;
    manifest: SignedManifest;
    signature_b64: string;
}

export interface SignatureDto {
    id: string;
    version_id: string;
    signer_id: string;
    key_id: string;
    algorithm: string;
    manifest_sha256: string;
    signature_b64: string;
    signature_format: string;
    signed_at: string;
    created_at: string;
}
