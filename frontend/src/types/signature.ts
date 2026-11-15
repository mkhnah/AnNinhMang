export interface SignedManifest {
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

export interface PrepareSignResponse {
    manifest: SignedManifest;
    manifest_sha256: string;
    expires_at: string;
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
