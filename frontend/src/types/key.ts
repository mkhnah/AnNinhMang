export interface PublicKeyDto {
    id: string;
    algorithm: string;
    fingerprint: string;
    status: 'ACTIVE' | 'REVOKED';
    created_at: string;
    revoked_at?: string | null;
    spki_pem?: string | null;
}

export interface ChallengeResponseDto {
    challenge_id: string;
    challenge_nonce: string;
    expires_at: string;
    purpose: string;
    expected_algorithm: string;
    expected_fingerprint?: string | null;
}

export interface KeyRegisterRequestDto {
    public_key_pem: string;
    algorithm: string;
    challenge_id: string;
    pop_signature_b64: string;
}
