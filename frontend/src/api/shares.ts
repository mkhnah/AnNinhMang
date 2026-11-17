import api from './client';

export interface ShareLink {
  id: string;
  version_id: string;
  share_url: string;
  expires_at: string;
  label: string | null;
}

export interface ShareListItem {
  id: string;
  version_id: string;
  created_at?: string;
  expires_at: string;
  revoked_at: string | null;
  label: string | null;
  status: string; // 'ACTIVE' | 'EXPIRED' | 'REVOKED'
}

export interface PublicShareResult {
  title: string;
  version_no: number;
  original_filename: string;
  expires_at: string;
  verified_at: string;
  signer_fingerprint: string | null;
  results: {
    summary_status: string;
    evidence_consistency: string;
    results: {
      certificate_binding?: string;
      certificate_chain?: string;
      certificate_validity?: string;
      certificate_revocation?: string;
      identity_binding?: string;
      identity_assurance?: string;
      trust_scope?: string;
      cryptographic_validity: string;
      document_integrity: string;
      key_ownership: string;
      certificate_trust: string;
      key_revocation_status: string;
      declared_timestamp: string | null;
      verification_time: string;
      timestamp_trust_level: string;
      trusted_timestamp?: string | null;
      timestamp_status?: string;
      timestamp_scope?: string | null;
    };
    warnings: string[];
    warning_codes: string[];
  };
}

export const sharesApi = {
  create: async (versionId: string, expiresInDays = 7, label?: string) =>
    (
      await api.post<ShareLink>('/shares', {
        version_id: versionId,
        expires_in_days: expiresInDays,
        label: label?.trim() || null,
      })
    ).data,

  revoke: async (shareId: string) => api.delete(`/shares/${shareId}`),

  list: async (documentId?: string, versionId?: string, limit = 20, offset = 0, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    if (documentId) params.append('document_id', documentId);
    if (versionId) params.append('version_id', versionId);
    params.append('limit', limit.toString());
    params.append('offset', offset.toString());
    return (await api.get<ShareListItem[]>(`/shares?${params.toString()}`, { signal })).data;
  },

  publicVerify: async (token: string, signal?: AbortSignal) =>
    (await api.get<PublicShareResult>(`/verify/share/${encodeURIComponent(token)}`, { signal })).data,
};
