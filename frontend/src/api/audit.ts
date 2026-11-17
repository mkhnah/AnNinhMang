import api from './client';

export const auditActions = [
  'USER_LOGIN', 'KEY_GENERATE', 'KEY_REVOKE', 'DOCUMENT_UPLOAD', 'DOCUMENT_SIGN',
  'DOCUMENT_VERIFY', 'SHARE_QR', 'SHARE_REVOKE', 'ACCESS_DENIED_IDOR', 'ACCESS_DENIED_ROLE',
  'CERTIFICATE_ISSUE', 'CERTIFICATE_RENEW', 'CERTIFICATE_REVOKE', 'CERTIFICATE_VERIFY', 'IDENTITY_REVIEW', 'CA_ROTATE', 'CA_COMPROMISED',
] as const;

export const actionLabels: Record<string, string> = {
  CERTIFICATE_ISSUE:'Cấp chứng chỉ', CERTIFICATE_RENEW:'Gia hạn chứng chỉ', CERTIFICATE_REVOKE:'Thu hồi chứng chỉ',
  CERTIFICATE_VERIFY:'Kiểm tra chứng chỉ / sở hữu khóa', IDENTITY_REVIEW:'Đối chiếu danh tính', CA_ROTATE:'Cấu hình phát hành CA', CA_COMPROMISED:'CA bị lộ khóa',
  USER_LOGIN: 'Đăng nhập', KEY_GENERATE: 'Đăng ký khóa', KEY_REVOKE: 'Thu hồi khóa',
  DOCUMENT_UPLOAD: 'Tải lên tài liệu', DOCUMENT_SIGN: 'Ký tài liệu', DOCUMENT_VERIFY: 'Xác minh tài liệu',
  SHARE_QR: 'Tạo chia sẻ QR', SHARE_REVOKE: 'Thu hồi chia sẻ',
  ACCESS_DENIED_IDOR: 'Chặn truy cập tài nguyên', ACCESS_DENIED_ROLE: 'Chặn truy cập theo vai trò',
};

export const verificationLabels: Record<string, string> = {
  VERIFIED: 'Xác minh thành công', INTEGRITY_COMPROMISED: 'Tài liệu bị thay đổi',
  SIGNATURE_INVALID: 'Chữ ký không hợp lệ', REVOKED_KEY: 'Khóa đã thu hồi',
  UNVERIFIABLE: 'Chưa thể xác minh', OTHER: 'Kết quả khác',
};

export interface AuditEntry {
  id: string;
  prev_hash: string;
  entry_hash: string;
  actor_id: string | null;
  action: string;
  target_type: string;
  target_id: string | null;
  client_ip: string | null;
  user_agent: string | null;
  status: string;
  details: Record<string, string | number | null>;
  details_valid: boolean;
  created_at: string;
}

export interface AuditPage {
  items: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
  snapshot_id: string;
}

export interface ChainResult {
  valid: boolean;
  checked_entries: number;
  error_id: string | null;
  reason: string | null;
  verified_at: string;
}

export interface AuditFilters {
  action?: string;
  status?: string;
  actor_id?: string;
  target_id?: string;
  client_ip?: string;
  since?: string;
  until?: string;
}

export interface SecurityAlert {
  code: 'REPEATED_VERIFICATION_FAILURE' | 'REPEATED_CERTIFICATE_FAILURE' | 'IDOR_ATTEMPT' | 'CA_UNTRUSTED' | 'CERTIFICATE_EXPIRING';
  actor_id: string | null;
  client_ip: string | null;
  count: number;
  first_at: string;
  last_at: string;
}

export interface DashboardStats {
  pki_counts?: Record<string, number>;
  generated_at: string;
  total_documents: number;
  total_versions: number;
  signed_versions: number;
  active_keys: number;
  verification_since: string;
  verification_total: number;
  verification_success_rate: number | null;
  verification_counts: { status: string; count: number }[];
  verification_daily: { date: string; verified: number; unsuccessful: number }[];
  alert_window_minutes: number;
  verification_failure_threshold: number;
  alerts: SecurityAlert[];
  alert_total: number;
}

export const auditApi = {
  async logs(params: AuditFilters & { limit: number; offset: number; snapshot_id?: string }, signal: AbortSignal) {
    return (await api.get<AuditPage>('/audit/logs', { params, signal })).data;
  },
  async verifyChain(signal: AbortSignal) {
    return (await api.get<ChainResult>('/audit/verify-chain', { signal })).data;
  },
  async stats(signal: AbortSignal) {
    return (await api.get<DashboardStats>('/dashboard/stats', { signal })).data;
  },
};
