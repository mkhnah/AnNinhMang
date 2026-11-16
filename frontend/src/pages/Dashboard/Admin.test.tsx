import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { Audit } from '../Audit';
import { Dashboard } from './index';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { auditApi, AuditEntry, AuditPage, ChainResult, DashboardStats } from '../../api/audit';

vi.mock('../../api/audit', async importOriginal => ({
  ...await importOriginal<typeof import('../../api/audit')>(),
  auditApi: { stats: vi.fn(), logs: vi.fn(), verifyChain: vi.fn() },
}));
const auth = vi.hoisted(() => ({ user: { role: 'ADMIN' } as { role: string } | null, loading: false }));
vi.mock('../../context/AuthContext', () => ({ useAuth: () => auth }));

const chain: ChainResult = { valid: true, checked_entries: 8, error_id: null, reason: null, verified_at: '2026-11-16T07:00:00Z' };
const stats: DashboardStats = {
  generated_at: '2026-11-16T07:00:00Z', total_documents: 10, total_versions: 12, signed_versions: 8,
  active_keys: 4, verification_since: '2026-10-17T07:00:00Z', verification_total: 3,
  verification_success_rate: 0, verification_counts: [{ status: 'UNVERIFIABLE', count: 3 }],
  verification_daily: [{ date: '2026-11-16', verified: 0, unsuccessful: 3 }],
  alert_window_minutes: 15, verification_failure_threshold: 3, alert_total: 1,
  alerts: [{ code: 'REPEATED_VERIFICATION_FAILURE', actor_id: null, client_ip: '127.0.0.10', count: 3,
    first_at: '2026-11-16T06:59:00Z', last_at: '2026-11-16T07:00:00Z' }],
};

function page(offset = 0): AuditPage {
  const item: AuditEntry = { id: String(40 - offset), prev_hash: 'a'.repeat(64), entry_hash: 'b'.repeat(64),
    actor_id: 'actor-one', action: 'DOCUMENT_SIGN', target_type: 'VERSION', target_id: 'version-one',
    client_ip: '127.0.0.1', user_agent: 'Firefox', status: 'SUCCESS', details: {}, details_valid: true,
    created_at: '2026-11-16T07:00:00Z' };
  return { items: [item], total: 40, offset, limit: 20, snapshot_id: '40' };
}

function showDashboard() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>);
}

function showAudit(path = '/admin/audit') {
  return render(<MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/admin/audit" element={<Audit />} />
  </Routes></MemoryRouter>);
}

beforeEach(() => {
  vi.clearAllMocks();
  auth.user = { role: 'ADMIN' };
  vi.mocked(auditApi.stats).mockResolvedValue(stats);
  vi.mocked(auditApi.verifyChain).mockResolvedValue(chain);
  vi.mocked(auditApi.logs).mockImplementation(async params => page(params.offset));
});

describe('Security dashboard', () => {
  it('shows metrics, chain verification and a scoped alert link', async () => {
    showDashboard();
    expect(await screen.findByText('AUDIT LOG INTACT')).toBeInTheDocument();
    expect(screen.getByText('3 lần xác minh gần nhất liên tiếp chưa thành công')).toBeInTheDocument();
    expect(screen.getByText('Chưa thể xác minh')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Tra cứu sự kiện' });
    expect(link.getAttribute('href')).toContain('client_ip=127.0.0.10');
    expect(screen.getByRole('img', { name: 'Biểu đồ lượt xác minh theo ngày' })).toBeInTheDocument();
  });

  it('shows an unknown chain on fetch failure and supports retry', async () => {
    vi.mocked(auditApi.verifyChain).mockRejectedValueOnce(new Error('offline'));
    showDashboard();
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể kiểm tra chuỗi băm');
    expect(screen.queryByText('AUDIT LOG INTACT')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Làm mới' }));
    expect(await screen.findByText('AUDIT LOG INTACT')).toBeInTheDocument();
  });

  it('reports a corrupt chain with the first error ID', async () => {
    vi.mocked(auditApi.verifyChain).mockResolvedValue({ ...chain, valid: false, error_id: '5', reason: 'ENTRY_HASH_MISMATCH' });
    showDashboard();
    expect(await screen.findByText('Phát hiện bất thường trong chuỗi băm')).toBeInTheDocument();
    expect(screen.getByText(/Vị trí lỗi 5/)).toBeInTheDocument();
    expect(screen.queryByText('AUDIT LOG INTACT')).not.toBeInTheDocument();
  });

  it('discards a late response after unmounting', async () => {
    let resolve!: (data: DashboardStats) => void;
    vi.mocked(auditApi.stats).mockReturnValue(new Promise(done => { resolve = done; }));
    const view = showDashboard();
    const signal = vi.mocked(auditApi.stats).mock.calls[0][0];
    view.unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => resolve(stats));
    expect(screen.queryByText('3 lần xác minh gần nhất liên tiếp chưa thành công')).not.toBeInTheDocument();
  });

  it('refreshes automatically and clears old alerts', async () => {
    vi.useFakeTimers();
    try {
      showDashboard();
      await act(async () => {});
      expect(screen.getByText('3 lần xác minh gần nhất liên tiếp chưa thành công')).toBeInTheDocument();
      vi.mocked(auditApi.stats).mockResolvedValue({ ...stats, alerts: [], alert_total: 0 });
      await act(async () => { vi.advanceTimersByTime(30_000); });
      expect(auditApi.stats).toHaveBeenCalledTimes(2);
      expect(screen.getByText('Chưa ghi nhận cảnh báo trong khoảng thời gian này.')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Audit browser', () => {
  it('shows full hashes and uses the snapshot for subsequent pages', async () => {
    showAudit();
    expect(await screen.findByText('b'.repeat(64))).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Trang sau' }));
    await waitFor(() => expect(auditApi.logs).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20, snapshot_id: '40' }), expect.any(AbortSignal)));
    expect(await screen.findByText('21–40 / 40 sự kiện')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Làm mới' }));
    await waitFor(() => expect(auditApi.logs).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0, snapshot_id: undefined }), expect.any(AbortSignal)));
  });

  it('loads deep-link filters and applies a new filter at page one', async () => {
    showAudit('/admin/audit?action=DOCUMENT_VERIFY&client_ip=127.0.0.10');
    await screen.findByText('b'.repeat(64));
    expect(auditApi.logs).toHaveBeenCalledWith(expect.objectContaining({ action: 'DOCUMENT_VERIFY', client_ip: '127.0.0.10' }), expect.any(AbortSignal));
    fireEvent.change(screen.getByLabelText('Sự kiện'), { target: { value: 'ACCESS_DENIED_IDOR' } });
    fireEvent.click(screen.getByRole('button', { name: 'Tra cứu' }));
    await waitFor(() => expect(auditApi.logs).toHaveBeenLastCalledWith(expect.objectContaining({ action: 'ACCESS_DENIED_IDOR', offset: 0, snapshot_id: undefined }), expect.any(AbortSignal)));
  });

  it('retries a failed page without silently showing an empty result', async () => {
    vi.mocked(auditApi.logs).mockRejectedValueOnce(new Error('offline'));
    showAudit();
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể tải nhật ký');
    expect(screen.queryByText('Không có sự kiện phù hợp với bộ lọc.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Thử lại' }));
    expect(await screen.findByText('b'.repeat(64))).toBeInTheDocument();
  });

  it('discards a stale page when filters change', async () => {
    let resolve!: (data: AuditPage) => void;
    vi.mocked(auditApi.logs).mockReturnValueOnce(new Promise(done => { resolve = done; }));
    showAudit();
    const signal = vi.mocked(auditApi.logs).mock.calls[0][1];
    fireEvent.change(screen.getByLabelText('Sự kiện'), { target: { value: 'KEY_REVOKE' } });
    fireEvent.click(screen.getByRole('button', { name: 'Tra cứu' }));
    await screen.findByText('b'.repeat(64));
    expect(signal.aborted).toBe(true);
    await act(async () => resolve({ ...page(), items: [{ ...page().items[0], id: 'stale-row' }] }));
    expect(screen.queryByText('stale-row')).not.toBeInTheDocument();
  });

  it('clears unsaved filters even when the URL already has no filters', async () => {
    showAudit();
    await screen.findByText('b'.repeat(64));
    fireEvent.change(screen.getByLabelText('Mã người thực hiện'), { target: { value: 'unsaved-filter' } });
    fireEvent.click(screen.getByRole('button', { name: 'Xóa bộ lọc' }));
    expect(screen.getByLabelText('Mã người thực hiện')).toHaveValue('');
    await waitFor(() => expect(auditApi.logs).toHaveBeenCalledTimes(2));
    expect(auditApi.logs).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0, snapshot_id: undefined }), expect.any(AbortSignal));
  });
});

it('blocks a USER from mounting the dashboard', async () => {
  auth.user = { role: 'USER' };
  render(<MemoryRouter initialEntries={['/admin/dashboard']}><Routes>
    <Route path="/admin/dashboard" element={<ProtectedRoute requiredRole="ADMIN"><Dashboard /></ProtectedRoute>} />
    <Route path="/forbidden" element={<p>Access forbidden</p>} />
  </Routes></MemoryRouter>);
  expect(await screen.findByText('Access forbidden')).toBeInTheDocument();
  expect(auditApi.stats).not.toHaveBeenCalled();
});
