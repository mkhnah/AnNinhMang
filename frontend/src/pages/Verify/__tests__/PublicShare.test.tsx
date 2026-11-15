import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { PublicShare } from '../PublicShare';
import { sharesApi, PublicShareResult } from '../../../api/shares';

vi.mock('../../../api/shares', () => ({
  sharesApi: {
    publicVerify: vi.fn(),
  },
}));

const TOKEN_A = '123456789012345678901234567890123456789012A';
const TOKEN_B = '123456789012345678901234567890123456789012B';
const TOKEN_C = '123456789012345678901234567890123456789012C';

const mockValidResult: PublicShareResult = {
  title: 'BaoCaoTaiChinh.pdf',
  version_no: 1,
  original_filename: 'BaoCaoTaiChinh.pdf',
  expires_at: '2026-12-01T00:00:00.000Z',
  verified_at: '2026-11-15T12:00:00.000Z',
  signer_fingerprint: 'a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef',
  results: {
    summary_status: 'VERIFIED',
    evidence_consistency: 'CONSISTENT',
    results: {
      cryptographic_validity: 'VALID',
      document_integrity: 'UNCHANGED',
      key_ownership: 'VERIFIED_POP',
      certificate_trust: 'SELF_REGISTERED',
      key_revocation_status: 'ACTIVE',
      declared_timestamp: '2026-11-15T10:00:00.000Z',
      verification_time: '2026-11-15T12:00:00.000Z',
      timestamp_trust_level: 'SERVER_RECORDED',
    },
    warnings: ['Khóa tự đăng ký trong hệ thống DocSign'],
    warning_codes: ['KEY_SELF_REGISTERED'],
  },
};

let navigateFn: (to: string) => void;
function NavHelper() {
  const navigate = useNavigate();
  navigateFn = navigate;
  return null;
}

const renderWithToken = (token: string) => {
  return render(
    <MemoryRouter initialEntries={[`/verify/share/${token}`]}>
      <NavHelper />
      <Routes>
        <Route path="/verify/share/:token" element={<PublicShare />} />
      </Routes>
    </MemoryRouter>
  );
};

describe('PublicShare Component Lifecycle & Stale Response Prevention', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state initially', () => {
    vi.mocked(sharesApi.publicVerify).mockReturnValue(new Promise(() => {}));
    renderWithToken(TOKEN_A);
    expect(screen.getByText(/Đang kiểm tra bằng chứng xác minh…/)).toBeInTheDocument();
  });

  it('renders verified 6-dimensional results successfully', async () => {
    vi.mocked(sharesApi.publicVerify).mockResolvedValue(mockValidResult);
    renderWithToken(TOKEN_A);

    await waitFor(() => {
      expect(screen.getByText('BaoCaoTaiChinh.pdf')).toBeInTheDocument();
    });

    expect(screen.getByText(/Chữ ký hợp lệ về mặt mật mã/)).toBeInTheDocument();
    expect(screen.getByText(/Tài liệu không thay đổi/)).toBeInTheDocument();
    expect(screen.getAllByText(/Khóa tự đăng ký/)[0]).toBeInTheDocument();
    expect(screen.getByText(/Khóa hiện đang hoạt động/)).toBeInTheDocument();
    expect(screen.getByText(mockValidResult.signer_fingerprint!)).toBeInTheDocument();

    // Zero PDF leakage check
    expect(screen.queryByRole('button', { name: /Tải PDF/i })).not.toBeInTheDocument();
    expect(screen.getByText(/Zero PDF Leakage/)).toBeInTheDocument();
    expect(screen.getByText('Thời điểm ký khai báo:')).toBeInTheDocument();
    expect(screen.getByText(/chưa được TSA chứng thực/)).toBeInTheDocument();
  });

  it('displays 404 error when token is invalid or revoked', async () => {
    vi.mocked(sharesApi.publicVerify).mockRejectedValue({
      response: { status: 404 },
    });
    renderWithToken(TOKEN_A);

    await waitFor(() => {
      expect(screen.getByText('Không thể xác minh')).toBeInTheDocument();
    });
    expect(
      screen.getByText('Liên kết xác minh không tồn tại hoặc đã bị thu hồi.')
    ).toBeInTheDocument();
  });

  it('displays 410 error when token is expired', async () => {
    vi.mocked(sharesApi.publicVerify).mockRejectedValue({
      response: { status: 410 },
    });
    renderWithToken(TOKEN_A);

    await waitFor(() => {
      expect(screen.getByText('Liên kết xác minh này đã hết hạn.')).toBeInTheDocument();
    });
  });

  it('discards stale response A when navigated to token B and response B finishes first (FIX-P6-03)', async () => {
    let resolveA!: (val: PublicShareResult) => void;
    let resolveB!: (val: PublicShareResult) => void;

    vi.mocked(sharesApi.publicVerify).mockImplementation((token: string) => {
      if (token === TOKEN_A) {
        return new Promise<PublicShareResult>((resolve) => {
          resolveA = resolve;
        });
      }
      return new Promise<PublicShareResult>((resolve) => {
        resolveB = resolve;
      });
    });

    renderWithToken(TOKEN_A);

    // Navigate to token B using React Router navigation
    act(() => {
      navigateFn(`/verify/share/${TOKEN_B}`);
    });

    // Response B completes first
    const resultB = { ...mockValidResult, title: 'DocumentB.pdf' };
    await act(async () => {
      resolveB(resultB);
    });

    await waitFor(() => {
      expect(screen.getByText('DocumentB.pdf')).toBeInTheDocument();
    });

    // Response A arrives late
    const resultA = { ...mockValidResult, title: 'DocumentA.pdf' };
    await act(async () => {
      resolveA(resultA);
    });

    // Verify DocumentA does NOT overwrite DocumentB
    expect(screen.getByText('DocumentB.pdf')).toBeInTheDocument();
    expect(screen.queryByText('DocumentA.pdf')).not.toBeInTheDocument();
  });

  it('aborts ongoing network request on component unmount', () => {
    let capturedSignal: AbortSignal | undefined;
    vi.mocked(sharesApi.publicVerify).mockImplementation((_, signal) => {
      capturedSignal = signal;
      return new Promise(() => {});
    });

    const { unmount } = renderWithToken(TOKEN_C);
    expect(capturedSignal?.aborted).toBe(false);

    unmount();
    expect(capturedSignal?.aborted).toBe(true);
  });
});

describe('Explicit verification states', () => {
  it.each([
    ['cryptographic_validity', 'INVALID', 'Chữ ký không hợp lệ'],
    ['cryptographic_validity', 'UNVERIFIABLE', 'Chưa đủ bằng chứng để xác minh'],
    ['document_integrity', 'TAMPERED', 'Tài liệu bị thay đổi'],
    ['document_integrity', 'UNKNOWN', 'Chưa xác định được tính toàn vẹn'],
    ['key_revocation_status', 'REVOKED', 'Khóa đã bị thu hồi'],
    ['key_revocation_status', 'UNKNOWN', 'Chưa xác định được trạng thái khóa'],
  ])('maps %s=%s without inventing negative evidence', async (field, value, label) => {
    vi.mocked(sharesApi.publicVerify).mockResolvedValue({
      ...mockValidResult,
      results: { ...mockValidResult.results, summary_status: 'VERIFIED',
        results: {...mockValidResult.results.results, [field]: value} },
    } as PublicShareResult);
    renderWithToken(TOKEN_A);
    expect(await screen.findByText(label)).toBeInTheDocument();
    expect(screen.queryByText('Tài liệu nguyên bản và chữ ký số hợp lệ theo bằng chứng máy chủ')).not.toBeInTheDocument();
  });
  it.each(['INCONSISTENT', 'NOT_APPLICABLE'])('shows evidence %s without overall success', async state => {
    vi.mocked(sharesApi.publicVerify).mockResolvedValue({...mockValidResult,
      results: {...mockValidResult.results, evidence_consistency: state}});
    renderWithToken(TOKEN_A);
    expect(await screen.findByText(state === 'INCONSISTENT' ? 'Bằng chứng không nhất quán' : 'Chưa đủ bằng chứng')).toBeInTheDocument();
    expect(screen.queryByText('Tài liệu nguyên bản và chữ ký số hợp lệ theo bằng chứng máy chủ')).not.toBeInTheDocument();
  });
});
