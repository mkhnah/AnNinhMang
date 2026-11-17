import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CreateShareModal } from '../CreateShareModal';
import { sharesApi, ShareLink } from '../../../api/shares';

vi.mock('../../../api/shares', () => ({
  sharesApi: {
    create: vi.fn(),
    revoke: vi.fn(),
    list: vi.fn(),
  },
}));

describe('CreateShareModal Component', () => {
  const onClose = vi.fn();
  const onSuccess = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders modal with expiry options and label input', () => {
    render(
      <CreateShareModal
        versionId="test-version-uuid"
        versionNo={1}
        documentTitle="HopDongKinhDoanh.pdf"
        onClose={onClose}
        onSuccess={onSuccess}
      />
    );

    expect(screen.getByText('Tạo liên kết chia sẻ')).toBeInTheDocument();
    expect(screen.getByText(/HopDongKinhDoanh.pdf/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Thời hạn hiệu lực:/i)).toBeInTheDocument();
    expect(screen.getByLabelText('Nhãn liên kết')).toBeInTheDocument();
  });

  it('submits form with selected expiry and custom label', async () => {
    const mockCreatedShare: ShareLink = {
      id: 'new-share-123',
      version_id: 'test-version-uuid',
      share_url: 'http://localhost:5173/verify/share/new_token_43_chars_length_valid_for_test_123',
      expires_at: '2026-11-22T00:00:00.000Z',
      label: 'Gửi đối tác ký',
    };
    vi.mocked(sharesApi.create).mockResolvedValue(mockCreatedShare);

    render(
      <CreateShareModal
        versionId="test-version-uuid"
        versionNo={1}
        documentTitle="HopDongKinhDoanh.pdf"
        onClose={onClose}
        onSuccess={onSuccess}
      />
    );

    // Select 14 days
    fireEvent.change(screen.getByLabelText(/Thời hạn hiệu lực:/i), {
      target: { value: '14' },
    });

    // Enter label
    fireEvent.change(screen.getByLabelText('Nhãn liên kết'), {
      target: { value: 'Gửi đối tác ký' },
    });

    // Submit
    fireEvent.click(screen.getByRole('button', { name: 'Tạo mã QR' }));

    await waitFor(() => {
      expect(sharesApi.create).toHaveBeenCalledWith('test-version-uuid', 14, 'Gửi đối tác ký');
    });

    expect(onSuccess).toHaveBeenCalledWith(mockCreatedShare);
  });

  it('displays error message when creation fails', async () => {
    vi.mocked(sharesApi.create).mockRejectedValue({
      response: {
        status: 422,
        data: { detail: 'Chính sách phát hành: Khóa ký đã bị thu hồi' },
      },
    });

    render(
      <CreateShareModal
        versionId="test-version-uuid"
        versionNo={1}
        documentTitle="HopDongKinhDoanh.pdf"
        onClose={onClose}
        onSuccess={onSuccess}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: 'Tạo mã QR' }));

    await waitFor(() => {
      expect(screen.getByText(/Chính sách phát hành: Khóa ký đã bị thu hồi/)).toBeInTheDocument();
    });
    expect(onSuccess).not.toHaveBeenCalled();
  });
});
