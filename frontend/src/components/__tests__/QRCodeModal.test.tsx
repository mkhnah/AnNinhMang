import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { QRCodeModal } from '../QRCodeModal';
import { ShareLink } from '../../api/shares';

// Mock canvas methods for jsdom
beforeEach(() => {
  HTMLCanvasElement.prototype.getContext = vi.fn().mockReturnValue({
    fillRect: vi.fn(),
    clearRect: vi.fn(),
    getImageData: vi.fn(() => ({ data: new Array(4) })),
    putImageData: vi.fn(),
    createImageData: vi.fn(() => []),
    setTransform: vi.fn(),
    drawImage: vi.fn(),
    save: vi.fn(),
    fillText: vi.fn(),
    restore: vi.fn(),
    beginPath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    closePath: vi.fn(),
    stroke: vi.fn(),
    translate: vi.fn(),
    scale: vi.fn(),
    rotate: vi.fn(),
    arc: vi.fn(),
    fill: vi.fn(),
    measureText: vi.fn(() => ({ width: 0 })),
    transform: vi.fn(),
    rect: vi.fn(),
    clip: vi.fn(),
  }) as any;
  HTMLCanvasElement.prototype.toDataURL = vi.fn().mockReturnValue('data:image/png;base64,mockPngData');
});

const mockShare: ShareLink = {
  id: 'test-share-id-1234',
  version_id: 'test-version-id-5678',
  share_url: 'http://localhost:5173/verify/share/dummy_token_43_chars_for_qr_code_rendering_ok',
  expires_at: '2026-12-01T00:00:00.000Z',
  label: 'Báo cáo Kiểm toán 2026',
};

describe('QRCodeModal Component', () => {
  const onClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders modal with share url, QR code canvas, and label', () => {
    render(<QRCodeModal share={mockShare} onClose={onClose} />);

    expect(screen.getByRole('dialog', { name: 'Mã QR xác minh' })).toBeInTheDocument();
    expect(screen.getByText('Mã QR Xác Minh')).toBeInTheDocument();
    expect(screen.getByText('Nhãn: Báo cáo Kiểm toán 2026')).toBeInTheDocument();

    const input = screen.getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe(mockShare.share_url);

    // Close button
    fireEvent.click(screen.getAllByRole('button', { name: 'Đóng' })[0]);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('copies share url using navigator.clipboard when available', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    });

    render(<QRCodeModal share={mockShare} onClose={onClose} />);

    const copyBtn = screen.getByRole('button', { name: /Sao chép/i });
    fireEvent.click(copyBtn);

    expect(writeTextMock).toHaveBeenCalledWith(mockShare.share_url);
    expect(await screen.findByText('Đã sao chép vào bộ nhớ tạm!')).toBeInTheDocument();
  });

  it('handles clipboard failure gracefully with manual fallback instructions', async () => {
    Object.assign(navigator, {
      clipboard: undefined,
    });
    document.execCommand = vi.fn().mockReturnValue(false);

    render(<QRCodeModal share={mockShare} onClose={onClose} />);

    const copyBtn = screen.getByRole('button', { name: /Sao chép/i });
    fireEvent.click(copyBtn);

    expect(
      await screen.findByText(/Vui lòng nhấn Ctrl\+C \/ Cmd\+C để sao chép liên kết/i)
    ).toBeInTheDocument();
  });

  it('triggers QR PNG image download', () => {
    render(<QRCodeModal share={mockShare} onClose={onClose} />);

    const downloadBtn = screen.getByRole('button', { name: /Tải ảnh QR \(PNG\)/i });
    expect(downloadBtn).toBeInTheDocument();
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    fireEvent.click(downloadBtn);
    expect(HTMLCanvasElement.prototype.toDataURL).toHaveBeenCalledWith('image/png');
    expect(click).toHaveBeenCalledOnce();
    const anchor = click.mock.instances[0] as HTMLAnchorElement;
    expect(anchor.download).toMatch(/\.png$/);
    expect(anchor.href).toBe('data:image/png;base64,mockPngData');
    click.mockRestore();
  });
});
