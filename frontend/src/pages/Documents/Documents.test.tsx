import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { Documents, DocumentDetail, UploadPanel } from './index';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { documentsApi } from '../../api/documents';

const auth = vi.hoisted(() => ({ user: null as null | { role: string }, loading: false }));
vi.mock('../../context/AuthContext', () => ({ useAuth: () => auth }));
vi.mock('../../api/shares', () => ({ sharesApi: { list: vi.fn().mockResolvedValue([]), revoke: vi.fn() } }));
vi.mock('../../api/documents', () => ({ documentsApi: { limits: vi.fn(), list: vi.fn(), detail: vi.fn(), versions: vi.fn(), upload: vi.fn(), download: vi.fn(), ready: vi.fn() } }));
const doc = { id: 'abc', title: '<img src=x onerror=alert(1)>.pdf', visibility: 'PRIVATE', created_at: '2026-11-14T00:00:00Z', updated_at: '2026-11-14T00:00:00Z' };
const version = { id: 'v1', document_id: 'abc', version_no: 1, original_filename: '<script>alert(1)</script>.pdf', file_sha256: 'a'.repeat(64), file_size_bytes: 1000, state: 'DRAFT' as const, created_at: doc.created_at, locked_at: null };
function detail() { return render(<MemoryRouter initialEntries={['/documents/abc']}><Routes><Route path="/documents/:id" element={<DocumentDetail />} /></Routes></MemoryRouter>); }
beforeEach(() => {
  vi.clearAllMocks(); auth.user = null;
  vi.mocked(documentsApi.limits).mockResolvedValue({ max_upload_bytes: 20 * 1024 * 1024 });
  vi.mocked(documentsApi.list).mockResolvedValue({ items: [doc], total: 1 });
  vi.mocked(documentsApi.detail).mockResolvedValue(doc);
  vi.mocked(documentsApi.versions).mockResolvedValue([version]);
});
describe('Documents', () => {
  it('lists owned documents and renders names as text', async () => {
    const { container } = render(<MemoryRouter><Documents /></MemoryRouter>);
    expect(await screen.findByText(doc.title)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
  });
  it('shows empty state', async () => {
    vi.mocked(documentsApi.list).mockResolvedValue({ items: [], total: 0 });
    render(<MemoryRouter><Documents /></MemoryRouter>);
    expect(await screen.findByText('Kho tài liệu đang trống')).toBeInTheDocument();
  });
  it('uploads selected PDF with progress and success', async () => {
    vi.mocked(documentsApi.upload).mockImplementation(async (_, progress) => { progress(60); return version; });
    const success = vi.fn(); render(<UploadPanel onSuccess={success} />);
    fireEvent.change(screen.getByLabelText('Chọn PDF'), { target: { files: [new File(['%PDF-'], 'test.pdf', { type: 'application/pdf' })] } });
    await waitFor(() => expect(success).toHaveBeenCalledOnce());
    expect(screen.getByText('Đã lưu PDF và xác nhận mã SHA-256.')).toBeInTheDocument();
  });
  it('supports drag and drop', async () => {
    vi.mocked(documentsApi.upload).mockResolvedValue(version);
    render(<UploadPanel onSuccess={vi.fn()} />);
    fireEvent.drop(screen.getByRole('button'), { dataTransfer: { files: [new File(['pdf'], 'drop.pdf')] } });
    await waitFor(() => expect(documentsApi.upload).toHaveBeenCalled());
  });
  it('rejects invalid extension', () => {
    render(<UploadPanel onSuccess={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Chọn PDF'), { target: { files: [new File(['bad'], 'bad.exe')] } });
    expect(screen.getByRole('alert')).toHaveTextContent('Chỉ chấp nhận');
    expect(documentsApi.upload).not.toHaveBeenCalled();
  });
  it('rejects files over 20 MB', () => {
    const file = new File(['test'], 'large.pdf'); Object.defineProperty(file, 'size', { value: 21 * 1024 * 1024 });
    render(<UploadPanel onSuccess={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Chọn PDF'), { target: { files: [file] } });
    expect(screen.getByRole('alert')).toHaveTextContent('20 MB');
  });
  it('shows API validation errors', async () => {
    vi.mocked(documentsApi.upload).mockRejectedValue({ response: { status: 400, data: { detail: 'PDF bị từ chối' } } });
    render(<UploadPanel onSuccess={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Chọn PDF'), { target: { files: [new File(['pdf'], 'bad.pdf')] } });
    expect(await screen.findByRole('alert')).toHaveTextContent('PDF bị từ chối');
  });
  it('shows network error and retry', async () => {
    vi.mocked(documentsApi.list).mockRejectedValue(new Error('network'));
    render(<MemoryRouter><Documents /></MemoryRouter>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Kiểm tra mạng');
    expect(screen.getByText('Thử lại')).toBeInTheDocument();
  });
  it('shows version history, hash and safe filename', async () => {
    const { container } = detail();
    expect(await screen.findByText('Phiên bản 1')).toBeInTheDocument();
    expect(screen.getByText(version.file_sha256)).toBeInTheDocument();
    expect(screen.getByText(version.original_filename)).toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull();
  });
  it('downloads using authenticated API', async () => {
    detail(); fireEvent.click(await screen.findByText('Tải PDF'));
    await waitFor(() => expect(documentsApi.download).toHaveBeenCalledWith('abc', version));
  });
  it('copies SHA-256', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined); Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    detail(); fireEvent.click(await screen.findByLabelText('Sao chép SHA-256 phiên bản 1'));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(version.file_sha256));
  });
  it('locks draft version', async () => {
    detail(); fireEvent.click(await screen.findByText('Khóa để chuẩn bị ký'));
    await waitFor(() => expect(documentsApi.ready).toHaveBeenCalledWith('abc', 'v1'));
  });
  it('redirects unauthenticated document routes', async () => {
    render(<MemoryRouter initialEntries={['/documents']}><Routes><Route path="/documents" element={<ProtectedRoute><Documents /></ProtectedRoute>} /><Route path="/login" element={<p>Login page</p>} /></Routes></MemoryRouter>);
    expect(await screen.findByText('Login page')).toBeInTheDocument();
    expect(documentsApi.list).not.toHaveBeenCalled();
  });
});
