import { useState } from 'react';
import { QrCode, X } from 'lucide-react';
import { ShareLink, sharesApi } from '../../api/shares';
import { errorMessage } from './index';

interface CreateShareModalProps {
  versionId: string;
  versionNo: number;
  documentTitle: string;
  onClose: () => void;
  onSuccess: (share: ShareLink) => void;
}

export function CreateShareModal({
  versionId,
  versionNo,
  documentTitle,
  onClose,
  onSuccess,
}: CreateShareModalProps) {
  const [days, setDays] = useState<number>(7);
  const [label, setLabel] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const share = await sharesApi.create(versionId, days, label);
      onSuccess(share);
    } catch (err: any) {
      setError(await errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Tạo liên kết chia sẻ QR"
    >
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl border border-slate-100">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-2">
            <QrCode className="text-violet-600" size={24} />
            <h2 className="text-lg font-bold text-slate-900">Tạo Mã QR Chia Sẻ</h2>
          </div>
          <button
            aria-label="Đóng"
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition"
          >
            <X size={20} />
          </button>
        </div>

        <p className="mt-2 text-xs text-slate-500">
          Phát hành liên kết công khai cho <strong>{documentTitle}</strong> (Phiên bản {versionNo}).
          Người nhận có thể quét QR để kiểm tra tính toàn vẹn và chữ ký số.
        </p>

        {error && (
          <div className="mt-3 rounded-lg bg-rose-50 p-3 text-xs text-rose-800 border border-rose-200">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label htmlFor="expiry-days" className="block text-xs font-semibold text-slate-700">
              Thời hạn hiệu lực:
            </label>
            <select
              id="expiry-days"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs text-slate-800 focus:border-slate-800 focus:outline-none"
            >
              <option value={1}>1 ngày (Chia sẻ nhanh)</option>
              <option value={7}>7 ngày (Mặc định)</option>
              <option value={14}>14 ngày</option>
              <option value={30}>30 ngày (Tối đa)</option>
            </select>
          </div>

          <div>
            <label htmlFor="share-label" className="block text-xs font-semibold text-slate-700">
              Ghi chú / Nhãn (Tùy chọn):
            </label>
            <input
              id="share-label"
              type="text"
              maxLength={100}
              placeholder="VD: Gửi khách hàng A, Báo cáo Hội đồng..."
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs text-slate-800 placeholder-slate-400 focus:border-slate-800 focus:outline-none"
            />
          </div>

          <div className="rounded-lg bg-slate-50 p-3 text-[11px] text-slate-500">
            Lưu ý: Hệ thống sẽ tự động xác minh lại chữ ký số và tệp PDF trước khi cấp mã thông báo.
            Chỉ những phiên bản toàn vẹn mới được phát hành mã QR.
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              disabled={submitting}
              onClick={onClose}
              className="rounded-lg bg-slate-100 px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-200 transition"
            >
              Hủy
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-4 py-2 text-xs font-medium text-white hover:bg-violet-700 disabled:opacity-50 transition"
            >
              {submitting ? 'Đang tạo…' : 'Tạo mã QR'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
