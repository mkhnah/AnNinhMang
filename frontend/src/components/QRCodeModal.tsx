import { useRef, useState } from 'react';
import { QRCodeCanvas } from 'qrcode.react';
import { Check, Copy, Download, X } from 'lucide-react';
import type { ShareLink } from '../api/shares';

const formatDate = (value: string) => {
  try {
    return new Date(value).toLocaleString('vi-VN');
  } catch {
    return value;
  }
};

export function QRCodeModal({ share, onClose }: { share: ShareLink; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState<string>('');
  const inputRef = useRef<HTMLInputElement>(null);

  const copy = async () => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(share.share_url);
        setCopied(true);
        setCopyFeedback('Đã sao chép vào bộ nhớ tạm!');
        window.setTimeout(() => {
          setCopied(false);
          setCopyFeedback('');
        }, 2000);
        return;
      }
      throw new Error('Clipboard API unavailable');
    } catch {
      // Fallback: select input text for manual copy
      if (inputRef.current) {
        inputRef.current.select();
        inputRef.current.setSelectionRange(0, 99999);
        try {
          const success = document.execCommand('copy');
          if (success) {
            setCopied(true);
            setCopyFeedback('Đã sao chép (fallback)!');
            window.setTimeout(() => {
              setCopied(false);
              setCopyFeedback('');
            }, 2000);
            return;
          }
        } catch {
          // Ignore
        }
        setCopyFeedback('Vui lòng nhấn Ctrl+C / Cmd+C để sao chép liên kết.');
      }
    }
  };

  const download = () => {
    const canvas = document.querySelector<HTMLCanvasElement>('#share-qr');
    if (!canvas) return;
    const link = document.createElement('a');
    link.download = `docsign-verification-qr-${share.id.slice(0, 8)}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Mã QR xác minh"
    >
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl border border-slate-100">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-slate-900">Mã QR Xác Minh</h2>
            <p className="mt-1 text-xs text-slate-500">
              Mã QR chứa mã thông báo truy cập công khai. Người quét có thể kiểm tra chữ ký mà không cần tài khoản.
            </p>
          </div>
          <button
            aria-label="Đóng"
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition"
          >
            <X size={20} />
          </button>
        </div>

        {share.label && (
          <div className="mt-3 rounded bg-slate-100 px-3 py-1.5 text-xs text-slate-700 font-medium">
            Nhãn: {share.label}
          </div>
        )}

        <div className="my-5 flex flex-col items-center justify-center">
          <div className="rounded-xl border border-slate-200 p-3 bg-white shadow-sm">
            <QRCodeCanvas id="share-qr" value={share.share_url} size={220} includeMargin />
          </div>
          <span className="mt-2 text-[11px] text-slate-400">Quét mã bằng camera điện thoại để xác minh</span>
        </div>

        <div className="space-y-2">
          <label htmlFor="share-url-input" className="block text-xs font-medium text-slate-700">
            Đường dẫn xác minh trực tiếp:
          </label>
          <div className="flex gap-2">
            <input
              id="share-url-input"
              ref={inputRef}
              type="text"
              readOnly
              value={share.share_url}
              onClick={(e) => (e.target as HTMLInputElement).select()}
              className="w-full rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800 focus:border-slate-800 focus:outline-none"
            />
            <button
              type="button"
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-2 text-xs font-medium text-white hover:bg-slate-800 transition"
              onClick={() => void copy()}
            >
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? 'Đã chép' : 'Sao chép'}
            </button>
          </div>
          {copyFeedback && <p className="text-[11px] text-emerald-600 font-medium">{copyFeedback}</p>}
        </div>

        <div className="mt-3 text-xs text-slate-500">
          Thời hạn: <span className="font-medium text-slate-700">{formatDate(share.expires_at)}</span>
        </div>

        <div className="mt-5 flex justify-end gap-2 border-t border-slate-100 pt-4">
          <button
            type="button"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 transition"
            onClick={download}
          >
            <Download size={14} /> Tải ảnh QR (PNG)
          </button>
          <button
            type="button"
            className="rounded-lg bg-slate-100 px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-200 transition"
            onClick={onClose}
          >
            Đóng
          </button>
        </div>
      </div>
    </div>
  );
}
