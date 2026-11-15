import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { AlertTriangle, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { sharesApi, PublicShareResult } from '../../api/shares';

const formatDate = (value: string | null | undefined) => {
  if (!value) return 'Không có';
  try {
    return new Date(value).toLocaleString('vi-VN');
  } catch {
    return value;
  }
};

const cryptoLabels: Record<string, string> = {
  VALID: 'Chữ ký hợp lệ về mặt mật mã', INVALID: 'Chữ ký không hợp lệ',
  UNVERIFIABLE: 'Chưa đủ bằng chứng để xác minh',
};
const integrityLabels: Record<string, string> = {
  UNCHANGED: 'Tài liệu không thay đổi', TAMPERED: 'Tài liệu bị thay đổi',
  UNKNOWN: 'Chưa xác định được tính toàn vẹn',
};
const keyLabels: Record<string, string> = {
  ACTIVE: 'Khóa hiện đang hoạt động', REVOKED: 'Khóa đã bị thu hồi',
  UNKNOWN: 'Chưa xác định được trạng thái khóa',
};
const evidenceLabels: Record<string, string> = {
  CONSISTENT: 'Bằng chứng nhất quán', INCONSISTENT: 'Bằng chứng không nhất quán',
  NOT_APPLICABLE: 'Chưa đủ bằng chứng',
};
function Status({ value, labels }: { value: string; labels: Record<string, string> }) {
  const positive = ['VALID', 'UNCHANGED', 'ACTIVE', 'CONSISTENT'].includes(value);
  const negative = ['INVALID', 'TAMPERED', 'REVOKED', 'INCONSISTENT'].includes(value);
  return <span className={`font-semibold ${positive ? 'text-emerald-700' : negative ? 'text-rose-700' : 'text-amber-700'}`}>
    {labels[value] || 'Chưa đủ bằng chứng'}
  </span>;
}

export function PublicShare() {
  const { token = '' } = useParams();
  const [result, setResult] = useState<PublicShareResult | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);

  const currentTokenRef = useRef<string>(token);
  const requestGenRef = useRef<number>(0);

  useEffect(() => {
    // 1. Snapshot token and increment generation counter
    currentTokenRef.current = token;
    const currentGen = ++requestGenRef.current;

    // 2. Setup AbortController for request cancellation
    const controller = new AbortController();

    // 3. Reset state on token change to prevent stale display
    setResult(null);
    setError('');
    setLoading(true);

    if (!token || token.trim().length !== 43) {
      setError('Mã liên kết xác minh không hợp lệ.');
      setLoading(false);
      return;
    }

    sharesApi
      .publicVerify(token, controller.signal)
      .then((data) => {
        // 4. Verify request generation matches current before state update
        if (currentGen === requestGenRef.current && currentTokenRef.current === token) {
          setResult(data);
          setError('');
          setLoading(false);
        }
      })
      .catch((e: any) => {
        if (controller.signal.aborted) {
          return;
        }
        if (currentGen === requestGenRef.current && currentTokenRef.current === token) {
          const status = e.response?.status;
          if (status === 410) {
            setError('Liên kết xác minh này đã hết hạn.');
          } else if (status === 404) {
            setError('Liên kết xác minh không tồn tại hoặc đã bị thu hồi.');
          } else if (status === 429) {
            setError('Hệ thống đang tiếp nhận nhiều yêu cầu. Vui lòng thử lại sau 1 phút.');
          } else if (status === 503) {
            setError('Hệ thống xác minh đang bận. Vui lòng thử lại sau giây lát.');
          } else {
            setError('Không thể xác minh liên kết chia sẻ này.');
          }
          setResult(null);
          setLoading(false);
        }
      });

    return () => {
      // 5. Cleanup & abort on unmount or token change
      controller.abort();
    };
  }, [token]);

  if (loading) {
    return (
      <div className="mx-auto max-w-xl p-6">
        <div className="rounded-2xl bg-white p-8 text-center shadow-md">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-4 border-slate-200 border-t-slate-800" />
          <h2 className="mt-4 text-lg font-medium text-slate-900">Đang kiểm tra bằng chứng xác minh…</h2>
          <p className="mt-1 text-sm text-slate-500">Đang phân tích tính toàn vẹn và chữ ký số từ máy chủ.</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto max-w-xl p-6">
        <div className="rounded-2xl bg-white p-8 text-center shadow-md">
          <ShieldX className="mx-auto text-rose-600" size={54} />
          <h1 className="mt-4 text-2xl font-semibold text-slate-900">Không thể xác minh</h1>
          <p className="mt-2 text-slate-600">{error}</p>
          <div className="mt-6 rounded-lg bg-slate-50 p-3 text-xs text-slate-500">
            Nếu bạn nhận được liên kết này từ người khác, vui lòng yêu cầu họ phát hành mã QR mới.
          </div>
        </div>
      </div>
    );
  }

  if (!result) return null;

  const dims = result.results.results;
  const isCryptoValid = dims.cryptographic_validity === 'VALID';
  const isDocIntact = dims.document_integrity === 'UNCHANGED';
  const isEvidenceConsistent = result.results.evidence_consistency === 'CONSISTENT';
  const isKeyActive = dims.key_revocation_status === 'ACTIVE';

  const isOverallVerified =
    isCryptoValid && isDocIntact && isEvidenceConsistent && isKeyActive && result.results.summary_status === 'VERIFIED';

  return (
    <div className="mx-auto max-w-xl p-6">
      <div className="rounded-2xl bg-white p-6 shadow-md border border-slate-100">
        {/* Header Status Banner */}
        <div className="flex items-center gap-4 border-b border-slate-100 pb-5">
          {isOverallVerified ? (
            <ShieldCheck className="text-emerald-600 shrink-0" size={48} />
          ) : (
            <ShieldAlert className="text-amber-600 shrink-0" size={48} />
          )}
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Kết quả xác thực điện tử</h1>
            <p className="text-sm text-slate-600 mt-0.5">
              {isOverallVerified
                ? 'Tài liệu nguyên bản và chữ ký số hợp lệ theo bằng chứng máy chủ'
                : 'Chữ ký số có cảnh báo cần lưu ý hoặc bằng chứng chưa hoàn hảo'}
            </p>
          </div>
        </div>

        {/* Document Metadata */}
        <div className="mt-5 rounded-lg bg-slate-50 p-4 text-sm">
          <h2 className="font-semibold text-slate-800">Thông tin tài liệu</h2>
          <div className="mt-2 grid grid-cols-3 gap-2 text-xs">
            <span className="text-slate-500">Tên tài liệu:</span>
            <span className="col-span-2 font-medium text-slate-800">{result.title}</span>
            <span className="text-slate-500">Phiên bản:</span>
            <span className="col-span-2 font-medium text-slate-800">Phiên bản {result.version_no} ({result.original_filename})</span>
            <span className="text-slate-500">Thời điểm ký khai báo:</span>
            <span className="col-span-2 font-medium text-slate-800">{formatDate(dims.declared_timestamp)}</span>
            <span className="text-slate-500">Thời điểm xác minh:</span>
            <span className="col-span-2 font-medium text-slate-800">{formatDate(result.verified_at)}</span>
          </div>
        </div>

        {/* 6 Dimensions Grid */}
        <div className="mt-5 space-y-3">
          <h2 className="font-semibold text-slate-800 text-sm">Phân tích đa chiều chữ ký & toàn vẹn</h2>
          
          <div className="grid gap-2 text-xs">
            {/* 1. Cryptographic Validity */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3">
              <span className="font-medium text-slate-700">1. Tính hợp lệ mật mã (RSA-PSS)</span>
              <Status value={dims.cryptographic_validity} labels={cryptoLabels} />
            </div>

            {/* 2. Document Integrity */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3">
              <span className="font-medium text-slate-700">2. Tính toàn vẹn tệp PDF</span>
              <Status value={dims.document_integrity} labels={integrityLabels} />
            </div>

            {/* 3. Key Ownership */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3">
              <span className="font-medium text-slate-700">3. Quyền sở hữu khóa (PoP)</span>
              <span className="font-semibold text-slate-800">
                {dims.key_ownership === 'VERIFIED_POP' ? 'Đã xác thực PoP' : dims.key_ownership}
              </span>
            </div>

            {/* 4. Certificate Trust */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3">
              <span className="font-medium text-slate-700">4. Mức độ chứng thực khóa</span>
              <span className="font-semibold text-amber-700">
                {dims.certificate_trust === 'SELF_REGISTERED'
                  ? 'Khóa tự đăng ký (Self-Registered)'
                  : dims.certificate_trust}
              </span>
            </div>

            {/* 5. Key Revocation Status */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3">
              <span className="font-medium text-slate-700">5. Trạng thái thu hồi khóa</span>
              <Status value={dims.key_revocation_status} labels={keyLabels} />
            </div>
          </div>
        </div>

        <div className="mt-3 rounded-lg border border-slate-200 p-3 text-xs">
          <span className="block font-medium text-slate-700">6. Tính nhất quán bằng chứng</span>
          <Status value={result.results.evidence_consistency} labels={evidenceLabels} />
        </div>
        {dims.certificate_trust === 'SELF_REGISTERED' && <p className="mt-3 text-xs text-amber-800">
          Khóa tự đăng ký không phải chứng thư được CA xác nhận. Thời điểm ký khai báo chưa được TSA chứng thực.
        </p>}

        {/* Signer Fingerprint */}
        <div className="mt-4 rounded bg-slate-50 p-3 text-xs">
          <span className="font-medium text-slate-600 block">Fingerprint Public Key (SHA-256):</span>
          <code className="break-all font-mono text-slate-800 block mt-1">
            {result.signer_fingerprint || 'Không xác định'}
          </code>
        </div>

        {/* Warnings Alert */}
        {result.results.warnings && result.results.warnings.length > 0 && (
          <div className="mt-4 rounded-lg bg-amber-50 p-3.5 text-xs text-amber-900 border border-amber-200">
            <div className="flex items-center gap-1.5 font-semibold">
              <AlertTriangle size={15} /> Lưu ý an ninh & pháp lý:
            </div>
            <ul className="mt-1.5 list-disc pl-5 space-y-1">
              {result.results.warnings.map((w, idx) => (
                <li key={idx}>{w}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Privacy & Zero PDF Leakage Notice */}
        <div className="mt-6 border-t border-slate-100 pt-4 text-center">
          <p className="text-[11px] text-slate-400">
            Bảo vệ quyền riêng tư (Zero PDF Leakage): Trang xác minh này chỉ đánh giá và trả về kết quả
            toán học từ chữ ký số rời; tuyệt đối không cung cấp tải về hoặc làm lộ nội dung tệp PDF gốc.
          </p>
        </div>
      </div>
    </div>
  );
}
