import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { AlertTriangle, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { sharesApi, PublicShareResult } from '../../api/shares';
import { pkiLabels } from '../../components/Verification/PkiResultPanel';

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
const trustLabels: Record<string, string> = {
  TRUSTED_CA: 'CA tin cậy', SELF_REGISTERED: 'Khóa tự đăng ký', UNKNOWN: 'Chưa xác định',
};
const ownershipLabels: Record<string, string> = {
  VERIFIED_POP: 'Đã chứng minh', UNVERIFIED: 'Chưa chứng minh', UNKNOWN: 'Chưa xác định',
};
function Status({ value, labels }: { value: string; labels: Record<string, string> }) {
  const positive = ['VALID', 'UNCHANGED', 'ACTIVE', 'CONSISTENT', 'TRUSTED_CA', 'VERIFIED_POP', 'TRUSTED_TSA'].includes(value);
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


  return <div className="verify-page">
    <section className="ui-card ui-card-body">
      <header className="flex items-center gap-4 border-b border-slate-100 pb-6">
        {isOverallVerified ? <ShieldCheck className="text-emerald-600" size={38}/> : <ShieldAlert className="text-amber-600" size={38}/>}
        <div className="min-w-0"><h1>Kết quả xác minh</h1>
          <span className={'ui-badge mt-2 '+(isOverallVerified ? 'ui-badge-success' : 'ui-badge-warning')}>{isOverallVerified ? 'Đã xác minh' : 'Cần kiểm tra'}</span>
        </div>
      </header>
      <section className="mt-6">
        <h2 className="font-semibold mb-4">Thông tin tài liệu</h2>
        <dl className="ui-data">
          <div className="full-width"><dt>Tài liệu</dt><dd className="font-semibold">{result.title}</dd></div>
          <div><dt>Phiên bản</dt><dd>{result.version_no}</dd></div>
          <div><dt>Thời điểm ký khai báo:</dt><dd>{formatDate(dims.declared_timestamp)}</dd></div>
          <div><dt>Thời điểm xác minh</dt><dd>{formatDate(result.verified_at)}</dd></div>
          {dims.trusted_timestamp&&<div><dt>Thời gian TSA chứng thực</dt><dd>{formatDate(dims.trusted_timestamp)}</dd></div>}
          {dims.timestamp_scope==='DOCSIGN_PRIVATE_TSA'&&<div><dt>Phạm vi dấu thời gian</dt><dd>TSA nội bộ DocSign</dd></div>}
        </dl>
      </section>
      <section className="mt-6 border-t border-slate-100 pt-6">
        <h2 className="font-semibold mb-4">Kết quả kiểm tra</h2>
        <dl className="grid sm:grid-cols-2 gap-3">
          {[
            {label:'Chữ ký',value:dims.cryptographic_validity,labels:cryptoLabels},
            {label:'Toàn vẹn tài liệu',value:dims.document_integrity,labels:integrityLabels},
            {label:'Sở hữu khóa',value:dims.key_ownership,labels:ownershipLabels},
            {label:'Tin cậy chứng chỉ',value:dims.certificate_trust,labels:trustLabels},
            {label:'Trạng thái khóa',value:dims.key_revocation_status,labels:keyLabels},
            {label:'Bằng chứng',value:result.results.evidence_consistency,labels:evidenceLabels},
            {label:'Dấu thời gian',value:dims.timestamp_status==='INVALID'?'INVALID':dims.timestamp_trust_level,labels:{TRUSTED_TSA:'Đã xác minh TSA',DECLARED:'Thời gian khai báo',SERVER_RECORDED:'Máy chủ ghi nhận',UNKNOWN:'Chưa xác định',INVALID:'Không hợp lệ'}},
          ].map(({label,value,labels})=><div className="rounded-xl border border-slate-200 p-4 min-w-0" key={label}>
            <dt className="text-sm text-slate-500 mb-2">{label}</dt><dd className="text-sm"><Status value={value} labels={labels}/></dd>
          </div>)}
        </dl>
      </section>
      {dims.certificate_binding && <section className="mt-6 border-t border-slate-100 pt-6">
        <h2 className="font-semibold mb-4">Chứng chỉ và danh tính</h2>
        <dl className="ui-data">
          {Object.entries({certificate_binding:'Chứng chỉ',certificate_chain:'CA phát hành',certificate_validity:'Thời hạn',certificate_revocation:'Thu hồi',identity_binding:'Tài khoản',identity_assurance:'Mức đối chiếu danh tính'}).map(([field,label])=><div key={field}>
            <dt>{label}</dt><dd>{pkiLabels[String(dims[field as keyof typeof dims])] || 'Chưa xác định'}</dd>
          </div>)}
        </dl>
      </section>}
      <div className="mt-6"><span className="text-xs text-slate-500">Fingerprint SHA-256</span><code className="ui-code mt-2">{result.signer_fingerprint || 'Không xác định'}</code></div>
      {result.results.warnings && result.results.warnings.length>0 && <div className="mt-6 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
        <h2 className="font-semibold flex items-center gap-2"><AlertTriangle size={17}/>Cảnh báo xác minh</h2>
        <ul className="mt-2 list-disc pl-5 space-y-1">{result.results.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
      </div>}
    </section>
  </div>;
}
