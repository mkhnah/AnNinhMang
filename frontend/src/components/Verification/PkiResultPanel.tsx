import { CheckCircle2, CircleAlert } from 'lucide-react';
import { PkiResult } from '../../types/pki';
import { Link } from 'react-router-dom';
export const pkiLabels: Record<string,string> = {
 MATCHED:'Khớp',MISMATCH:'Không khớp',VALID:'Hợp lệ',INVALID:'Không hợp lệ',ACTIVE:'Đang hoạt động',REVOKED:'Đã thu hồi',UNKNOWN:'Chưa xác định',VERIFIED:'Đã chứng minh',
 ACCOUNT_BOUND:'Tài khoản',ADMIN_REVIEWED:'Đã đối chiếu danh tính',LEGACY_NO_CERTIFICATE_BINDING:'Chưa gắn chứng chỉ',
};
export function PkiResultPanel({result}:{result:PkiResult}) {
 return <section className="space-y-5" aria-label="Kết quả kiểm tra PKI">
  <div role="status" className={'ui-card ui-card-body flex flex-wrap items-center gap-4 '+(result.verified?'border-emerald-200 bg-emerald-50':'border-amber-200 bg-amber-50')}>
   {result.verified?<CheckCircle2 size={28} className="text-emerald-600"/>:<CircleAlert size={28} className="text-amber-600"/>}
   <div className="flex-1 min-w-0"><h2 className="text-lg font-semibold">{result.purpose==='SIGNATURE_PACKAGE'?(result.verified?'Chữ ký khớp với chứng chỉ số':'Chữ ký chưa được xác minh đầy đủ'):(result.verified?'Đã xác minh trong miền CA DocSign':'Chưa xác minh đầy đủ')}</h2><time className="text-sm text-slate-500">{new Date(result.checked_at).toLocaleString('vi-VN')}</time></div>
   <span className="ui-badge ui-badge-primary">{pkiLabels[result.identity_assurance]||'Chưa xác định danh tính'}</span>
  </div>
  {result.purpose==='SIGNATURE_PACKAGE'&&<p className="ui-alert">Kết quả xác minh chữ ký trên gói signature và đối chiếu chứng chỉ. Tính toàn vẹn của PDF chưa được kiểm tra; hãy dùng mục Tài liệu PDF để xác minh tài liệu.</p>}
  {result.trusted_timestamp&&<div className="ui-card ui-card-body"><p className="font-semibold">Dấu thời gian: {result.timestamp_trust}</p><p>{new Date(result.trusted_timestamp).toLocaleString('vi-VN')}</p><p>{result.timestamp_authority}</p><p className="text-sm text-slate-500">TSA nội bộ DocSign; chứng thực chữ ký đã tồn tại tại thời gian này.</p></div>}
  {result.timestamp_status==='INVALID'&&<p role="alert" className="ui-alert ui-alert-error">Dấu thời gian không hợp lệ hoặc TSA không còn được tin cậy.</p>}
  {result.warnings?.some(warning=>warning.startsWith('LEGACY_NO_CERTIFICATE_BINDING'))&&<p className="ui-alert">Chữ ký phiên bản cũ chỉ gắn với khóa công khai; chưa có thông tin ràng buộc chứng chỉ trong dữ liệu đã ký.</p>}
  <dl className="result-grid">{Object.entries({certificate_chain:'CA phát hành',certificate_validity:'Thời hạn chứng chỉ',certificate_revocation:'Thu hồi',certificate_binding:'Chứng chỉ',identity_binding:'Tài khoản',cryptographic_validity:'Chữ ký',possession:'Sở hữu khóa'}).map(([key,label])=>{
   const value=result[key as keyof PkiResult];return typeof value==='string'&&<div key={key} className="result-metric"><dt>{label}</dt><dd className={['VALID','MATCHED','ACTIVE','VERIFIED'].includes(value)?'text-emerald-600':'text-amber-700'}>{pkiLabels[value]||value}</dd></div>;
  })}</dl>
  <details open={!result.purpose} className="ui-card ui-card-body"><summary className="font-semibold">Thông tin chứng chỉ</summary><dl className="ui-data mt-5">{Object.entries({subject:'Chủ thể',issuer:'CA cấp',serial:'Số sê-ri',user_id:'Mã tài khoản',fingerprint:'Fingerprint SHA-256',not_before:'Có hiệu lực từ',not_after:'Hết hạn',message_sha256:'SHA-256 dữ liệu'}).map(([key,label])=>{
   const value=result[key as keyof PkiResult];return value&&<div key={key} className={key==='fingerprint'||key==='message_sha256'?'full-width':''}><dt>{label}</dt><dd>{String(value)}</dd></div>;
  })}</dl></details>
  {result.user_id&&<Link className="ui-button" to={'/verify/users?uuid='+encodeURIComponent(result.user_id)}>Đối chiếu UUID người dùng</Link>}
 </section>;
}
