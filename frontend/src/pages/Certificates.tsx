import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { BadgeCheck, RefreshCw, Download, ShieldCheck, KeyRound, FileBadge, ChevronLeft, ChevronRight, Send } from 'lucide-react';
import { pkiApi } from '../api/pki';
import { keysApi } from '../api/keys';
import { Authority, CertificateDto, IdentityReview, PkiResult } from '../types/pki';
import { PublicKeyDto } from '../types/key';
import { useAuth } from '../context/AuthContext';
import { getKeyFromKeystore } from '../crypto/keyStorage';
import { canonicalizeManifest } from '../crypto/manifestCanonicalizer';
import { arrayBufferToBase64, toCryptoBytes } from '../crypto/spki';
import { PkiResultPanel } from '../components/Verification/PkiResultPanel';
import { AdminNav } from '../components/AdminNav';

function savePem(content: string, filename: string) {
    const url = URL.createObjectURL(new Blob([content], {type:'application/x-pem-file'}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click();
    URL.revokeObjectURL(url);
}
const date = (value: string) => new Date(value).toLocaleString('vi-VN');
const button = 'ui-button';
const statusLabels: Record<string,string> = {ACTIVE:'Đang hoạt động',REVOKED:'Đã thu hồi',EXPIRED:'Hết hạn',CA_UNTRUSTED:'CA không tin cậy',NOT_YET_VALID:'Chưa hiệu lực',PENDING:'Chờ duyệt',APPROVED:'Đã duyệt',REJECTED:'Từ chối',TRUSTED:'Tin cậy',RETIRED:'Ngừng tin cậy',COMPROMISED:'Đã lộ khóa'};
type CertificateAttempt = {path:string; body:unknown};

export function Certificates({admin = false}: {admin?: boolean}) {
    const {user} = useAuth();
    const [certificates, setCertificates] = useState<CertificateDto[]>([]);
    const [keys, setKeys] = useState<PublicKeyDto[]>([]);
    const [reviews, setReviews] = useState<IdentityReview[]>([]);
    const [authorities, setAuthorities] = useState<Authority[]>([]);
    const [readiness, setReadiness] = useState('');
    const [offset, setOffset] = useState(0);
    const [reviewOffset, setReviewOffset] = useState(0);
    const [total, setTotal] = useState(0);
    const [filter, setFilter] = useState('');
    const [fullName, setFullName] = useState('');
    const [reference, setReference] = useState('');
    const [reason, setReason] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');
    const [notice, setNotice] = useState('');
    const [proofResult, setProofResult] = useState<PkiResult | null>(null);
    const pendingKey = `docsign.pending-certificate.v1/${user?.id}`;
    const [retry, setRetry] = useState<CertificateAttempt | null>(null);
    const mounted = useRef(true);
    const locked = useRef(false);
    const generation = useRef(0);
    const load = useCallback(async () => {
        const id = ++generation.current;
        const [page, accountKeys, identityReviews, roots, ready] = await Promise.all([
            pkiApi.certificates(admin, offset, filter), admin ? Promise.resolve([]) : keysApi.listMyKeys(),
            pkiApi.reviews(admin, reviewOffset), admin ? pkiApi.authorities() : Promise.resolve([]),
            admin ? pkiApi.readiness().catch(() => ({ready:false, enabled:true, code:'CA_CONFIGURATION_UNAVAILABLE', subject:''})) : Promise.resolve(null),
        ]);
        if (!mounted.current || generation.current !== id) return;
        setCertificates(page.items); setTotal(page.total); setKeys(accountKeys); setReviews(identityReviews); setAuthorities(roots);
        if (ready) setReadiness(ready.ready ? `CA sẵn sàng` : `CA chưa sẵn sàng: ${ready.code}`);
    }, [admin, offset, filter, reviewOffset, user?.id]);
    useEffect(() => {
        mounted.current = true;
        setError(''); setNotice(''); setProofResult(null);
        void load().catch(() => {if (mounted.current) setError('Không thể tải dữ liệu chứng chỉ. Hãy thử làm mới.');});
        return () => {mounted.current = false; generation.current++;};
    }, [load]);
    useEffect(() => {
        if (admin || !user) return;
        try {
            const raw = sessionStorage.getItem(pendingKey);
            if (!raw) return;
            const attempt: CertificateAttempt = JSON.parse(raw);
            if (!/^\/certificates\/(issue-for-key|[A-Za-z0-9_-]{1,36}\/renew)$/.test(attempt.path) || !attempt.body || typeof attempt.body !== 'object') throw new Error('Invalid context');
            setRetry(attempt);
        } catch {setError('Không đọc được yêu cầu cấp đang chờ. Kiểm tra danh sách chứng chỉ trước khi cấp lại.');}
    }, [pendingKey, admin, user?.id]);
    const clearRetry = () => {
        try {sessionStorage.removeItem(pendingKey);} catch { /* A retained request reconciles safely through idempotency. */ }
        setRetry(null);
    };
    const act = async (operation: () => Promise<void>) => {
        if (locked.current) return;
        locked.current = true; setBusy(true); setError(''); setNotice(''); setProofResult(null);
        try {await operation(); await load();}
        catch (err) {
            if (mounted.current) {
                const detail = (err as {response?:{data?:{detail?:unknown}}})?.response?.data?.detail;
                setError(typeof detail === 'string' ? detail : err instanceof Error ? err.message : 'Thao tác thất bại');
            }
        } finally {locked.current = false; if (mounted.current) setBusy(false);}
    };
    const localSign = async (keyId: string, payload: Record<string, unknown>) => {
        const key = keys.find(item => item.id === keyId);
        if (!key || !user) throw new Error('Không tìm thấy khóa thuộc tài khoản');
        const record = await getKeyFromKeystore(key.fingerprint);
        if (!record?.privateKey || record.userId !== user.id) throw new Error('Cần khôi phục Private Key trên trình duyệt để chứng minh quyền sở hữu');
        return arrayBufferToBase64(await crypto.subtle.sign({name:'RSA-PSS', saltLength:32}, record.privateKey,
            toCryptoBytes(canonicalizeManifest(payload))));
    };
    const issue = (keyId: string, certificateId?: string) => act(async () => {
        if (retry) throw new Error('Hãy thử gửi lại yêu cầu đang chờ trước khi cấp chứng chỉ khác');
        const challenge = await pkiApi.challenge(keyId, certificateId);
        const signature = await localSign(keyId, challenge.payload);
        const attempt = {path:certificateId ? `/certificates/${certificateId}/renew` : '/certificates/issue-for-key',
            body:{challenge_id:challenge.challenge_id, pop_signature_b64:signature, idempotency_key:crypto.randomUUID()}};
        sessionStorage.setItem(pendingKey, JSON.stringify(attempt));
        setRetry(attempt);
        const cert = await pkiApi.issue(attempt.path, attempt.body);
        if (mounted.current) {clearRetry(); setNotice(`Đã cấp chứng chỉ ${cert.serial.slice(0,12)}…`);}
    });
    const prove = (cert: CertificateDto) => act(async () => {
        const challenge = await pkiApi.possessionChallenge(cert.id);
        const signature = await localSign(cert.key_id, challenge.payload);
        const result = await pkiApi.possessionVerify(challenge.challenge_id, signature);
        if (mounted.current) setProofResult(result);
    });
    const revoke = (cert: CertificateDto) => {
        if (!window.confirm(`Thu hồi chứng chỉ ${cert.serial}? Chữ ký sử dụng chứng chỉ này sẽ không đạt xác minh đầy đủ theo trạng thái hiện tại.`)) return;
        void act(async () => {await pkiApi.revoke(cert.id, 'USER_REQUEST'); if (mounted.current) setNotice('Đã thu hồi chứng chỉ');});
    };
    return <div>
        {admin&&<AdminNav/>}
        <header className="ui-page-header"><h1>{admin?'CA và danh tính':'Chứng chỉ của tôi'}</h1><div className="flex gap-2">{user?.role==='ADMIN'&&<Link className="ui-button" to={admin?'/certificates':'/admin/pki'}>{admin?'Chứng chỉ của tôi':'Quản trị CA'}</Link>}<button className={button} disabled={busy} onClick={()=>{void act(async()=>{});}}><RefreshCw size={16} className={busy?'animate-spin':''}/>Làm mới</button></div></header>
        {error&&<p role="alert" className="ui-alert ui-alert-error mb-5">{error}</p>}
        {notice&&<p role="status" className="ui-alert ui-alert-success mb-5">{notice}</p>}
        {retry&&<div className="ui-card ui-card-body mb-6"><h2 className="font-semibold mb-3">Yêu cầu cấp đang chờ xác nhận</h2><div className="flex flex-wrap gap-2">
            <button disabled={busy} className="ui-button ui-button-primary" onClick={()=>{void act(async()=>{const cert=await pkiApi.issue(retry.path,retry.body);if(mounted.current){clearRetry();setNotice('Đã xác nhận chứng chỉ '+cert.serial.slice(0,12));}});}}>Thử gửi lại yêu cầu</button>
            <button disabled={busy} className={button} onClick={()=>{clearRetry();void act(async()=>{});}}>Bỏ yêu cầu và làm mới danh sách</button></div></div>}
        {admin&&<section className="ui-card mb-6"><div className="ui-card-heading"><h2>CA phát hành</h2><ShieldCheck size={20} className="text-sky-600"/></div><div className="ui-card-body space-y-4">
            <p className="ui-badge ui-badge-primary">{readiness||'Đang kiểm tra…'}</p>
            {authorities.map(ca=><article key={ca.id} className="authority-row">
                <div><h3 className="font-semibold">{ca.subject.replace(/^CN=/,'')}</h3><span className="ui-badge mt-2">{statusLabels[ca.trust_status]}</span><code className="ui-code mt-3">{ca.fingerprint}</code></div>
                <div className="flex flex-wrap gap-2 mt-4"><button disabled={busy||ca.trust_status==='COMPROMISED'} className={button} onClick={()=>{void act(async()=>{await pkiApi.updateAuthority(ca.id,'TRUSTED',!ca.issuance_enabled);});}}>{ca.issuance_enabled?'Ngừng cấp':'Bật cấp và trust'}</button>
                <button disabled={busy||ca.trust_status==='COMPROMISED'} className={button} onClick={()=>{if(window.confirm('Ngừng tin cậy CA này và toàn bộ chứng chỉ liên quan?'))void act(async()=>{await pkiApi.updateAuthority(ca.id,'RETIRED',false);});}}>Ngừng tin cậy</button>
                <button disabled={busy||ca.trust_status==='COMPROMISED'} className="ui-button ui-button-danger" onClick={()=>{if(window.confirm('Đánh dấu CA đã bị lộ khóa? Thao tác này không thể đảo ngược.'))void act(async()=>{await pkiApi.updateAuthority(ca.id,'COMPROMISED',false);});}}>Báo lộ khóa</button></div>
            </article>)}
            {!authorities.length&&<p className="text-slate-500">Chưa có CA phát hành</p>}
        </div></section>}
        <div className="certificate-layout">
          <section className="min-w-0">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-5"><h2 className="text-lg font-semibold">Chứng chỉ <span className="ui-badge ml-2">{total}</span></h2>{admin&&<div className="flex flex-wrap gap-3 items-center"><Link to="/verify/users" className="ui-button">Tra cứu UUID</Link><input aria-label="Lọc theo mã tài khoản" placeholder="Mã tài khoản" disabled={busy} value={filter} maxLength={36} onChange={e=>{setOffset(0);setFilter(e.target.value);}} className="min-w-0 w-48"/></div>}</div>
            <div className="certificate-list">
            {!certificates.length&&<div className="ui-card ui-empty"><FileBadge size={36}/><p>Chưa có chứng chỉ</p></div>}
            {certificates.map(cert=><article key={cert.id} className="ui-card ui-card-body">
              <div className="certificate-card-head"><span className="certificate-icon"><BadgeCheck size={24}/></span><div className="min-w-0 flex-1"><h3 className="certificate-title">{cert.subject.startsWith('CN=DocSign account')?'Chứng chỉ ký số':cert.subject.replace(/^CN=/,'')}</h3><div className="flex flex-wrap gap-2 mt-2"><span className={'ui-badge '+(cert.status==='ACTIVE'?'ui-badge-success':'ui-badge-warning')}>{statusLabels[cert.status]||cert.status}</span><span className="ui-badge ui-badge-primary">{cert.identity_assurance==='ADMIN_REVIEWED'?'Đã đối chiếu danh tính':'Tài khoản'}</span></div></div></div>
              <dl className="ui-data"><div><dt>Ngày cấp</dt><dd>{date(cert.not_before)}</dd></div><div><dt>Ngày hết hạn</dt><dd>{date(cert.not_after)}</dd></div></dl>
              <details className="certificate-details mt-5"><summary>Thông tin chứng chỉ</summary><dl className="ui-data mt-4"><div className="full-width"><dt>Chủ thể</dt><dd>{cert.subject}</dd></div><div className="full-width"><dt>Serial</dt><dd><code className="ui-code">{cert.serial}</code></dd></div><div className="full-width"><dt>Fingerprint SHA-256</dt><dd><code className="ui-code">{cert.fingerprint}</code></dd></div>{admin&&<div className="full-width"><dt>Tài khoản</dt><dd>{cert.user_id}</dd></div>}</dl></details>
              <div className="certificate-card-actions"><button className={button} disabled={busy} onClick={()=>{void act(async()=>{savePem(await pkiApi.download(cert.id),'certificate-'+cert.serial+'.pem');});}}><Download size={15}/>Tải PEM</button>
                {!admin&&<><button aria-label="Gia hạn / cập nhật danh tính" className={button} disabled={busy||!!cert.revoked_at} onClick={()=>{void issue(cert.key_id,cert.id);}}><RefreshCw size={15}/>Gia hạn</button><button aria-label="Chứng minh sở hữu khóa" className={button} disabled={busy||cert.status!=='ACTIVE'} onClick={()=>{void prove(cert);}}><KeyRound size={15}/>Xác thực khóa</button></>}
                <button className="ui-button ui-button-danger" disabled={busy||!!cert.revoked_at} onClick={()=>revoke(cert)}>Thu hồi</button>
              </div>
            </article>)}</div>
            {total>20&&<div className="ui-pagination"><button aria-label="Trang trước" disabled={busy||offset===0} className={button} onClick={()=>setOffset(Math.max(0,offset-20))}><ChevronLeft size={16}/></button><span>Trang {offset/20+1}</span><button aria-label="Trang sau" disabled={busy||offset+20>=total} className={button} onClick={()=>setOffset(offset+20)}><ChevronRight size={16}/></button></div>}
            {!admin&&keys.filter(key=>key.status==='ACTIVE'&&!key.current_certificate_id).map(key=><div key={key.id} className="ui-card ui-card-body mt-5 flex flex-wrap gap-4 items-center justify-between"><span className="text-sm">Khóa {key.fingerprint.slice(0,16)}…</span><button className="ui-button ui-button-primary" disabled={busy} onClick={()=>{void issue(key.id);}}>Cấp chứng chỉ bằng PoP</button></div>)}
          </section>
          <aside className="ui-card"><div className="ui-card-heading"><h2>{admin?'Xét duyệt danh tính':'Xác minh danh tính'}</h2><ShieldCheck size={20} className="text-sky-600"/></div><div className="ui-card-body">
            {!admin&&<form className="grid gap-5 mb-6" onSubmit={e=>{e.preventDefault();void act(async()=>{await pkiApi.requestReview(fullName,reference);if(mounted.current){setFullName('');setReference('');setNotice('Đã gửi yêu cầu xác minh danh tính');}});}}>
                <label className="ui-field">Họ tên<input value={fullName} onChange={e=>setFullName(e.target.value)} minLength={2} maxLength={64} required/></label>
                <label className="ui-field">Mã hồ sơ<input value={reference} onChange={e=>setReference(e.target.value)} minLength={3} maxLength={200} required/></label>
                <button className="ui-button ui-button-primary" disabled={busy}><Send size={15}/>Gửi yêu cầu</button>
            </form>}
            {admin&&<label className="ui-field mb-5">Lý do duyệt / từ chối<textarea value={reason} maxLength={500} onChange={e=>setReason(e.target.value)} rows={3}/></label>}
            {reviews.map(review=><article key={review.id} className="review-card"><div className="flex flex-wrap gap-2 items-center justify-between"><h3 className="font-semibold">{review.claims.full_name}</h3><span className="ui-badge">{statusLabels[review.status]}</span></div><dl className="ui-data"><div className="full-width"><dt>Mã hồ sơ</dt><dd>{review.claims.evidence_reference}</dd></div>{review.reason&&<div className="full-width"><dt>Kết quả</dt><dd>{review.reason}</dd></div>}</dl>
                {admin&&review.status==='PENDING'&&<div className="flex flex-wrap gap-2">{[['APPROVED','Duyệt danh tính'],['REJECTED','Từ chối']].map(([status,label])=><button key={status} disabled={busy||reason.trim().length<3||review.user_id===user?.id} className={status==='APPROVED'?'ui-button ui-button-primary':button} onClick={()=>{void act(async()=>{await pkiApi.decide(review.id,status,reason);});}}>{label}</button>)}</div>}
            </article>)}
            {!reviews.length&&<p className="text-sm text-slate-400">Chưa có yêu cầu</p>}
            {(reviewOffset>0||reviews.length>=20)&&<div className="ui-pagination"><button disabled={busy||reviewOffset===0} className={button} onClick={()=>setReviewOffset(Math.max(0,reviewOffset-20))}><ChevronLeft size={16}/></button><button disabled={busy||reviews.length<20} className={button} onClick={()=>setReviewOffset(reviewOffset+20)}><ChevronRight size={16}/></button></div>}
          </div></aside>
        </div>
        {proofResult&&<div className="mt-6"><PkiResultPanel result={proofResult}/></div>}
    </div>;
}
