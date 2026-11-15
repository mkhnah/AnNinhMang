import { SharesPanel } from './SharesPanel';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { FileText, UploadCloud, Download, Copy, Check, Lock, ArrowLeft, ShieldCheck, PenTool, Eye } from 'lucide-react';
import { documentsApi, Document, Version } from '../../api/documents';
import { verifyApi } from '../../api/verify';
import { SignModal } from './SignModal';
import { QRCodeModal } from '../../components/QRCodeModal';
import { CreateShareModal } from './CreateShareModal';
import { ShareLink } from '../../api/shares';
import { SignatureDetailsModal } from './SignatureDetailsModal';
import { VerifyModal } from './VerifyModal';
import './documents.css';

export async function errorMessage(error: unknown): Promise<string> {
  const response = (error as { response?: { status: number; data?: { detail?: unknown } | Blob } })?.response;
  if (!response) return 'Không thể kết nối. Kiểm tra mạng rồi thử lại.';
  if (response.status === 401) return 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.';
  if (response.status === 413) return 'PDF vượt giới hạn dung lượng cho phép.';
  let data = response.data;
  if (data instanceof Blob) { try { data = JSON.parse(await data.text()); } catch { data = undefined; } }
  const detail = (data as { detail?: unknown })?.detail;
  return typeof detail === 'string' ? detail : 'Không thể thực hiện thao tác. Vui lòng thử lại.';
}
const size = (bytes: number) => `${(bytes / 1024 / 1024).toFixed(2)} MB`;
const date = (value: string) => new Date(value.endsWith('Z') || /[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`).toLocaleString('vi-VN');

export function UploadPanel({ documentId, onSuccess }: { documentId?: string; onSuccess: () => void }) {
  const [busy, setBusy] = useState(false), [progress, setProgress] = useState(0), [error, setError] = useState(''), [success, setSuccess] = useState(false);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const inFlight = useRef(false);
  const [maxBytes, setMaxBytes] = useState(20 * 1024 * 1024);
  useEffect(() => { let active = true; void documentsApi.limits().then(data => { if (active) setMaxBytes(data.max_upload_bytes); }).catch(() => {}); return () => { active = false; }; }, []);
  const upload = async (file?: File) => {
    if (!file || inFlight.current) return;
    setError(''); setSuccess(false);
    if (!file.name.toLowerCase().endsWith('.pdf')) { setError('Chỉ chấp nhận tệp .pdf.'); return; }
    // Convenience precheck; the server enforces its configured limit.
    if (file.size > maxBytes) { setError(`PDF vượt giới hạn ${maxBytes / 1024 / 1024} MB.`); return; }
    inFlight.current = true; setBusy(true); setProgress(0);
    try { await documentsApi.upload(file, setProgress, documentId); setSuccess(true); onSuccess(); }
    catch (e) { setError(await errorMessage(e)); }
    finally { inFlight.current = false; setBusy(false); if (input.current) input.current.value = ''; }
  };
  return <section className="upload-section" aria-label={documentId ? 'Thêm phiên bản' : 'Tải PDF lên'}>
    <button type="button" disabled={busy} className={`dropzone ${dragging ? 'dragging' : ''}`}
      onClick={() => input.current?.click()} onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)} onDrop={e => { e.preventDefault(); setDragging(false); void upload(e.dataTransfer.files[0]); }}>
      <UploadCloud size={30} aria-hidden="true" /><span><strong>{documentId ? 'Thêm phiên bản PDF' : 'Lưu một tài liệu mới'}</strong><small>Kéo thả PDF hoặc bấm để chọn · Tối đa {maxBytes / 1024 / 1024} MB</small></span>
    </button>
    <input aria-label="Chọn PDF" ref={input} type="file" accept=".pdf,application/pdf" hidden disabled={busy} onChange={e => void upload(e.target.files?.[0])} />
    {busy && <div className="upload-status" role="status"><progress max={100} value={progress} aria-label="Tiến độ tải lên" /><span>{progress < 100 ? `Đang tải ${progress}%` : 'Đang kiểm tra và lưu PDF…'}</span></div>}
    {error && <p role="alert" className="document-error">{error}</p>}
    {success && <p role="status" className="document-success">Đã lưu PDF và xác nhận mã SHA-256.</p>}
  </section>;
}

export function Documents() {
  const [items, setItems] = useState<Document[]>([]), [total, setTotal] = useState(0), [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true), [error, setError] = useState('');
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { const data = await documentsApi.list(offset); setItems(data.items); setTotal(data.total); }
    catch (e) { setError(await errorMessage(e)); }
    finally { setLoading(false); }
  }, [offset]);
  useEffect(() => { void load(); }, [load]);
  return <div className="documents-page">
    <header className="documents-heading"><div><h1>Tài liệu của bạn</h1><p>Lưu bản gốc. Theo dõi từng phiên bản.</p></div><ShieldCheck size={36} className="document-seal" /></header>
    <UploadPanel onSuccess={() => { if (offset) setOffset(0); else void load(); }} />
    <section className="document-register" aria-label="Danh sách tài liệu">
      <div className="register-heading"><h2>Kho tài liệu</h2><span>{total} tài liệu · Riêng tư</span></div>
      {error && <p role="alert" className="document-error">{error} <button onClick={() => void load()}>Thử lại</button></p>}
      {loading ? <p role="status" className="document-empty">Đang tải tài liệu…</p> : items.length === 0 && !error ? <div className="document-empty"><FileText size={36} /><h3>Kho tài liệu đang trống</h3><p>Chọn PDF phía trên để lưu tài liệu đầu tiên.</p></div> : <ul className="document-list">{items.map(item => <li key={item.id}><Link to={`/documents/${item.id}`}><FileText size={24} /><div><strong>{item.title}</strong><small>Cập nhật {date(item.updated_at)}</small></div><span className="private-tag"><Lock size={13} /> Riêng tư</span></Link></li>)}</ul>}
      {total > 20 && <div className="document-pagination"><button disabled={offset === 0 || loading} onClick={() => setOffset(offset - 20)}>Trang trước</button><span>{offset + 1}–{Math.min(offset + 20, total)} / {total}</span><button disabled={offset + 20 >= total || loading} onClick={() => setOffset(offset + 20)}>Trang sau</button></div>}
    </section>
  </div>;
}

export function DocumentDetail() {
  const { id = '' } = useParams();
  return <DocumentDetailContent key={id} />;
}

function DocumentDetailContent() {
  const { id = '' } = useParams();
  const [doc, setDoc] = useState<Document | null>(null), [versions, setVersions] = useState<Version[]>([]);
  const [loading, setLoading] = useState(true), [error, setError] = useState(''), [copied, setCopied] = useState(''), [busy, setBusy] = useState('');
  const [hasMore, setHasMore] = useState(false);
  const [signingVersion, setSigningVersion] = useState<Version | null>(null);
  const [creatingShareVersion, setCreatingShareVersion] = useState<Version | null>(null);
  const [shareLink, setShareLink] = useState<ShareLink | null>(null);
  const [shareRefresh, setShareRefresh] = useState(0);
  const [inspectingVersion, setInspectingVersion] = useState<Version | null>(null);
  const [verifyingVersion, setVerifyingVersion] = useState<Version | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { const [document, history] = await Promise.all([documentsApi.detail(id), documentsApi.versions(id)]); setDoc(document); setVersions(history); setHasMore(history.length === 100); }
    catch (e) { setError(await errorMessage(e)); }
    finally { setLoading(false); }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const action = async (version: Version, kind: 'download' | 'ready' | 'copy') => {
    setBusy(version.id); setError('');
    try {
      if (kind === 'copy') { await navigator.clipboard.writeText(version.file_sha256); setCopied(version.id); }
      else if (kind === 'download') await documentsApi.download(id, version);
      else { await documentsApi.ready(id, version.id); await load(); }
    } catch (e) { setError(kind === 'copy' ? 'Không thể sao chép. Hãy chọn và sao chép mã băm bên dưới.' : await errorMessage(e)); }
    finally { setBusy(''); }
  };
  const handleDownloadPackage = async (version: Version) => {
    setBusy(version.id); setError('');
    try {
      const pkg = await verifyApi.exportSignaturePackage(id, version.id);
      const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `signature-package-${doc?.title || 'document'}-v${version.version_no}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(await errorMessage(e));
    } finally {
      setBusy('');
    }
  };
  const more = async () => {
    try { const next = await documentsApi.versions(id, versions.length); setVersions([...versions, ...next]); setHasMore(next.length === 100); }
    catch (e) { setError(await errorMessage(e)); }
  };
  return <div className="documents-page"><Link to="/documents" className="document-back"><ArrowLeft size={16} /> Kho tài liệu</Link>
    {error && <p role="alert" className="document-error">{error}</p>}
    {loading ? <p role="status">Đang tải phiên bản…</p> : doc && <>
      <header className="documents-heading"><div><h1>{doc.title}</h1><p>Mỗi phiên bản giữ nguyên nội dung PDF đã tải lên.</p></div><Lock className="document-seal" size={30} /></header>
      <UploadPanel documentId={id} onSuccess={() => void load()} />
      <section className="document-register"><div className="register-heading"><h2>Lịch sử phiên bản</h2><span>Mới nhất trước</span></div>
        <ol className="version-list">{versions.map(version => <li key={version.id}>
          <div className="version-heading"><div><h3>Phiên bản {version.version_no}</h3><p>{version.original_filename}</p></div><span className={`state-tag state-${version.state}`}>{version.state}</span></div>
          <p className="version-meta">{date(version.created_at)} · {size(version.file_size_bytes)}{version.locked_at ? ` · Đã khóa ${date(version.locked_at)}` : ''}</p>
          <div className="hash-panel"><span>SHA-256</span><code>{version.file_sha256}</code><button aria-label={`Sao chép SHA-256 phiên bản ${version.version_no}`} disabled={busy === version.id} onClick={() => void action(version, 'copy')}>{copied === version.id ? <Check size={17} /> : <Copy size={17} />}</button></div>
          <div className="version-actions">
            <button disabled={busy === version.id} onClick={() => void action(version, 'download')}><Download size={16} /> Tải PDF</button>
            {version.state === 'DRAFT' && <button disabled={busy === version.id} onClick={() => void action(version, 'ready')}><Lock size={16} /> Khóa để chuẩn bị ký</button>}
            {version.state === 'READY_TO_SIGN' && <button className="font-semibold text-emerald-700 hover:text-emerald-800" disabled={busy === version.id} onClick={() => setSigningVersion(version)}><PenTool size={16} /> Ký số (Sign)</button>}
            {version.state === 'SIGNED' && (
              <>
                <button className="font-semibold text-sky-700 hover:text-sky-800" disabled={busy === version.id} onClick={() => setInspectingVersion(version)}><Eye size={16} /> Chi tiết chữ ký</button>
                <button className="font-semibold text-emerald-700 hover:text-emerald-800" disabled={busy === version.id} onClick={() => setVerifyingVersion(version)}><ShieldCheck size={16} /> Xác minh</button>
                <button className="font-semibold text-violet-700 hover:text-violet-800" disabled={busy === version.id} onClick={() => setCreatingShareVersion(version)}><ShieldCheck size={16} /> QR chia sẻ</button>
                <button className="font-semibold text-slate-700 hover:text-slate-800" disabled={busy === version.id} onClick={() => void handleDownloadPackage(version)}><Download size={16} /> Gói chữ ký</button>
              </>
            )}
          </div>
        </li>)}</ol>{hasMore && <button className="document-more" onClick={() => void more()}>Xem phiên bản cũ hơn</button>}
      </section>

      {/* Sign Document Modal */}
      {signingVersion && (
        <SignModal
          documentId={id}
          versionId={signingVersion.id}
          versionNo={signingVersion.version_no}
          documentTitle={doc.title}
          fileSha256={signingVersion.file_sha256}
          onClose={() => setSigningVersion(null)}
          onSuccess={() => {
            setSigningVersion(null);
            void load();
          }}
        />
      )}

      {/* Signature Details Modal */}
      {inspectingVersion && (
        <SignatureDetailsModal
          documentId={id}
          versionId={inspectingVersion.id}
          versionNo={inspectingVersion.version_no}
          documentTitle={doc.title}
          onClose={() => setInspectingVersion(null)}
        />
      )}

      {/* Verification Modal */}
      {verifyingVersion && (
        <VerifyModal
          documentId={id}
          versionId={verifyingVersion.id}
          versionNo={verifyingVersion.version_no}
          documentTitle={doc.title}
          onClose={() => setVerifyingVersion(null)}
        />
      )}
      {creatingShareVersion && (
        <CreateShareModal
          versionId={creatingShareVersion.id}
          versionNo={creatingShareVersion.version_no}
          documentTitle={doc.title}
          onClose={() => setCreatingShareVersion(null)}
          onSuccess={(created) => {
            setCreatingShareVersion(null);
            setShareLink(created);
            setShareRefresh(value => value + 1);
          }}
        />
      )}

      {shareLink && (
        <QRCodeModal
          share={shareLink}
          onClose={() => {
            setShareLink(null);
          }}
        />
      )}

      <SharesPanel key={id} documentId={id} refresh={shareRefresh} />
    </>}
  </div>;
}
