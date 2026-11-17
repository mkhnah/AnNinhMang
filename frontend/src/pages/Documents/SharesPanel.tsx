import { useCallback, useEffect, useRef, useState } from 'react';
import { sharesApi, ShareListItem } from '../../api/shares';

const LIMIT = 20;
export function SharesPanel({ documentId, refresh = 0 }: { documentId: string; refresh?: number }) {
  const [items, setItems] = useState<ShareListItem[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [revoking, setRevoking] = useState<ShareListItem | null>(null);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const generation = useRef(0);
  const pending = useRef(false);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (next: number, reset: boolean) => {
    if (pending.current && !reset) return;
    if (reset) controller.current?.abort();
    const request = ++generation.current;
    const abort = new AbortController();
    controller.current = abort;
    pending.current = true;
    setLoading(true); setError('');
    if (reset) { setItems([]); setOffset(0); setHasMore(true); setRevoking(null); }
    try {
      const page = await sharesApi.list(documentId, undefined, LIMIT, next, abort.signal);
      if (request !== generation.current || abort.signal.aborted) return;
      setItems(previous => [...new Map([...(reset ? [] : previous), ...page].map(item => [item.id, item])).values()]);
      setOffset(next + page.length);
      // Array API has no exact total. A full page means another request may exist.
      setHasMore(page.length === LIMIT);
    } catch {
      if (request === generation.current && !abort.signal.aborted) setError('Không tải được liên kết chia sẻ. Vui lòng thử lại.');
    } finally {
      if (request === generation.current) { pending.current = false; setLoading(false); }
    }
  }, [documentId]);
  useEffect(() => {
    void load(0, true);
    return () => { ++generation.current; controller.current?.abort(); pending.current = false; };
  }, [load, refresh]);

  const revoke = async () => {
    if (!revoking || revokeBusy) return;
    const item = revoking;
    const request = generation.current;
    setRevokeBusy(true); setError('');
    try {
      await sharesApi.revoke(item.id);
      if (request !== generation.current) return;
      setItems(previous => previous.map(value => value.id === item.id
        ? {...value, status: 'REVOKED', revoked_at: new Date().toISOString()} : value));
      setRevoking(null);
    } catch {
      if (request === generation.current) setError('Không thu hồi được liên kết. Vui lòng thử lại.');
    } finally { setRevokeBusy(false); }
  };
  return <section className="document-register mt-6" aria-label="Liên kết chia sẻ">
    <div className="register-heading"><h2>Liên kết chia sẻ</h2><span>Đã tải {items.length} liên kết</span></div>
    <div className="ui-card-body">
    {error && <p role="alert" className="ui-alert ui-alert-error mb-4">{error}</p>}
    {!loading && !error && items.length === 0 && <p className="text-sm text-slate-500 py-3">Chưa có liên kết QR nào được tạo cho tài liệu này.</p>}
    <ul className="space-y-2">{items.map(item => <li key={item.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-200 p-3 text-sm">
      <div className="min-w-0"><p className="font-semibold break-words">{item.label || 'Liên kết xác minh'}</p><p className="text-xs text-slate-500 mt-1 mb-2">Hết hạn: {new Date(item.expires_at).toLocaleString('vi-VN')}</p>
        <span className={`ui-badge ${item.status === 'REVOKED' ? 'ui-badge-danger' : item.status === 'EXPIRED' ? 'ui-badge-warning' : 'ui-badge-success'}`}>{item.status === 'REVOKED' ? 'Đã thu hồi' : item.status === 'EXPIRED' ? 'Hết hạn' : 'Đang hoạt động'}</span></div>
      {item.status !== 'REVOKED' && <button type="button" className="ui-button ui-button-danger" aria-label={`Thu hồi ${item.label || item.id}`} onClick={() => setRevoking(item)}>Thu hồi</button>}
    </li>)}</ul>
    {loading && <p role="status" className="text-sm text-slate-500 py-3">Đang tải liên kết…</p>}
    <div className="flex flex-wrap gap-2 justify-end mt-4">
      <button type="button" className="ui-button" disabled={loading || revokeBusy} onClick={() => void load(0, true)}>Tải lại liên kết</button>
      {hasMore && !loading && <button type="button" className="ui-button" disabled={revokeBusy} onClick={() => void load(offset, false)}>{error ? 'Thử lại tải liên kết' : 'Tải thêm liên kết'}</button>}
    </div>
    </div>
    {revoking && <div role="dialog" aria-modal="true" aria-label="Xác nhận thu hồi liên kết" className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
      <div className="w-full max-w-sm rounded-2xl bg-white p-6"><h3 className="text-lg font-semibold">Thu hồi liên kết?</h3><p className="text-sm text-slate-500 mt-2 break-words">{revoking.label}</p>
        <div className="flex flex-wrap justify-end gap-2 mt-6">
          <button className="ui-button" disabled={revokeBusy} onClick={() => setRevoking(null)}>Hủy bỏ</button>
          <button className="ui-button ui-button-danger" disabled={revokeBusy} onClick={() => void revoke()}>Xác nhận thu hồi</button>
        </div>
      </div>
    </div>}
  </section>;
}
