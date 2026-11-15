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
    <div className="register-heading"><h2>Liên kết QR đã phát hành</h2><span>Đã tải {items.length} liên kết</span></div>
    <p className="text-xs text-slate-500">Tổng số chưa xác định; tải thêm để xem các liên kết cũ.</p>
    <button type="button" disabled={loading || revokeBusy} onClick={() => void load(0, true)}>Tải lại liên kết</button>
    {error && <p role="alert">{error}</p>}
    {!loading && !error && items.length === 0 && <p>Chưa có liên kết QR nào được tạo cho tài liệu này.</p>}
    <ul className="space-y-2">{items.map(item => <li key={item.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-200 p-3 text-sm">
      <div><p>{item.label || 'Liên kết xác minh'}</p><p>Hết hạn: {new Date(item.expires_at).toLocaleString('vi-VN')}</p>
        <span>{item.status === 'REVOKED' ? 'Đã thu hồi' : item.status === 'EXPIRED' ? 'Hết hạn' : 'Đang hoạt động'}</span></div>
      {item.status !== 'REVOKED' && <button type="button" aria-label={`Thu hồi ${item.label || item.id}`} onClick={() => setRevoking(item)}>Thu hồi</button>}
    </li>)}</ul>
    {loading && <p role="status">Đang tải liên kết…</p>}
    {hasMore && !loading && <button type="button" disabled={revokeBusy} onClick={() => void load(offset, false)}>{error ? 'Thử lại tải liên kết' : 'Tải thêm liên kết'}</button>}
    {revoking && <div role="dialog" aria-modal="true" aria-label="Xác nhận thu hồi liên kết" className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
      <div className="w-full max-w-sm rounded bg-white p-6"><h3>Xác nhận thu hồi liên kết?</h3><p>{revoking.label}</p>
        <button disabled={revokeBusy} onClick={() => setRevoking(null)}>Hủy bỏ</button>
        <button disabled={revokeBusy} onClick={() => void revoke()}>Xác nhận thu hồi</button>
      </div>
    </div>}
  </section>;
}
