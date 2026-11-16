import { FormEvent, useEffect, useRef, useState } from 'react';
import { useLocation, useSearchParams } from 'react-router-dom';
import { ChevronLeft, ChevronRight, RefreshCw, Search } from 'lucide-react';
import { actionLabels, auditActions, auditApi, AuditFilters, AuditPage } from '../../api/audit';
import { AdminNav } from '../../components/AdminNav';

const statusLabels: Record<string, string> = { SUCCESS: 'Thành công', FAILURE: 'Thất bại', DENIED: 'Bị chặn' };
const inputClass = 'mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-sky-500';
const filterKeys = ['action', 'status', 'actor_id', 'target_id', 'client_ip', 'since', 'until'] as const;

function localDate(iso?: string) {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function Audit() {
  const location = useLocation();
  const [search, setSearch] = useSearchParams();
  const initial: AuditFilters = {};
  for (const key of filterKeys) {
    const value = search.get(key);
    if (value) initial[key] = value;
  }
  return <AuditBrowser key={location.key} filters={initial} onFilter={filters => setSearch(filters as Record<string, string>)} />;
}

function AuditBrowser({ filters, onFilter }: { filters: AuditFilters; onFilter: (filters: AuditFilters) => void }) {
  const [draft, setDraft] = useState({ ...filters, since: localDate(filters.since), until: localDate(filters.until) });
  const [data, setData] = useState<AuditPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [validation, setValidation] = useState('');
  const snapshot = useRef<string>();
  const initialFilters = useRef(filters);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setData(null);
    setError('');
    auditApi.logs({ ...initialFilters.current, limit: 20, offset, snapshot_id: snapshot.current }, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        snapshot.current = page.snapshot_id;
        setData(page);
      })
      .catch(error => {
        if (controller.signal.aborted) return;
        setError(error?.response?.status === 422 ? 'Bộ lọc không hợp lệ. Kiểm tra mã định danh và khoảng thời gian.' : 'Không thể tải nhật ký kiểm toán. Hãy thử lại.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [offset, revision]);

  function submit(event: FormEvent) {
    event.preventDefault();
    setValidation('');
    if (draft.since && draft.until && new Date(draft.since) > new Date(draft.until)) {
      setValidation('Thời điểm bắt đầu phải trước thời điểm kết thúc.');
      return;
    }
    const applied: AuditFilters = {};
    for (const key of filterKeys) {
      const value = draft[key]?.trim();
      if (value) applied[key] = key === 'since' || key === 'until' ? new Date(value).toISOString() : value;
    }
    onFilter(applied);
  }

  function refresh() {
    snapshot.current = undefined;
    setOffset(0);
    setRevision(value => value + 1);
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
      <AdminNav />
      <div className="flex flex-wrap justify-between items-start gap-4 mb-7">
        <div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">Nhật ký kiểm toán</h1>
          <p className="text-sm text-slate-500 mt-2">Tra cứu hoạt động, kết quả và các mắt xích của chuỗi băm.</p>
        </div>
        <button onClick={refresh} disabled={loading} className="inline-flex gap-2 items-center px-4 py-2 text-sm font-medium rounded-lg border border-slate-300 bg-white disabled:opacity-50">
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Làm mới
        </button>
      </div>
      <form onSubmit={submit} className="rounded-xl border border-slate-200 bg-white p-5 mb-6">
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <label className="text-sm font-medium">Sự kiện
            <select className={inputClass} value={draft.action ?? ''} onChange={event => setDraft({ ...draft, action: event.target.value })}>
              <option value="">Tất cả sự kiện</option>
              {auditActions.map(action => <option key={action} value={action}>{actionLabels[action]}</option>)}
            </select>
          </label>
          <label className="text-sm font-medium">Kết quả
            <select className={inputClass} value={draft.status ?? ''} onChange={event => setDraft({ ...draft, status: event.target.value })}>
              <option value="">Tất cả kết quả</option>
              {Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          <label className="text-sm font-medium">Mã người thực hiện
            <input className={inputClass} maxLength={36} value={draft.actor_id ?? ''} onChange={event => setDraft({ ...draft, actor_id: event.target.value })} placeholder="User ID" />
          </label>
          <label className="text-sm font-medium">Mã đối tượng
            <input className={inputClass} maxLength={36} value={draft.target_id ?? ''} onChange={event => setDraft({ ...draft, target_id: event.target.value })} placeholder="Target ID" />
          </label>
          <label className="text-sm font-medium">IP truy cập
            <input className={inputClass} maxLength={45} value={draft.client_ip ?? ''} onChange={event => setDraft({ ...draft, client_ip: event.target.value })} placeholder="IPv4 hoặc IPv6" />
          </label>
          <label className="text-sm font-medium">Từ thời điểm
            <input type="datetime-local" className={inputClass} value={draft.since} onChange={event => setDraft({ ...draft, since: event.target.value })} />
          </label>
          <label className="text-sm font-medium">Đến thời điểm
            <input type="datetime-local" className={inputClass} value={draft.until} onChange={event => setDraft({ ...draft, until: event.target.value })} />
          </label>
          <div className="flex items-end gap-3">
            <button className="inline-flex items-center gap-2 bg-sky-600 hover:bg-sky-700 text-white rounded-lg px-4 py-2 text-sm font-medium"><Search size={16} /> Tra cứu</button>
            <button type="button" onClick={() => onFilter({})} className="text-sm text-slate-600 underline py-2">Xóa bộ lọc</button>
          </div>
        </div>
        {validation && <p role="alert" className="text-sm text-rose-700 mt-3">{validation}</p>}
      </form>
      {error && <div role="alert" className="rounded-lg border border-rose-200 bg-rose-50 p-4 mb-4 text-sm text-rose-800">
        {error} <button onClick={() => setRevision(value => value + 1)} className="font-semibold underline ml-2">Thử lại</button>
      </div>}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden" aria-busy={loading}>
        {loading ? <p role="status" className="p-10 text-center text-sm text-slate-500">Đang tải nhật ký…</p> : data?.items.length === 0 ? (
          <p className="p-10 text-center text-sm text-slate-500">Không có sự kiện phù hợp với bộ lọc.</p>
        ) : data && <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Bảng nhật ký có thể cuộn ngang">
          <table className="w-full min-w-[1200px] text-left text-sm">
            <caption className="sr-only">Nhật ký kiểm toán với mã băm trước và mã băm từng bản ghi</caption>
            <thead className="bg-slate-50 text-slate-500 text-xs border-b border-slate-200">
              <tr>{['ID', 'Thời điểm', 'Sự kiện', 'Người thực hiện', 'Đối tượng', 'Kết quả', 'prev_hash', 'entry_hash'].map(label => <th key={label} scope="col" className="px-4 py-3 font-medium">{label}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data.items.map(entry => <tr key={entry.id} className="align-top hover:bg-slate-50/60">
                <td className="px-4 py-4 font-mono text-xs">{entry.id}</td>
                <td className="px-4 py-4 text-xs whitespace-nowrap">{new Date(entry.created_at).toLocaleString('vi-VN')}</td>
                <td className="px-4 py-4 min-w-52">
                  <p className="font-medium">{actionLabels[entry.action] ?? entry.action}</p>
                  <details className="mt-2 text-xs text-slate-500">
                    <summary className="cursor-pointer text-sky-700">Chi tiết</summary>
                    <p className="mt-2 break-all">IP {entry.client_ip ?? '—'} · {entry.user_agent ?? '—'}</p>
                    {!entry.details_valid && <p className="text-rose-700 mt-2">Dữ liệu chi tiết có định dạng bất thường.</p>}
                    <pre className="whitespace-pre-wrap break-all mt-2 max-w-64">{JSON.stringify(entry.details, null, 2)}</pre>
                  </details>
                </td>
                <td className="px-4 py-4"><code className="text-xs break-all block w-36">{entry.actor_id ?? 'Khách công khai'}</code></td>
                <td className="px-4 py-4"><p className="text-xs text-slate-500 mb-1">{entry.target_type}</p><code className="text-xs break-all block w-36">{entry.target_id ?? '—'}</code></td>
                <td className="px-4 py-4"><span className={`inline-block whitespace-nowrap rounded-full px-2 py-1 text-xs font-medium ${entry.status === 'SUCCESS' ? 'bg-emerald-50 text-emerald-700' : entry.status === 'DENIED' ? 'bg-rose-50 text-rose-700' : 'bg-amber-50 text-amber-800'}`}>{statusLabels[entry.status] ?? entry.status}</span></td>
                <td className="px-4 py-4"><code className="block w-44 break-all text-xs text-slate-500">{entry.prev_hash}</code></td>
                <td className="px-4 py-4"><code className="block w-44 break-all text-xs text-slate-600">{entry.entry_hash}</code></td>
              </tr>)}
            </tbody>
          </table>
        </div>}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 px-5 py-4">
          <p className="text-xs text-slate-500">{data ? data.total === 0 ? '0 sự kiện' : `${offset + 1}–${Math.min(offset + data.limit, data.total)} / ${data.total} sự kiện` : '—'}</p>
          <div className="flex gap-2">
            <button aria-label="Trang trước" disabled={loading || !data || offset === 0} onClick={() => setOffset(value => Math.max(0, value - 20))} className="p-2 rounded-lg border border-slate-300 disabled:opacity-40"><ChevronLeft size={16} /></button>
            <button aria-label="Trang sau" disabled={loading || !data || offset + 20 >= data.total} onClick={() => setOffset(value => value + 20)} className="p-2 rounded-lg border border-slate-300 disabled:opacity-40"><ChevronRight size={16} /></button>
          </div>
        </div>
      </div>
    </div>
  );
}
