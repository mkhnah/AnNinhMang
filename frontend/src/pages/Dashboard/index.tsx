import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowUpRight, CheckCircle2, FileText, KeyRound, RefreshCw, ShieldCheck } from 'lucide-react';
import { auditApi, ChainResult, DashboardStats, verificationLabels } from '../../api/audit';
import { AdminNav } from '../../components/AdminNav';

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [error, setError] = useState('');
  const [chainError, setChainError] = useState('');
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => setRevision(value => value + 1), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setStats(null);
    setChain(null);
    setError('');
    setChainError('');
    Promise.allSettled([auditApi.stats(controller.signal), auditApi.verifyChain(controller.signal)]).then(([metrics, integrity]) => {
      if (controller.signal.aborted) return;
      if (metrics.status === 'fulfilled') setStats(metrics.value);
      else setError('Không thể tải thống kê và cảnh báo. Hãy thử lại.');
      if (integrity.status === 'fulfilled') setChain(integrity.value);
      else setChainError('Không thể kiểm tra chuỗi băm. Hãy thử lại.');
      setLoading(false);
    });
    return () => controller.abort();
  }, [revision]);

  const peak = Math.max(1, ...(stats?.verification_daily.map(day => day.verified + day.unsuccessful) ?? []));

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
      <AdminNav />
      <div className="flex flex-wrap items-start justify-between gap-4 mb-7">
        <div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-slate-900">Tổng quan an ninh</h1>

        </div>
        <button onClick={() => setRevision(value => value + 1)} disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium disabled:opacity-50">
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Làm mới
        </button>
      </div>

      <section aria-label="Toàn vẹn nhật ký" className={`rounded-xl border px-5 py-4 mb-6 ${chain?.valid
        ? 'border-emerald-200 bg-emerald-50' : chain ? 'border-rose-300 bg-rose-50' : 'border-slate-200 bg-white'}`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            {chain?.valid ? <ShieldCheck className="text-emerald-700 shrink-0" /> : <AlertTriangle className="text-slate-500 shrink-0" />}
            <div>
              <p className="font-semibold">{chain ? chain.valid ? 'AUDIT LOG INTACT' : 'Phát hiện bất thường trong chuỗi băm' : loading ? 'Đang kiểm tra chuỗi băm…' : 'Trạng thái chuỗi băm chưa xác định'}</p>
              {chain && <p className="text-sm mt-1">Đã kiểm tra {chain.checked_entries.toLocaleString('vi-VN')} bản ghi
                {chain.error_id && ` · Vị trí lỗi ${chain.error_id}`}
                {chain.reason && ` · ${chain.reason}`}</p>}
              {chainError && <p role="alert" className="text-sm text-rose-700 mt-1">{chainError}</p>}
            </div>
          </div>
          <Link to="/admin/audit" className="text-sm font-medium inline-flex items-center gap-1">Xem nhật ký <ArrowUpRight size={16} /></Link>
        </div>
      </section>

      {error && <div role="alert" className="p-4 rounded-lg bg-rose-50 text-rose-800 border border-rose-200 mb-6">{error}</div>}
      {loading && <p role="status" className="text-sm text-slate-500 py-8">Đang tải thống kê và cảnh báo…</p>}
      {stats && <>
        {stats.pki_counts && <section className="rounded-xl border bg-white p-5 mb-6"><h2 className="font-semibold mb-3">Chứng chỉ và CA</h2><div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
          {Object.entries({certificates:'Chứng chỉ đã cấp',revoked:'Đã thu hồi',expiring:'Hết hạn trong 30 ngày',pending_reviews:'Danh tính chờ duyệt'}).map(([key,label]) => <div key={key}><p className="text-slate-500">{label}</p><p className="text-2xl font-semibold mt-2">{stats.pki_counts?.[key] ?? 0}</p></div>)}
        </div><Link to="/admin/pki" className="inline-block text-sky-700 text-sm mt-4">Quản trị CA và danh tính →</Link></section>}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {[
            { label: 'Tài liệu', value: stats.total_documents.toLocaleString('vi-VN'), detail: `${stats.total_versions} phiên bản`, icon: FileText },
            { label: 'Phiên bản đã ký', value: stats.signed_versions.toLocaleString('vi-VN'), detail: '', icon: ShieldCheck },
            { label: 'Khóa đang hoạt động', value: stats.active_keys.toLocaleString('vi-VN'), detail: '', icon: KeyRound },
            { label: 'Xác minh thành công', value: stats.verification_success_rate === null ? '—' : `${stats.verification_success_rate.toLocaleString('vi-VN')}%`, detail: `${stats.verification_total} lượt trong 30 ngày`, icon: CheckCircle2 },
          ].map(card => <section key={card.label} className="rounded-xl border border-slate-200 bg-white p-5">
            <div className="flex items-center justify-between text-slate-500 text-sm"><span>{card.label}</span><card.icon size={18} /></div>
            <p className="text-3xl font-semibold tracking-tight mt-4">{card.value}</p>
            {card.detail && <p className="text-xs text-slate-500 mt-2">{card.detail}</p>}
          </section>)}
        </div>

        <section aria-label="Cảnh báo an ninh" className={`rounded-xl border p-5 mb-6 ${stats.alert_total > 0 ? 'bg-rose-50 border-rose-300' : 'bg-white border-slate-200'}`}>
          <div className="flex flex-wrap justify-between gap-2 mb-3">
            <h2 className="font-semibold flex items-center gap-2"><AlertTriangle size={18} /> Cảnh báo an ninh</h2>
            <span className="text-sm text-slate-500">{stats.alert_window_minutes} phút gần nhất</span>
          </div>
          {stats.alert_total === 0 ? <p className="text-sm text-slate-500">Chưa ghi nhận cảnh báo trong khoảng thời gian này.</p> : <>
            <ul className="divide-y divide-rose-200">
              {stats.alerts.map(alert => <li key={`${alert.code}-${alert.actor_id}-${alert.client_ip}`} className="py-3 text-sm">
                <p className="font-semibold text-rose-800">{alert.code === 'IDOR_ATTEMPT'
                  ? `${alert.count} lần bị chặn khi truy cập tài nguyên trái quyền`
                  : alert.code === 'CA_UNTRUSTED' ? `${alert.count} CA không còn được tin cậy`
                  : alert.code === 'CERTIFICATE_EXPIRING' ? `${alert.count} chứng chỉ hết hạn trong 30 ngày`
                  : alert.code === 'REPEATED_CERTIFICATE_FAILURE' ? `${alert.count} lần kiểm tra chứng chỉ / chữ ký gần nhất thất bại`
                  : `${alert.count} lần xác minh gần nhất liên tiếp chưa thành công`}</p>
                <p className="mt-1 break-all text-slate-600">{alert.actor_id ? `Tài khoản ${alert.actor_id}` : alert.client_ip ? `IP ${alert.client_ip}` : 'Toàn hệ thống'}</p>
                <Link className="inline-block text-sky-700 underline mt-2" to={['CERTIFICATE_EXPIRING','CA_UNTRUSTED'].includes(alert.code) ? '/admin/pki' : `/admin/audit?${new URLSearchParams({
                  action: alert.code === 'IDOR_ATTEMPT' ? 'ACCESS_DENIED_IDOR' : alert.code === 'REPEATED_CERTIFICATE_FAILURE' ? 'CERTIFICATE_VERIFY' : 'DOCUMENT_VERIFY',
                  ...(alert.actor_id ? { actor_id: alert.actor_id } : alert.client_ip ? { client_ip: alert.client_ip } : {}),
                  since: new Date(new Date(stats.generated_at).getTime() - stats.alert_window_minutes * 60_000).toISOString(),
                })}`}>Tra cứu sự kiện</Link>
              </li>)}
            </ul>
            {stats.alert_total > stats.alerts.length && <p className="text-sm text-rose-800 mt-3">Hiển thị {stats.alerts.length} trên {stats.alert_total} cảnh báo gần nhất.</p>}
          </>}
        </section>

        <div className="grid lg:grid-cols-5 gap-6">
          <section className="lg:col-span-3 rounded-xl border border-slate-200 bg-white p-5">
            <h2 className="font-semibold">Lượt xác minh trong 7 ngày</h2>

            <div role="img" aria-label="Biểu đồ lượt xác minh theo ngày" className="grid grid-cols-7 gap-2 sm:gap-4 mt-6">
              {stats.verification_daily.map(day => <div key={day.date} className="min-w-0 text-center">
                <div className="h-36 flex flex-col justify-end items-center" title={`${day.date} · Thành công ${day.verified} · Chưa thành công ${day.unsuccessful}`}>
                  <span className="text-xs text-slate-500 mb-2">{day.verified + day.unsuccessful}</span>
                  <div className="w-full max-w-10 bg-rose-300 rounded-t" style={{ height: `${day.unsuccessful / peak * 100}px` }} />
                  <div className="w-full max-w-10 bg-sky-600" style={{ height: `${day.verified / peak * 100}px` }} />
                </div>
                <span className="text-xs text-slate-500 block mt-3">{day.date.slice(8)}/{day.date.slice(5, 7)}</span>
                <span className="sr-only">{day.date}, thành công {day.verified}, chưa thành công {day.unsuccessful}</span>
              </div>)}
            </div>
            <div className="flex flex-wrap gap-4 text-xs text-slate-500 mt-5"><span><span className="inline-block w-2 h-2 rounded-sm bg-sky-600 mr-2" />Thành công</span><span><span className="inline-block w-2 h-2 rounded-sm bg-rose-300 mr-2" />Chưa thành công</span></div>
          </section>
          <section className="lg:col-span-2 rounded-xl border border-slate-200 bg-white p-5">
            <h2 className="font-semibold mb-5">Kết quả xác minh trong 30 ngày</h2>
            {stats.verification_total === 0 && <p className="text-sm text-slate-500 mb-4">Chưa có lượt xác minh.</p>}
            <ul className="space-y-4">
              {stats.verification_counts.map(item => <li key={item.status}>
                <div className="flex justify-between gap-3 text-sm mb-2"><span>{verificationLabels[item.status] ?? item.status}</span><span className="font-medium">{item.count}</span></div>
                <div className="h-1.5 bg-slate-100 rounded-full"><div className={`h-full rounded-full ${item.status === 'VERIFIED' ? 'bg-sky-600' : 'bg-slate-400'}`} style={{ width: `${stats.verification_total ? item.count / stats.verification_total * 100 : 0}%` }} /></div>
              </li>)}
            </ul>
          </section>
        </div>
        <p className="text-xs text-slate-500 mt-5">Cập nhật {new Date(stats.generated_at).toLocaleString('vi-VN')}</p>
      </>}
    </div>
  );
}
