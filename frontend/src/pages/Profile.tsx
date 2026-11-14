import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, Calendar, LogOut, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const Profile: React.FC = () => {
  const { user, logoutAll } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!user) return null;

  const handleLogoutAll = async () => {
    if (!window.confirm('Bạn có chắc chắn muốn đăng xuất khỏi tất cả thiết bị? Tất cả phiên làm việc hiện tại sẽ bị hủy.')) {
      return;
    }

    setLoading(true);
    setMessage(null);
    setError(null);
    try {
      const msg = await logoutAll();
      setMessage(msg);
      setTimeout(() => {
        navigate('/login');
      }, 1500);
    } catch {
      setError('Không thể thực hiện đăng xuất tất cả phiên. Vui lòng thử lại.');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (isoString?: string | null) => {
    if (!isoString) return 'Chưa ghi nhận';
    return new Date(isoString).toLocaleString('vi-VN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
      {/* Page Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Hồ sơ người dùng</h1>
        <p className="text-sm text-slate-500">Quản lý danh tính, bảo mật phiên và thông tin tài khoản</p>
      </div>

      {/* Messages */}
      {message && (
        <div className="mb-6 p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-sm flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-600" />
          <span>{message}</span>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-600" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Left Column: Avatar & Role */}
        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col items-center text-center">
          <div className="w-20 h-20 rounded-full bg-sky-100 border-2 border-sky-200 flex items-center justify-center text-sky-700 text-2xl font-bold mb-4 shadow-inner">
            {user.full_name.charAt(0).toUpperCase()}
          </div>
          <h2 className="text-lg font-bold text-slate-900">{user.full_name}</h2>
          <p className="text-sm text-slate-500 mb-4">{user.email}</p>

          <span
            className={`text-xs font-semibold px-3 py-1 rounded-full ${
              user.role === 'ADMIN'
                ? 'bg-purple-100 text-purple-800 border border-purple-200'
                : 'bg-sky-100 text-sky-800 border border-sky-200'
            }`}
          >
            Vai trò: {user.role}
          </span>
        </div>

        {/* Right Column: Account Details & Security Actions */}
        <div className="md:col-span-2 space-y-6">
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <h3 className="text-base font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-sky-600" />
              Chi tiết tài khoản & Bảo mật
            </h3>

            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
              <div className="p-3 bg-slate-50 rounded-xl">
                <dt className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Mã định danh (UUID)</dt>
                <dd className="font-mono text-xs text-slate-800 break-all">{user.id}</dd>
              </div>

              <div className="p-3 bg-slate-50 rounded-xl">
                <dt className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Trạng thái tài khoản</dt>
                <dd className="flex items-center gap-1.5 font-medium text-emerald-700">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
                  {user.status}
                </dd>
              </div>

              <div className="p-3 bg-slate-50 rounded-xl">
                <dt className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Ngày đăng ký</dt>
                <dd className="text-slate-800 flex items-center gap-1.5">
                  <Calendar className="w-4 h-4 text-slate-400" />
                  {formatDate(user.created_at)}
                </dd>
              </div>

              <div className="p-3 bg-slate-50 rounded-xl">
                <dt className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Đăng nhập gần nhất</dt>
                <dd className="text-slate-800 flex items-center gap-1.5">
                  <Calendar className="w-4 h-4 text-slate-400" />
                  {formatDate(user.last_login_at)}
                </dd>
              </div>
            </dl>
          </div>

          {/* Session Security Control */}
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <h3 className="text-base font-semibold text-slate-900 mb-2 flex items-center gap-2 text-rose-700">
              <LogOut className="w-5 h-5 text-rose-600" />
              Quản lý phiên đăng nhập
            </h3>
            <p className="text-sm text-slate-500 mb-4">
              Trong trường hợp nghi ngờ tài khoản bị lộ hoặc quên đăng xuất trên thiết bị công cộng, bạn có thể vô hiệu hóa toàn bộ các phiên làm việc đang hoạt động.
            </p>

            <button
              onClick={handleLogoutAll}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 bg-rose-50 hover:bg-rose-100 text-rose-700 font-medium text-sm rounded-xl border border-rose-200 transition-colors disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Đang hủy tất cả phiên...
                </>
              ) : (
                <>
                  <LogOut className="w-4 h-4" />
                  Đăng xuất khỏi tất cả thiết bị
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
