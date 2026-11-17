import React from 'react';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, UserCheck, ShieldAlert, FileText, Lock, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Home: React.FC = () => {
  const { user } = useAuth();

  if (!user) return null;

  return (
    <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Welcome Banner */}
      <div className="bg-gradient-to-r from-sky-600 to-indigo-700 rounded-3xl p-8 text-white shadow-sm">
        <div className="max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 backdrop-blur-sm text-xs font-semibold mb-4 border border-white/20">
            <ShieldCheck className="w-4 h-4 text-sky-200" />
            <span>Phân Hệ Xác Thực & Phân Quyền An Toàn (Phase 1)</span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">
            Xin chào, {user.full_name}!
          </h1>

        </div>
      </div>

      {/* Feature Highlights Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col justify-between">
          <div>
            <div className="w-12 h-12 rounded-xl bg-sky-50 text-sky-600 flex items-center justify-center mb-4 border border-sky-100">
              <UserCheck className="w-6 h-6" />
            </div>
            <h3 className="font-bold text-slate-900 text-lg">Hồ sơ người dùng</h3>

          </div>
          <div className="mt-6">
            <Link
              to="/profile"
              className="inline-flex items-center text-sm font-semibold text-sky-600 hover:text-sky-700"
            >
              Xem hồ sơ <ArrowRight className="w-4 h-4 ml-1" />
            </Link>
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col justify-between">
          <div>
            <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center mb-4 border border-emerald-100">
              <Lock className="w-6 h-6" />
            </div>
            <h3 className="font-bold text-slate-900 text-lg">Bảo mật mật mã</h3>

          </div>
          <div className="mt-6">
            <span className="inline-flex items-center text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
              Đạt chuẩn NIST & OWASP
            </span>
          </div>
        </div>

        {user.role === 'ADMIN' ? (
          <div className="bg-white p-6 rounded-2xl border border-purple-200 shadow-sm flex flex-col justify-between bg-gradient-to-br from-white to-purple-50/30">
            <div>
              <div className="w-12 h-12 rounded-xl bg-purple-50 text-purple-600 flex items-center justify-center mb-4 border border-purple-100">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <h3 className="font-bold text-purple-950 text-lg">Quản trị hệ thống</h3>

            </div>
            <div className="mt-6">
              <Link
                to="/admin"
                className="inline-flex items-center text-sm font-semibold text-purple-700 hover:text-purple-800"
              >
                Vào trang quản trị <ArrowRight className="w-4 h-4 ml-1" />
              </Link>
            </div>
          </div>
        ) : (
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col justify-between">
            <div>
              <div className="w-12 h-12 rounded-xl bg-slate-50 text-slate-600 flex items-center justify-center mb-4 border border-slate-100">
                <FileText className="w-6 h-6" />
              </div>
              <h3 className="font-bold text-slate-900 text-lg">Sắp ra mắt (Phase 2)</h3>

            </div>
            <div className="mt-6">
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 text-slate-600">
                Sẵn sàng cho Phase 2
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
