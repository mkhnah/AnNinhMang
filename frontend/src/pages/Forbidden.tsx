import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldX, ArrowLeft } from 'lucide-react';

export const Forbidden: React.FC = () => {
  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-slate-50">
      <div className="max-w-md w-full text-center space-y-6 bg-white p-8 rounded-2xl shadow-sm border border-slate-200">
        <div className="mx-auto w-16 h-16 rounded-2xl bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-600">
          <ShieldX className="w-9 h-9" />
        </div>

        <div>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">403 — Truy cập bị từ chối</h1>

        </div>

        <div className="pt-2">
          <Link
            to="/"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-sky-600 hover:bg-sky-700 transition-colors shadow-sm"
          >
            <ArrowLeft className="w-4 h-4" />
            Trở về trang chủ
          </Link>
        </div>
      </div>
    </div>
  );
};
