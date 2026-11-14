import React from 'react';
import { Link } from 'react-router-dom';
import { FileQuestion, ArrowLeft } from 'lucide-react';

export const NotFound: React.FC = () => {
  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-slate-50">
      <div className="max-w-md w-full text-center space-y-6 bg-white p-8 rounded-2xl shadow-sm border border-slate-200">
        <div className="mx-auto w-16 h-16 rounded-2xl bg-slate-100 flex items-center justify-center text-slate-500">
          <FileQuestion className="w-8 h-8" />
        </div>

        <div>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">404 — Không tìm thấy trang</h1>
          <p className="mt-2 text-sm text-slate-500">
            Trang bạn đang tìm kiếm không tồn tại hoặc đã được di chuyển.
          </p>
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
