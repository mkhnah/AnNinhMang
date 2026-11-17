import { NavLink } from 'react-router-dom';

export function AdminNav() {
  return (
    <nav aria-label="Quản trị" className="flex gap-1 overflow-x-auto border-b border-slate-200 mb-7">
      {[
        ['/admin/dashboard', 'Tổng quan an ninh'],
        ['/admin/audit', 'Nhật ký kiểm toán'],
        ['/admin/pki', 'CA và danh tính'],
        ['/admin', 'Tài khoản'],
      ].map(([to, label]) => (
        <NavLink key={to} to={to} end className={({ isActive }) =>
          `whitespace-nowrap px-4 py-3 text-sm font-medium border-b-2 ${isActive
            ? 'border-sky-600 text-sky-700' : 'border-transparent text-slate-500 hover:text-slate-900'}`}>
          {label}
        </NavLink>
      ))}
    </nav>
  );
}
