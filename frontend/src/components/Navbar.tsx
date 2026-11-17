import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { ShieldCheck, FileText, KeyRound, BadgeCheck, ScanLine, LayoutDashboard, LogOut, Menu, X, UserRound } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {setOpen(false);}, [location.pathname]);
  const links = [
    ...(user ? [{to:'/', label:'Tài liệu', icon:FileText}, {to:'/keys', label:'Khóa ký', icon:KeyRound}, {to:'/certificates', label:'Chứng chỉ', icon:BadgeCheck}] : []),
    {to:'/verify', label:'Xác minh', icon:ScanLine},
    ...(user?.role === 'ADMIN' ? [{to:'/admin/dashboard', label:'Quản trị', icon:LayoutDashboard}] : []),
  ];
  const items = links.map(({to,label,icon:Icon}) => <NavLink key={to} to={to} end={to === '/'}
    className={({isActive}) => 'app-nav-link ' + (isActive || (to === '/' && location.pathname.startsWith('/documents')) || (to === '/admin/dashboard' && location.pathname.startsWith('/admin')) ? 'is-active' : '')}>
    <Icon size={18} aria-hidden="true" /><span>{label}</span>
  </NavLink>);
  const signOut = async () => {try {await logout(); navigate('/login');} catch {setError('Không thể đăng xuất.');}};
  return <header className="app-header">
    <div className="app-header-inner">
      <Link to="/" className="app-brand" aria-label="DocSign"><span className="app-brand-icon"><ShieldCheck size={23}/></span>DocSign<span className="brand-dot">.</span></Link>
      <nav className="app-desktop-nav" aria-label="Điều hướng chính">{items}</nav>
      <div className="app-account">
        {user ? <><Link to="/profile" className="app-profile" aria-label="Hồ sơ"><span className="app-avatar">{user.full_name?.charAt(0).toUpperCase() || <UserRound size={17}/>}</span><span className="app-account-name">{user.full_name}</span></Link>
          <button onClick={() => {void signOut();}} className="icon-button" aria-label="Đăng xuất" title="Đăng xuất"><LogOut size={18}/></button></>
          : <><Link to="/login" className="app-login">Đăng nhập</Link><Link to="/register" className="ui-button ui-button-primary app-register">Đăng ký</Link></>}
        <button className="icon-button app-menu-toggle" aria-label={open ? 'Đóng menu' : 'Mở menu'} aria-expanded={open} aria-controls="mobile-navigation" onClick={() => setOpen(!open)}>{open ? <X size={21}/> : <Menu size={21}/>}</button>
      </div>
    </div>
    {open && <nav id="mobile-navigation" className="app-mobile-nav" aria-label="Điều hướng trên điện thoại">{items}{user && <NavLink to="/profile" className="app-nav-link"><UserRound size={18}/>Hồ sơ</NavLink>}</nav>}
    {error && <p role="alert" className="ui-alert ui-alert-error">{error}</p>}
  </header>;
}
