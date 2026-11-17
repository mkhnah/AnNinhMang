import { NavLink } from 'react-router-dom';
import { FileCheck2, BadgeCheck, Fingerprint, Users } from 'lucide-react';
export function VerificationTabs() {
  return <nav className="verification-tabs" aria-label="Loại xác minh">
    {[{to:'/verify',label:'Tài liệu PDF',icon:FileCheck2},{to:'/verify/signature',label:'Chữ ký số',icon:Fingerprint},{to:'/verify/certificate',label:'Chứng chỉ số',icon:BadgeCheck},{to:'/verify/users',label:'Tra cứu người dùng',icon:Users}].map(({to,label,icon:Icon})=>
      <NavLink key={to} to={to} end className={({isActive})=>`verification-tab ${isActive?'is-active':''}`}><Icon size={18}/><span>{label}</span></NavLink>)}
  </nav>;
}
