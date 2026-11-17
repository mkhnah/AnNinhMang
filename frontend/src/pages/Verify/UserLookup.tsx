import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Copy, Loader2, Search, Users } from 'lucide-react';
import { usersApi, UserLookupPage } from '../../api/users';
import { VerificationTabs } from '../../components/Verification/VerificationTabs';

const statuses = {ACTIVE:'Đang hoạt động', LOCKED:'Tạm khóa', DISABLED:'Đã vô hiệu hóa'};

export function UserLookup() {
    const [params] = useSearchParams();
    const expectedUuid = (params.get('uuid') || '').trim().toLowerCase().slice(0, 36);
    const initialQuery = (params.get('q') || expectedUuid).slice(0, 255);
    const [query, setQuery] = useState(initialQuery);
    const [page, setPage] = useState<UserLookupPage | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');
    const [notice, setNotice] = useState('');
    const generation = useRef(0);
    const controller = useRef<AbortController>();

    const invalidate = useCallback(() => {
        generation.current++; controller.current?.abort();
        setPage(null); setError(''); setNotice(''); setBusy(false);
    }, []);
    const search = useCallback(async (value: string, offset = 0) => {
        invalidate();
        const text = value.trim();
        if (text.length < 2) {setError('Nhập ít nhất 2 ký tự để tìm kiếm.'); return;}
        const id = generation.current;
        const abort = new AbortController(); controller.current = abort;
        setBusy(true);
        try {
            const data = await usersApi.search(text, offset, abort.signal);
            if (generation.current === id) setPage(data);
        } catch {
            if (generation.current === id) setError('Không thể tìm kiếm người dùng. Vui lòng thử lại.');
        } finally {if (generation.current === id) setBusy(false);}
    }, [invalidate]);
    useEffect(() => {
        setQuery(initialQuery);
        if (initialQuery.trim().length >= 2) void search(initialQuery);
        else invalidate();
        return () => {generation.current++; controller.current?.abort();};
    }, [initialQuery, search, invalidate]);
    const copy = async (uuid: string) => {
        const id = generation.current;
        try {
            await navigator.clipboard.writeText(uuid);
            if (generation.current === id) setNotice('Đã sao chép UUID: ' + uuid);
        } catch {
            if (generation.current === id) setError('Không thể sao chép tự động. Bạn có thể chọn và sao chép UUID bên dưới.');
        }
    };

    return <div className="verify-page">
        <VerificationTabs />
        <header className="ui-page-header"><h1>Tra cứu người dùng</h1><span className="certificate-icon"><Users size={24}/></span></header>
        <p className="mb-6 text-slate-600">Tìm theo họ tên, email hoặc UUID để đối chiếu mã tài khoản trên chứng chỉ và chữ ký.</p>
        {expectedUuid&&<div className="ui-alert mb-6"><p>UUID cần đối chiếu</p><code className="break-all">{expectedUuid}</code></div>}
        <form onSubmit={event=>{event.preventDefault();void search(query);}} className="ui-card ui-card-body grid gap-4 mb-6">
            <label className="ui-field">Tìm kiếm người dùng<input type="search" value={query} maxLength={255} placeholder="Nhập họ tên, email hoặc UUID" onChange={event=>{invalidate();setQuery(event.target.value);}} /></label>
            <div className="verify-actions"><button disabled={busy||query.trim().length<2} className="ui-button ui-button-primary">{busy?<Loader2 size={17} className="animate-spin"/>:<Search size={17}/>} {busy?'Đang tìm…':'Tìm kiếm'}</button></div>
        </form>
        {error&&<p role="alert" className="ui-alert ui-alert-error mb-6">{error}</p>}
        {notice&&<p role="status" className="ui-alert ui-alert-success mb-6">{notice}</p>}
        {page&&<section aria-label="Kết quả tìm kiếm người dùng" className="space-y-4">
            <p role="status">Tìm thấy {page.total} người dùng.</p>
            {page.items.length===0&&<div className="ui-card ui-card-body">Không tìm thấy người dùng phù hợp.</div>}
            {page.items.map(person=><article key={person.id} className="ui-card ui-card-body space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3"><div className="min-w-0"><h2 className="font-semibold break-words">{person.full_name}</h2><p className="text-sm text-slate-500 break-all">{person.email}</p></div><span className={'ui-badge '+(person.status==='ACTIVE'?'ui-badge-success':'ui-badge-warning')}>{statuses[person.status]}</span></div>
                <dl className="ui-data"><div className="full-width"><dt>UUID người dùng</dt><dd><code className="break-all select-all">{person.id}</code></dd></div></dl>
                <div className="flex flex-wrap items-center gap-3"><button type="button" className="ui-button" aria-label={'Sao chép UUID của '+person.full_name} onClick={()=>{void copy(person.id);}}><Copy size={16}/>Sao chép UUID</button>
                    {expectedUuid&&<span className={'ui-badge '+(person.id.toLowerCase()===expectedUuid?'ui-badge-success':'ui-badge-warning')}>{person.id.toLowerCase()===expectedUuid?'Khớp UUID cần đối chiếu':'Không khớp UUID cần đối chiếu'}</span>}
                </div>
            </article>)}
            {page.total>page.limit&&<div className="ui-pagination"><button type="button" className="ui-button" disabled={busy||page.offset===0} onClick={()=>{void search(query,Math.max(0,page.offset-page.limit));}}>Trang trước</button><span>Trang {Math.floor(page.offset/page.limit)+1} / {Math.ceil(page.total/page.limit)}</span><button type="button" className="ui-button" disabled={busy||page.offset+page.limit>=page.total} onClick={()=>{void search(query,page.offset+page.limit);}}>Trang sau</button></div>}
            <p className="text-sm text-slate-500">Họ tên tài khoản do người dùng khai báo. Đối chiếu UUID xác định tài khoản trong hệ thống; việc kiểm tra chứng chỉ và chữ ký được thực hiện ở các mục tương ứng.</p>
        </section>}
    </div>;
}
