import { useEffect, useRef, useState } from 'react';
import { BadgeCheck, Fingerprint, Search, Loader2 } from 'lucide-react';
import { VerificationTabs } from '../../components/Verification/VerificationTabs';
import { FilePicker } from '../../components/ui/FilePicker';
import { pkiApi } from '../../api/pki';
import { PkiResult } from '../../types/pki';
import { PkiResultPanel } from '../../components/Verification/PkiResultPanel';

export function PkiVerify({signature = false}: {signature?: boolean}) {
    const [certificateFile, setCertificateFile] = useState<File | null>(null);
    const [signatureFile, setSignatureFile] = useState<File | null>(null);
    const [result, setResult] = useState<PkiResult | null>(null);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const generation = useRef(0);
    const controller = useRef<AbortController>();
    const invalidate = () => { generation.current++; controller.current?.abort(); setResult(null); setError(''); setBusy(false); };
    useEffect(() => { invalidate(); return () => {generation.current++; controller.current?.abort();}; }, [signature]);
    const chooseCert = (file?: File) => {
        invalidate(); setCertificateFile(null);
        if (!file) return;
        if (!/\.(pem|crt)$/i.test(file.name)) { setError('Chọn tệp chứng chỉ PEM (.pem hoặc .crt).'); return; }
        if (file.size > 16384) { setError('Chứng chỉ vượt giới hạn 16 KB'); return; }
        setCertificateFile(file);
    };
    const chooseSignature = (file?: File) => {
        invalidate(); setSignatureFile(null);
        if (!file) return;
        if (!file.name.toLowerCase().endsWith('.json')) { setError('Chọn tệp signature-package.json do hệ thống xuất ra.'); return; }
        if (file.size > 524288) { setError('Tệp signature vượt giới hạn 512 KB'); return; }
        setSignatureFile(file);
    };
    const submit = async (event: React.FormEvent) => {
        event.preventDefault(); invalidate();
        const id = generation.current;
        const abort = new AbortController(); controller.current = abort;
        setBusy(true);
        try {
            if (!certificateFile) throw new Error('Vui lòng chọn tệp chứng chỉ số.');
            if (signature && !signatureFile) throw new Error('Vui lòng chọn tệp signature-package.json.');
            const pem = await certificateFile.text();
            if (id !== generation.current) return;
            let verified;
            if (signature) {
                const content = await signatureFile!.text();
                if (id !== generation.current) return;
                verified = await pkiApi.verifySignature(pem, content, abort.signal);
            } else verified = await pkiApi.verifyCertificate(pem, abort.signal);
            if (id === generation.current) setResult(verified);
        } catch (err) {
            if (id !== generation.current) return;
            const detail = (err as {response?: {data?: {detail?: unknown}}})?.response?.data?.detail;
            setError(typeof detail === 'string' ? detail : err instanceof Error ? err.message : 'Không thể xác minh');
        } finally { if (id === generation.current) setBusy(false); }
    };
    return <div className="verify-page">
        <VerificationTabs />
        <header className="ui-page-header"><h1>{signature?'Xác minh chữ ký số':'Xác minh chứng chỉ số'}</h1><span className="certificate-icon">{signature?<Fingerprint size={24}/>:<BadgeCheck size={24}/>}</span></header>
        <p className="mb-6 text-slate-600">{signature
            ? 'Tải file signature và chứng chỉ số để kiểm tra chữ ký có khớp với chứng chỉ hay không. Để kiểm tra tính toàn vẹn của PDF, chọn mục Tài liệu PDF.'
            : 'Tải chứng chỉ số để xem thông tin chủ thể, đơn vị cấp, thời hạn và trạng thái thu hồi.'}</p>
        <form onSubmit={submit} className="ui-card ui-card-body verify-form">
            {signature&&<section className="form-section"><h2 className="text-sm font-semibold">File signature</h2>
                <p className="text-sm text-slate-500">Sử dụng tệp signature-package.json được xuất sau khi ký tài liệu.</p>
                <FilePicker label="Chọn file signature" accept=".json,application/json" file={signatureFile} onChange={chooseSignature} />
            </section>}
            <section className="form-section"><h2 className="text-sm font-semibold">Chứng chỉ số</h2>
                <FilePicker label="Tải chứng chỉ PEM" accept=".pem,.crt" file={certificateFile} onChange={chooseCert} />
            </section>
            {error&&<p role="alert" className="ui-alert ui-alert-error">{error}</p>}
            <footer className="verify-actions"><button disabled={busy||!certificateFile||(signature&&!signatureFile)} className="ui-button ui-button-primary">{busy?<Loader2 size={17} className="animate-spin"/>:<Search size={17}/>} {busy?'Đang xác minh…':'Bắt đầu xác minh'}</button></footer>
        </form>
        {result&&<div className="mt-6"><PkiResultPanel result={result}/></div>}
    </div>;
}
