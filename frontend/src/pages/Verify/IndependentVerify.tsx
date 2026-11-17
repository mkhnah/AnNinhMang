import React, { useState, useRef, useEffect } from 'react';
import { Search, Loader2, RotateCcw, FileCheck2 } from 'lucide-react';
import { VerificationResultResponse } from '../../types/verify';
import { verifyApi } from '../../api/verify';
import { VerificationResultPanel } from '../../components/Verification/VerificationResultPanel';
import { VerificationTabs } from '../../components/Verification/VerificationTabs';
import { FilePicker } from '../../components/ui/FilePicker';

export const IndependentVerify: React.FC = () => {
    const [pdfFile, setPdfFile] = useState<File | null>(null);
    const [packageFile, setPackageFile] = useState<File | null>(null);

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [result, setResult] = useState<VerificationResultResponse | null>(null);

    const [verifiedFileName, setVerifiedFileName] = useState('');
    const generation = useRef(0);
    const request = useRef<AbortController | null>(null);
    const invalidate = () => {
        generation.current += 1;
        request.current?.abort();
        request.current = null;
        setResult(null);
        setVerifiedFileName('');
        setIsSubmitting(false);
    };
    useEffect(() => () => {
        generation.current += 1;
        request.current?.abort();
    }, []);

    const handlePdfSelect = (file?: File) => {
        if (!file) return;
        invalidate();
        setPdfFile(null);
        if (!file.name.toLowerCase().endsWith('.pdf')) {
            setError('Tệp tài liệu bắt buộc phải có định dạng .pdf.');
            return;
        }
        if (file.size > 20 * 1024 * 1024) {
            setError('Tệp PDF vượt quá giới hạn tối đa 20 MB.');
            return;
        }
        setError(null);
        setPdfFile(file);
    };

    const handlePkgSelect = (file?: File) => {
        if (!file) return;
        invalidate();
        setPackageFile(null);
        if (!file.name.toLowerCase().endsWith('.json')) {
            setError('Gói bằng chứng chữ ký bắt buộc phải là tệp định dạng .json.');
            return;
        }
        if (file.size > 512 * 1024) {
            setError('Tệp signature-package.json vượt quá kích thước 512 KB.');
            return;
        }
        setError(null);
        setPackageFile(file);
    };

    const handleReset = () => {
        invalidate();
        setPdfFile(null);
        setPackageFile(null);
        setError(null);
        setResult(null);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!pdfFile) {
            setError('Vui lòng chọn tệp PDF cần xác minh.');
            return;
        }

        if (!packageFile) {
            setError('Vui lòng chọn tệp signature-package.json.');
            return;
        }

        const snapshot = Object.freeze({ pdf: pdfFile, package: packageFile });
        request.current?.abort();
        const controller = new AbortController();
        request.current = controller;
        const id = ++generation.current;
        setResult(null);
        setIsSubmitting(true);
        try {
            const args = [
                snapshot.pdf,
                snapshot.package,
                null,
                controller.signal
            ] as const;
            const verification = await verifyApi.verifyIndependent(...args);
            if (generation.current !== id || controller.signal.aborted) return;
            setVerifiedFileName(snapshot.pdf.name);
            setResult(verification);
        } catch (err: unknown) {
            if (generation.current !== id || controller.signal.aborted) return;
            const res = (err as { response?: { data?: { detail?: string } } })?.response;
            const detail = res?.data?.detail;
            setError(
                typeof detail === 'string'
                    ? detail
                    : 'Không thể xác minh tài liệu. Vui lòng kiểm tra lại tính hợp lệ của tệp PDF và gói chữ ký.'
            );
        } finally {
            if (generation.current === id) setIsSubmitting(false);
        }
    };

    return <div className="verify-page">
      <VerificationTabs/>
      <header className="ui-page-header"><h1>Xác minh tài liệu PDF</h1><span className="certificate-icon"><FileCheck2 size={24}/></span></header>
      <p className="mb-6 text-slate-600">Tải tài liệu PDF và file signature tương ứng để kiểm tra tính toàn vẹn của tài liệu và chữ ký.</p>
      {result?<div className="space-y-6"><div className="ui-card ui-card-body flex flex-wrap gap-4 items-center justify-between"><strong className="break-all">{verifiedFileName}</strong><button type="button" onClick={handleReset} className="ui-button"><RotateCcw size={16}/>Xác minh tài liệu khác</button></div><VerificationResultPanel result={result} documentTitle={verifiedFileName}/></div>:
      <form onSubmit={handleSubmit} className="ui-card ui-card-body verify-form">
        <section className="form-section"><div className="form-section-header"><h2>Tài liệu PDF</h2>{pdfFile&&<button type="button" className="text-sm text-sky-700" onClick={()=>{invalidate();setPdfFile(null);}}>Đổi tệp khác</button>}</div>
          <FilePicker label="Chọn tệp PDF" accept=".pdf,application/pdf" file={pdfFile} onChange={file=>{if(!file){invalidate();setPdfFile(null);}else handlePdfSelect(file);}}/>
        </section>
        <section className="form-section"><div className="form-section-header"><h2>File signature</h2></div>
          <p className="text-sm text-slate-500">Sử dụng tệp signature-package.json được xuất sau khi ký tài liệu.</p>
          <FilePicker label="Chọn tệp JSON" accept=".json,application/json" file={packageFile} onChange={file=>{if(!file){invalidate();setPackageFile(null);}else handlePkgSelect(file);}}/>
          {packageFile&&<button type="button" className="text-sm text-sky-700 justify-self-start" onClick={()=>{invalidate();setPackageFile(null);}}>Đổi tệp</button>}
        </section>
        {error&&<p role="alert" className="ui-alert ui-alert-error">{error}</p>}
        <footer className="verify-actions gap-3"><button type="button" onClick={handleReset} disabled={isSubmitting} className="ui-button">Làm mới</button><button type="submit" disabled={isSubmitting||!pdfFile||!packageFile} className="ui-button ui-button-primary">{isSubmitting?<Loader2 size={17} className="animate-spin"/>:<Search size={17}/>} {isSubmitting?'Đang xác minh…':'Bắt đầu xác minh'}</button></footer>
      </form>}
    </div>;
};
