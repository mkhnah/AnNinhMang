import React, { useState, useRef, useEffect } from 'react';
import {
    ShieldCheck,
    UploadCloud,
    FileText,
    FileJson,
    CheckCircle,
    AlertCircle,
    RotateCcw,
    Lock,
    Search,
} from 'lucide-react';
import { VerificationResultResponse } from '../../types/verify';
import { verifyApi } from '../../api/verify';
import { VerificationResultPanel } from '../../components/Verification/VerificationResultPanel';

export const IndependentVerify: React.FC = () => {
    const [pdfFile, setPdfFile] = useState<File | null>(null);
    const [packageFile, setPackageFile] = useState<File | null>(null);
    const [packageJsonText, setPackageJsonText] = useState<string>('');
    const [inputMode, setInputMode] = useState<'file' | 'text'>('file');

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

    const pdfInputRef = useRef<HTMLInputElement>(null);
    const pkgInputRef = useRef<HTMLInputElement>(null);

    const [pdfDragging, setPdfDragging] = useState(false);
    const [pkgDragging, setPkgDragging] = useState(false);

    const handlePdfSelect = (file?: File) => {
        if (!file) return;
        invalidate();
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
        setPackageJsonText('');
        setError(null);
        setResult(null);
        if (pdfInputRef.current) pdfInputRef.current.value = '';
        if (pkgInputRef.current) pkgInputRef.current.value = '';
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!pdfFile) {
            setError('Vui lòng chọn tệp PDF cần xác minh.');
            return;
        }

        if (inputMode === 'file' && !packageFile) {
            setError('Vui lòng chọn tệp signature-package.json.');
            return;
        }

        if (inputMode === 'text' && !packageJsonText.trim()) {
            setError('Vui lòng dán nội dung JSON của gói chữ ký.');
            return;
        }

        const snapshot = Object.freeze({ pdf: pdfFile, package: packageFile, json: packageJsonText.trim(), mode: inputMode });
        request.current?.abort();
        const controller = new AbortController();
        request.current = controller;
        const id = ++generation.current;
        setResult(null);
        setIsSubmitting(true);
        try {
            const verification = await verifyApi.verifyIndependent(
                snapshot.pdf,
                snapshot.mode === 'file' ? snapshot.package : null,
                snapshot.mode === 'text' ? snapshot.json : null,
                controller.signal
            );
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

    return (
        <div className="max-w-5xl mx-auto px-4 py-10 sm:px-6 lg:px-8">
            {/* Header */}
            <div className="text-center mb-10">
                <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-sky-100 text-sky-700 mb-4 shadow-inner">
                    <ShieldCheck className="w-8 h-8" />
                </div>
                <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight sm:text-4xl">
                    Xác minh Tài liệu Độc lập
                </h1>
                <p className="mt-3 max-w-2xl mx-auto text-base text-slate-600">
                    Kiểm tra tính toàn vẹn của tệp PDF và chữ ký số mật mã RSA-PSS 3072-bit (RFC 8785) mà không cần đăng nhập hay phụ thuộc vào máy chủ gốc.
                </p>
                <div className="mt-2 inline-flex items-center gap-2 text-xs font-semibold px-3 py-1 rounded-full bg-slate-100 text-slate-600">
                    <Lock className="w-3.5 h-3.5 text-slate-500" />
                    Không lưu trữ tài liệu · Xóa tệp tạm tự động sau xác minh
                </div>
            </div>

            {/* If result is available, display results with a button to re-check */}
            {result ? (
                <div className="space-y-6">
                    <div className="flex justify-between items-center bg-white p-4 rounded-xl border border-slate-200">
                        <span className="text-sm font-semibold text-slate-700">
                            Kết quả cho tệp: <strong className="text-slate-900">{verifiedFileName}</strong>
                        </span>
                        <button
                            type="button"
                            onClick={handleReset}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-sky-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
                        >
                            <RotateCcw className="w-3.5 h-3.5" />
                            Xác minh tài liệu khác
                        </button>
                    </div>

                    <VerificationResultPanel
                        result={result}
                        documentTitle={verifiedFileName}
                    />
                </div>
            ) : (
                /* Verification Submission Form */
                <form onSubmit={handleSubmit} className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6 sm:p-8 space-y-8">
                    {/* Step 1: Upload PDF */}
                    <div>
                        <div className="flex items-center justify-between mb-3">
                            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                                <span className="w-6 h-6 rounded-full bg-sky-600 text-white text-xs flex items-center justify-center font-bold">1</span>
                                Tải lên tệp PDF cần xác minh
                            </h2>
                            {pdfFile && (
                                <button
                                    type="button"
                                    onClick={() => { invalidate(); setPdfFile(null); }}
                                    className="text-xs text-rose-600 hover:underline"
                                >
                                    Đổi tệp khác
                                </button>
                            )}
                        </div>

                        {pdfFile ? (
                            <div className="flex items-center justify-between p-4 bg-emerald-50 border border-emerald-200 rounded-xl">
                                <div className="flex items-center gap-3">
                                    <FileText className="w-8 h-8 text-emerald-600" />
                                    <div>
                                        <p className="text-sm font-semibold text-slate-900">{pdfFile.name}</p>
                                        <p className="text-xs text-slate-500">{(pdfFile.size / 1024 / 1024).toFixed(2)} MB</p>
                                    </div>
                                </div>
                                <span className="inline-flex items-center gap-1 text-xs font-bold text-emerald-700">
                                    <CheckCircle className="w-4 h-4" /> Đã sẵn sàng
                                </span>
                            </div>
                        ) : (
                            <div
                                onDragOver={(e) => { e.preventDefault(); setPdfDragging(true); }}
                                onDragLeave={() => setPdfDragging(false)}
                                onDrop={(e) => {
                                    e.preventDefault();
                                    setPdfDragging(false);
                                    handlePdfSelect(e.dataTransfer.files[0]);
                                }}
                                onClick={() => pdfInputRef.current?.click()}
                                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
                                    pdfDragging
                                        ? 'border-sky-500 bg-sky-50'
                                        : 'border-slate-300 hover:border-sky-400 bg-slate-50 hover:bg-slate-100/70'
                                }`}
                            >
                                <UploadCloud className="w-10 h-10 text-slate-400 mx-auto mb-3" />
                                <p className="text-sm font-semibold text-slate-800">
                                    Kéo thả tệp PDF vào đây hoặc bấm để chọn tệp
                                </p>
                                <p className="text-xs text-slate-500 mt-1">Hỗ trợ tài liệu .pdf tối đa 20 MB</p>
                                <input
                                    ref={pdfInputRef}
                                    type="file"
                                    aria-label="Chọn tệp PDF"
                                    accept=".pdf,application/pdf"
                                    hidden
                                    onChange={(e) => handlePdfSelect(e.target.files?.[0])}
                                />
                            </div>
                        )}
                    </div>

                    {/* Step 2: Signature Package */}
                    <div>
                        <div className="flex items-center justify-between mb-3">
                            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                                <span className="w-6 h-6 rounded-full bg-sky-600 text-white text-xs flex items-center justify-center font-bold">2</span>
                                Cung cấp Gói chứng cứ chữ ký (Signature Package)
                            </h2>
                            <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg text-xs font-medium">
                                <button
                                    type="button"
                                    onClick={() => { invalidate(); setInputMode('file'); }}
                                    className={`px-2.5 py-1 rounded-md transition-colors ${
                                        inputMode === 'file'
                                            ? 'bg-white text-slate-900 shadow-sm font-semibold'
                                            : 'text-slate-600 hover:text-slate-900'
                                    }`}
                                >
                                    Tải tệp .json
                                </button>
                                <button
                                    type="button"
                                    onClick={() => { invalidate(); setInputMode('text'); }}
                                    className={`px-2.5 py-1 rounded-md transition-colors ${
                                        inputMode === 'text'
                                            ? 'bg-white text-slate-900 shadow-sm font-semibold'
                                            : 'text-slate-600 hover:text-slate-900'
                                    }`}
                                >
                                    Dán JSON
                                </button>
                            </div>
                        </div>

                        {inputMode === 'file' ? (
                            packageFile ? (
                                <div className="flex items-center justify-between p-4 bg-emerald-50 border border-emerald-200 rounded-xl">
                                    <div className="flex items-center gap-3">
                                        <FileJson className="w-8 h-8 text-emerald-600" />
                                        <div>
                                            <p className="text-sm font-semibold text-slate-900">{packageFile.name}</p>
                                            <p className="text-xs text-slate-500">{(packageFile.size / 1024).toFixed(1)} KB</p>
                                        </div>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={() => { invalidate(); setPackageFile(null); }}
                                        className="text-xs text-rose-600 hover:underline"
                                    >
                                        Đổi tệp
                                    </button>
                                </div>
                            ) : (
                                <div
                                    onDragOver={(e) => { e.preventDefault(); setPkgDragging(true); }}
                                    onDragLeave={() => setPkgDragging(false)}
                                    onDrop={(e) => {
                                        e.preventDefault();
                                        setPkgDragging(false);
                                        handlePkgSelect(e.dataTransfer.files[0]);
                                    }}
                                    onClick={() => pkgInputRef.current?.click()}
                                    className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
                                        pkgDragging
                                            ? 'border-sky-500 bg-sky-50'
                                            : 'border-slate-300 hover:border-sky-400 bg-slate-50 hover:bg-slate-100/70'
                                    }`}
                                >
                                    <FileJson className="w-10 h-10 text-slate-400 mx-auto mb-3" />
                                    <p className="text-sm font-semibold text-slate-800">
                                        Kéo thả tệp signature-package.json vào đây hoặc bấm để chọn tệp
                                    </p>
                                    <p className="text-xs text-slate-500 mt-1">Định dạng JSON chứa manifest, chữ ký và khóa công khai</p>
                                    <input
                                        ref={pkgInputRef}
                                        type="file"
                                        aria-label="Chọn tệp JSON"
                                        accept=".json,application/json"
                                        hidden
                                        onChange={(e) => handlePkgSelect(e.target.files?.[0])}
                                    />
                                </div>
                            )
                        ) : (
                            <div>
                                <textarea
                                    value={packageJsonText}
                                    onChange={(e) => { invalidate(); setPackageJsonText(e.target.value); }}
                                    placeholder='Dán nội dung JSON ở đây: {"package_version": 1, "manifest": {...}, "signature_b64": "...", "public_key_spki_pem": "..."}'
                                    rows={6}
                                    className="w-full font-mono text-xs p-3 rounded-xl border border-slate-300 focus:outline-none focus:ring-2 focus:ring-sky-500"
                                />
                            </div>
                        )}
                    </div>

                    {/* Error Banner */}
                    {error && (
                        <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl flex items-start gap-3">
                            <AlertCircle className="w-5 h-5 text-rose-600 flex-shrink-0 mt-0.5" />
                            <div className="text-sm text-rose-800 font-medium">{error}</div>
                        </div>
                    )}

                    {/* Submit Button */}
                    <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100">
                        <button
                            type="button"
                            onClick={handleReset}
                            disabled={isSubmitting}
                            className="px-4 py-2 text-sm font-semibold text-slate-600 hover:text-slate-900 transition-colors"
                        >
                            Làm mới
                        </button>
                        <button
                            type="submit"
                            disabled={isSubmitting || !pdfFile || (inputMode === 'file' ? !packageFile : !packageJsonText.trim())}
                            className="inline-flex items-center gap-2 px-6 py-2.5 text-sm font-bold text-white bg-sky-600 hover:bg-sky-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-xl shadow-md transition-all shadow-sky-600/20"
                        >
                            <Search className="w-4 h-4" />
                            {isSubmitting ? 'Đang xác minh mật mã…' : 'Bắt đầu xác minh'}
                        </button>
                    </div>
                </form>
            )}
        </div>
    );
};
