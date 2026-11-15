import React, { useState, useRef, useEffect } from 'react';
import {
    ShieldCheck,
    AlertTriangle,
    XCircle,
    HelpCircle,
    CheckCircle2,
    Clock,
    FileCheck,
    Key,
    Lock,
    Download,
    Award,
    FileCode,
} from 'lucide-react';
import {
    VerificationResultResponse,
    VerificationReportResponse,
} from '../../types/verify';
import { verifyApi } from '../../api/verify';

interface VerificationResultPanelProps {
    result: VerificationResultResponse;
    documentTitle?: string;
}

export const VerificationResultPanel: React.FC<VerificationResultPanelProps> = ({
    result,
    documentTitle,
}) => {
    const [downloadingReport, setDownloadingReport] = useState(false);
    const [reportError, setReportError] = useState<string | null>(null);
    const [copyNotice, setCopyNotice] = useState('');
    const reportGeneration = useRef(0);
    const reportController = useRef<AbortController | null>(null);
    useEffect(() => {
        setDownloadingReport(false);
        setReportError(null);
        return () => { reportGeneration.current += 1; reportController.current?.abort(); };
    }, [result.verification_id]);

    const {
        summary_status,
        results,
        document_hash_expected,
        document_hash_computed,
        signer_fingerprint,
        key_id,
        signature_algorithm,
        signature_format,
        warnings,
    } = result;

    const handleDownloadReport = async () => {
        if (!result.verification_receipt) { setReportError('Cần xác minh lại để nhận receipt báo cáo.'); return; }
        const id = ++reportGeneration.current;
        reportController.current?.abort();
        const controller = new AbortController();
        reportController.current = controller;
        setDownloadingReport(true);
        setReportError(null);
        try {
            const report: VerificationReportResponse = await verifyApi.generateReport(result.verification_receipt, controller.signal);
            if (id !== reportGeneration.current || controller.signal.aborted) return;
            const blob = new Blob([JSON.stringify(report, null, 2)], {
                type: 'application/json',
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `verification-report-${result.verification_id.slice(0, 8)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (err: unknown) {
            if (id !== reportGeneration.current || controller.signal.aborted) return;
            setReportError('Không thể tải báo cáo. Nếu kết quả đã hết hạn, hãy xác minh lại tài liệu rồi thử tải báo cáo mới.');
        } finally {
            if (id === reportGeneration.current) setDownloadingReport(false);
        }
    };

    // Helper for summary status styling
    const getSummaryConfig = () => {
        const effective = results.cryptographic_validity === 'INVALID' ? 'SIGNATURE_INVALID' : results.document_integrity === 'TAMPERED' ? 'INTEGRITY_COMPROMISED' : summary_status;
        switch (effective) {
            case 'VERIFIED':
                return {
                    bg: 'bg-emerald-50 border-emerald-300 text-emerald-900',
                    icon: <CheckCircle2 className="w-8 h-8 text-emerald-600 flex-shrink-0" />,
                    title: 'Xác minh thành công — Tài liệu & Chữ ký hợp lệ',
                    desc: 'Toàn vẹn tệp PDF và tính hợp lệ toán học của chữ ký số RSA-PSS 3072-bit khớp với bằng chứng được cung cấp tại thời điểm kiểm tra.',
                };
            case 'INTEGRITY_COMPROMISED':
                return {
                    bg: 'bg-rose-50 border-rose-300 text-rose-900',
                    icon: <XCircle className="w-8 h-8 text-rose-600 flex-shrink-0" />,
                    title: 'Cảnh báo vi phạm — Tệp đã bị chỉnh sửa (Tampered)',
                    desc: 'Mã băm SHA-256 thực tế của tài liệu không khớp với chữ ký. Nội dung PDF đã bị can thiệp sau thời điểm ký!',
                };
            case 'SIGNATURE_INVALID':
                return {
                    bg: 'bg-rose-50 border-rose-300 text-rose-900',
                    icon: <XCircle className="w-8 h-8 text-rose-600 flex-shrink-0" />,
                    title: 'Chữ ký không hợp lệ (Cryptographic Invalid)',
                    desc: 'Chữ ký số RSA-PSS không khớp về mặt toán học với bản tóm lược Manifest hoặc khóa công khai tương ứng.',
                };
            case 'REVOKED_KEY':
                return {
                    bg: 'bg-amber-50 border-amber-300 text-amber-900',
                    icon: <AlertTriangle className="w-8 h-8 text-amber-600 flex-shrink-0" />,
                    title: 'Cảnh báo — Khóa ký đã bị thu hồi (Revoked)',
                    desc: 'Khóa công khai đã bị chủ sở hữu thu hồi. Trạng thái thu hồi hiện tại không chứng minh thời điểm chữ ký được tạo.',
                };
            case 'UNVERIFIABLE':
            default:
                return {
                    bg: 'bg-amber-50 border-amber-300 text-amber-900',
                    icon: <HelpCircle className="w-8 h-8 text-amber-600 flex-shrink-0" />,
                    title: 'Không thể xác minh đầy đủ (Unverifiable)',
                    desc: 'Thiếu dữ liệu chữ ký, gói bằng chứng không hợp lệ hoặc không có khóa công khai đối chiếu.',
                };
        }
    };

    const summary = getSummaryConfig();

    const copyHash = async (value: string, label: string) => {
        try { await navigator.clipboard.writeText(value); setCopyNotice(`Đã sao chép ${label}`); }
        catch { setCopyNotice('Không thể sao chép; hãy chọn mã băm để sao chép.'); }
    };
    const renderHashDiff = () => (
        <div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {([
                    ['Expected SHA-256', document_hash_expected],
                    ['Computed SHA-256', document_hash_computed],
                ] as const).map(([label, hash]) => <div key={label} className="bg-slate-900 p-3 rounded-lg text-slate-100">
                    <div className="flex justify-between mb-2 text-xs"><span>{label}</span>
                        <button aria-label={`Copy ${label}`} onClick={() => void copyHash(hash, label)}>Sao chép</button>
                    </div>
                    <div aria-label={label} className="font-mono text-xs break-all select-all">
                        {hash ? [...hash].map((char, index) => {
                            const other = label === 'Expected SHA-256' ? document_hash_computed : document_hash_expected;
                            return char !== other[index] ? <mark key={index} data-hash-index={index} aria-label={`Khác tại ký tự ${index + 1}`} className="bg-rose-200 text-rose-950">{char}</mark> : <span key={index}>{char}</span>;
                        }) : '(Không có dữ liệu)'}
                    </div>
                </div>)}
            </div>
            <p className="text-xs mt-2">Sự khác biệt giữa các ký tự hash không cho biết chính xác vị trí byte đã bị sửa trong tài liệu.</p>
            <p role="status" className="text-xs">{copyNotice}</p>
        </div>
    );

    return (
        <div className="space-y-6">
            {/* Summary Banner */}
            <div className={`p-5 rounded-xl border flex items-start gap-4 ${summary.bg}`}>
                {summary.icon}
                <div className="flex-1">
                    <h3 className="text-lg font-bold">{summary.title}</h3>
                    <p className="text-sm mt-1 opacity-90">{summary.desc}</p>
                    {documentTitle && (
                        <p className="text-xs font-semibold mt-2 text-slate-600">
                            Tài liệu: <span className="text-slate-800">{documentTitle}</span>
                        </p>
                    )}
                </div>
                <div className="text-right flex-shrink-0">
                    <span className="inline-block px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-white/80 border shadow-sm">
                        {result.verification_mode === 'INTERNAL' ? 'Chế độ nội bộ' : 'Kiểm tra độc lập'}
                    </span>
                </div>
            </div>

            {/* Six Dimensions Grid */}
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                <h4 className="text-base font-bold text-slate-900 mb-4 flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-sky-600" />
                    Kết quả phân tích 6 chiều độc lập
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {/* 1. Cryptographic Validity */}
                    <div className="p-4 rounded-lg border bg-slate-50 flex flex-col justify-between">
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-bold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                                    <Lock className="w-4 h-4 text-slate-400" />
                                    1. Tính hợp lệ mật mã
                                </span>
                                <span
                                    className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        results.cryptographic_validity === 'VALID'
                                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                                            : results.cryptographic_validity === 'INVALID'
                                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                            : 'bg-slate-200 text-slate-700'
                                    }`}
                                >
                                    {results.cryptographic_validity}
                                </span>
                            </div>
                            <p className="text-xs text-slate-600">
                                {results.cryptographic_validity === 'VALID'
                                    ? 'Chữ ký RSA-PSS 3072 khớp toán học chính xác với Manifest RFC 8785.'
                                    : results.cryptographic_validity === 'INVALID'
                                    ? 'Chữ ký không khớp với khóa công khai hoặc nội dung manifest.'
                                    : 'Không thể tính toán chữ ký do thiếu dữ liệu hoặc cấu trúc sai.'}
                            </p>
                        </div>
                    </div>

                    {/* 2. Document Integrity */}
                    <div className="p-4 rounded-lg border bg-slate-50 flex flex-col justify-between">
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-bold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                                    <FileCheck className="w-4 h-4 text-slate-400" />
                                    2. Toàn vẹn tài liệu
                                </span>
                                <span
                                    className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        results.document_integrity === 'UNCHANGED'
                                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                                            : results.document_integrity === 'TAMPERED'
                                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                            : 'bg-slate-200 text-slate-700'
                                    }`}
                                >
                                    {results.document_integrity}
                                </span>
                            </div>
                            <p className="text-xs text-slate-600">
                                {results.document_integrity === 'UNCHANGED'
                                    ? 'Mã băm SHA-256 của PDF khớp hoàn toàn với bản tóm lược đã ký.'
                                    : results.document_integrity === 'TAMPERED'
                                    ? 'PDF đã bị thay đổi (sai khác SHA-256 so với giá trị trong chữ ký).'
                                    : 'Chưa có thông tin băm đối chiếu.'}
                            </p>
                        </div>
                    </div>

                    {/* 3. Key Ownership */}
                    <div className="p-4 rounded-lg border bg-slate-50 flex flex-col justify-between">
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-bold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                                    <Key className="w-4 h-4 text-slate-400" />
                                    3. Quyền sở hữu khóa
                                </span>
                                <span
                                    className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        results.key_ownership === 'VERIFIED_POP'
                                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                                            : results.key_ownership === 'UNVERIFIED'
                                            ? 'bg-amber-100 text-amber-800 border border-amber-300'
                                            : 'bg-slate-200 text-slate-700'
                                    }`}
                                >
                                    {results.key_ownership}
                                </span>
                            </div>
                            <p className="text-xs text-slate-600">
                                {results.key_ownership === 'VERIFIED_POP'
                                    ? 'Đã kiểm chứng Proof-of-Possession khi đăng ký khóa trên hệ thống.'
                                    : results.key_ownership === 'UNVERIFIED' ? 'Chưa có bằng chứng PoP hệ thống gắn với khóa này.' : 'Chưa đủ bằng chứng để xác định khóa và PoP.'}
                            </p>
                        </div>
                    </div>

                    {/* 4. Certificate Trust */}
                    <div className="p-4 rounded-lg border bg-slate-50 flex flex-col justify-between">
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-bold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                                    <Award className="w-4 h-4 text-slate-400" />
                                    4. Chuỗi tin cậy chứng thư
                                </span>
                                <span
                                    className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        results.certificate_trust === 'TRUSTED_CA'
                                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                                            : 'bg-slate-200 text-slate-700'
                                    }`}
                                >
                                    {results.certificate_trust}
                                </span>
                            </div>
                            <p className="text-xs text-slate-600">
                                {results.certificate_trust === 'SELF_REGISTERED'
                                    ? 'Khóa tự đăng ký bởi người dùng (Self-registered SPKI). Không dùng CA ủy quyền.'
                                    : results.certificate_trust === 'TRUSTED_CA' ? 'Chuỗi chứng thư đã được kiểm tra bằng nguồn CA tin cậy.' : 'Chưa có bằng chứng khóa hoặc chuỗi chứng thư để đánh giá mức tin cậy.'}
                            </p>
                        </div>
                    </div>

                    {/* 5. Revocation Status */}
                    <div className="p-4 rounded-lg border bg-slate-50 flex flex-col justify-between">
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-bold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                                    <AlertTriangle className="w-4 h-4 text-slate-400" />
                                    5. Trạng thái thu hồi
                                </span>
                                <span
                                    className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        results.key_revocation_status === 'ACTIVE'
                                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                                            : results.key_revocation_status === 'REVOKED'
                                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                            : 'bg-slate-200 text-slate-700'
                                    }`}
                                >
                                    {results.key_revocation_status}
                                </span>
                            </div>
                            <p className="text-xs text-slate-600">
                                {results.key_revocation_status === 'ACTIVE'
                                    ? 'Khóa ký đang hoạt động bình thường, chưa ghi nhận thu hồi.'
                                    : results.key_revocation_status === 'REVOKED'
                                    ? `Khóa đã bị thu hồi${
                                          results.revoked_at ? ` lúc ${new Date(results.revoked_at).toLocaleString('vi-VN')}` : ''
                                      }.`
                                    : 'Không thể tra cứu trạng thái thu hồi.'}
                            </p>
                        </div>
                    </div>

                    {/* 6. Timestamp Evidence */}
                    <div className="p-4 rounded-lg border bg-slate-50 flex flex-col justify-between">
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-bold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                                    <Clock className="w-4 h-4 text-slate-400" />
                                    6. Bằng chứng thời gian
                                </span>
                                <span className="px-2 py-0.5 rounded text-xs font-bold bg-sky-100 text-sky-800 border border-sky-300">
                                    {results.timestamp_trust_level}
                                </span>
                            </div>
                            <p className="text-xs text-slate-600">
                                {results.timestamp_trust_level === 'SERVER_RECORDED'
                                    ? `Máy chủ ghi nhận: ${
                                          results.server_recorded_at
                                              ? new Date(results.server_recorded_at).toLocaleString('vi-VN')
                                              : 'Có sẵn'
                                      }.`
                                    : results.timestamp_trust_level === 'DECLARED'
                                    ? 'Thời gian ký tự khai báo trong manifest.'
                                    : results.timestamp_trust_level === 'TRUSTED_TSA' ? 'Dấu thời gian từ nhà cung cấp TSA độc lập.' : 'Chưa có bằng chứng thời gian để đánh giá.'}
                            </p>
                            <p className="text-xs mt-1">Thời gian khai báo trong manifest: {results.declared_timestamp ? new Date(results.declared_timestamp).toLocaleString('vi-VN') : 'Không có'}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* SHA-256 Comparison & Avalanche Effect Panel */}
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                <div className="flex items-center justify-between mb-3">
                    <h4 className="text-base font-bold text-slate-900 flex items-center gap-2">
                        <FileCode className="w-5 h-5 text-indigo-600" />
                        Đối chiếu mã băm SHA-256 & Hiệu ứng thác đổ (Avalanche Effect)
                    </h4>
                    <span
                        className={`text-xs font-bold px-2.5 py-1 rounded-full ${
                            results.document_integrity === 'UNCHANGED'
                                ? 'bg-emerald-100 text-emerald-800'
                                : results.document_integrity === 'TAMPERED' ? 'bg-rose-100 text-rose-800' : 'bg-slate-100 text-slate-700'
                        }`}
                    >
                        {results.document_integrity === 'UNCHANGED' ? 'Trùng khớp 100%' : results.document_integrity === 'TAMPERED' ? 'Sai lệch mã băm' : 'Chưa đủ dữ liệu băm'}
                    </span>
                </div>

                {renderHashDiff()}

                <p className="text-xs text-slate-500 mt-3 leading-relaxed">
                    SHA-256 có hiệu ứng thác đổ: một thay đổi nhỏ trong PDF thường làm nhiều ký tự digest thay đổi. Đối chiếu hash giúp phát hiện sai lệch nội dung; không xác nhận danh tính người ký hoặc bảo đảm chống mọi hình thức giả mạo.
                </p>
            </div>

            {/* Technical Metadata & Cryptographic Parameters */}
            <div className="bg-slate-50 rounded-xl border border-slate-200 p-5">
                <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wide mb-3">
                    Tham số kỹ thuật & Danh tính mật mã
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                    <div>
                        <span className="text-slate-400 block">Thuật toán chữ ký:</span>
                        <span className="font-mono font-medium text-slate-800">{signature_algorithm}</span>
                    </div>
                    <div>
                        <span className="text-slate-400 block">Định dạng chữ ký:</span>
                        <span className="font-mono font-medium text-slate-800">{signature_format}</span>
                    </div>
                    <div className="col-span-1 sm:col-span-2">
                        <span className="text-slate-400 block">Dấu vân tay khóa (SHA-256 Fingerprint):</span>
                        <span className="font-mono font-medium text-slate-800 break-all select-all">
                            {signer_fingerprint || '(Không có)'}
                        </span>
                    </div>
                    {key_id && (
                        <div>
                            <span className="text-slate-400 block">Khóa ID trong hệ thống:</span>
                            <span className="font-mono font-medium text-slate-800">{key_id}</span>
                        </div>
                    )}
                    <div>
                        <span className="text-slate-400 block">Mã phiên xác minh:</span>
                        <span className="font-mono font-medium text-slate-800">{result.verification_id}</span>
                    </div>
                </div>

                {/* Warnings List */}
                {warnings && warnings.length > 0 && (
                    <div className="mt-4 pt-3 border-t border-slate-200">
                        <span className="text-xs font-bold text-amber-700 flex items-center gap-1.5 mb-2">
                            <AlertTriangle className="w-4 h-4" />
                            Cảnh báo phân tích ({warnings.length}):
                        </span>
                        <ul className="list-disc list-inside text-xs text-amber-800 space-y-1">
                            {warnings.map((w, idx) => (
                                <li key={idx}>{w}</li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>

            {/* Actions: Download Verification Report JSON */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <span className="text-xs text-slate-500">
                    Báo cáo JSON ghi lại kết quả tại thời điểm kiểm tra; báo cáo chưa được ký số và không tự chứng minh chống sửa đổi.
                </span>
                <button
                    type="button"
                    onClick={handleDownloadReport}
                    disabled={downloadingReport}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-slate-800 hover:bg-slate-900 rounded-lg shadow-sm transition-colors disabled:opacity-50"
                >
                    <Download className="w-4 h-4" />
                    {downloadingReport ? 'Đang tạo báo cáo…' : 'Tải báo cáo JSON (Report)'}
                </button>
            </div>
            {reportError && <p className="text-xs text-rose-600 text-right">{reportError}</p>}
        </div>
    );
};
