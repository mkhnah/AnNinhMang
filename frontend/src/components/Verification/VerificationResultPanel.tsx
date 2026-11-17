import React, { useState, useRef, useEffect } from 'react';
import {
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
import { pkiLabels } from './PkiResultPanel';

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

            <p role="status" className="text-xs">{copyNotice}</p>
        </div>
    );

    return (
        <div className="verification-result space-y-6">
            {/* Summary Banner */}
            <div className={`p-5 rounded-xl border flex flex-wrap items-start gap-4 ${summary.bg}`}>
                {summary.icon}
                <div className="flex-1 min-w-0">
                    <h3 className="text-lg font-bold">{summary.title}</h3>

                    {documentTitle && (
                        <p className="text-xs font-semibold mt-2 text-slate-600">
                            Tài liệu: <span className="text-slate-800">{documentTitle}</span>
                        </p>
                    )}
                </div>
            </div>


            {results.certificate_binding && <section className="bg-white border rounded-xl p-5 space-y-3" aria-label="Chứng chỉ và danh tính">
                <h3 className="font-semibold">Chứng chỉ và danh tính</h3>
                {results.certificate_binding === 'LEGACY_NO_CERTIFICATE_BINDING' ? <span className="ui-badge ui-badge-warning">Chưa gắn chứng chỉ</span> : <>
                    <dl className="grid sm:grid-cols-2 gap-3 text-sm">{Object.entries({certificate_binding:'Chứng chỉ trong dữ liệu ký',certificate_chain:'CA tin cậy',certificate_validity:'Thời hạn',certificate_revocation:'Thu hồi',identity_binding:'Danh tính người ký',identity_assurance:'Mức đối chiếu danh tính'}).map(([key,label]) => {
                        const value = results[key as keyof typeof results]; return <div key={key}><dt className="text-slate-500">{label}</dt><dd className="font-medium">{pkiLabels[String(value)] || String(value ?? 'UNKNOWN')}</dd></div>;
                    })}</dl><p className="font-mono text-xs break-all">{results.certificate_sha256}</p>

                </>}
            </section>}
            <section className="ui-card ui-card-body">
                <h4 className="font-semibold mb-5">Kết quả xác minh</h4>
                <dl className="verification-dimensions">
                    {([
                        {label:'Chữ ký',value:results.cryptographic_validity,Icon:Lock,good:results.cryptographic_validity === 'VALID',bad:results.cryptographic_validity === 'INVALID'},
                        {label:'Toàn vẹn tài liệu',value:results.document_integrity,Icon:FileCheck,good:results.document_integrity === 'UNCHANGED',bad:results.document_integrity === 'TAMPERED'},
                        {label:'Sở hữu khóa',value:results.key_ownership,Icon:Key,good:results.key_ownership === 'VERIFIED_POP',bad:false},
                        {label:'Tin cậy chứng chỉ',value:results.certificate_trust,Icon:Award,good:results.certificate_trust === 'TRUSTED_CA',bad:false},
                        {label:'Trạng thái khóa',value:results.key_revocation_status,Icon:AlertTriangle,good:results.key_revocation_status === 'ACTIVE',bad:results.key_revocation_status === 'REVOKED'},
                        {label:'Dấu thời gian',value:results.timestamp_status === 'INVALID' ? 'INVALID' : results.timestamp_trust_level,Icon:Clock,good:results.timestamp_trust_level === 'TRUSTED_TSA',bad:results.timestamp_status === 'INVALID'},
                    ]).map(({label,value,Icon,good,bad}) => <div className="verification-dimension" key={label}>
                        <dt><Icon size={17} />{label}</dt>
                        <dd className={'ui-badge ' + (good ? 'ui-badge-success' : bad ? 'ui-badge-danger' : '')}>{value}</dd>
                    </div>)}
                </dl>
                <dl className="ui-data mt-6 border-t border-slate-100 pt-5">
                    <div><dt>Thời gian ký khai báo</dt><dd>{results.declared_timestamp ? new Date(results.declared_timestamp).toLocaleString('vi-VN') : 'Không có'}</dd></div>
                    <div><dt>Thời gian xác minh</dt><dd>{new Date(results.verification_time).toLocaleString('vi-VN')}</dd></div>
                    {results.server_recorded_at && <div><dt>Máy chủ ghi nhận</dt><dd>{new Date(results.server_recorded_at).toLocaleString('vi-VN')}</dd></div>}
                    {results.trusted_timestamp && <div><dt>Thời gian TSA chứng thực</dt><dd>{new Date(results.trusted_timestamp).toLocaleString('vi-VN')}</dd></div>}
                    {results.timestamp_authority && <div className="full-width"><dt>Đơn vị cấp dấu thời gian</dt><dd>{results.timestamp_authority}</dd></div>}
                    {results.timestamp_scope === 'DOCSIGN_PRIVATE_TSA' && <div className="full-width"><dt>Phạm vi tin cậy dấu thời gian</dt><dd>TSA nội bộ DocSign — thời gian chứng thực chữ ký đã tồn tại; không phải thời điểm ký được bên thứ ba độc lập xác nhận.</dd></div>}
                    {results.revoked_at && <div><dt>Đã thu hồi</dt><dd>{new Date(results.revoked_at).toLocaleString('vi-VN')}</dd></div>}
                </dl>
            </section>

            {/* SHA-256 Comparison & Avalanche Effect Panel */}
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                <div className="flex flex-wrap gap-3 items-center justify-between mb-4">
                    <h4 className="text-base font-bold text-slate-900 flex items-center gap-2">
                        <FileCode className="w-5 h-5 text-indigo-600" />
                        Mã băm tài liệu
                    </h4>
                    <span className={`ui-badge ${results.document_integrity === 'UNCHANGED' ? 'ui-badge-success' : results.document_integrity === 'TAMPERED' ? 'ui-badge-danger' : 'ui-badge-warning'}`}>
                        {results.document_integrity === 'UNCHANGED' ? 'Trùng khớp 100%' : results.document_integrity === 'TAMPERED' ? 'Sai lệch mã băm' : 'Chưa đủ dữ liệu băm'}
                    </span>
                </div>

                {renderHashDiff()}


            </div>

            {/* Technical Metadata & Cryptographic Parameters */}
            <div className="ui-card ui-card-body">
                <h4 className="font-semibold mb-4">Chi tiết chữ ký</h4>
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

                <button
                    type="button"
                    onClick={handleDownloadReport}
                    disabled={downloadingReport}
                    className="ui-button ui-button-primary"
                >
                    <Download className="w-4 h-4" />
                    {downloadingReport ? 'Đang tạo báo cáo…' : 'Tải báo cáo JSON'}
                </button>
            </div>
            {reportError && <p className="text-xs text-rose-600 text-right">{reportError}</p>}
        </div>
    );
};
