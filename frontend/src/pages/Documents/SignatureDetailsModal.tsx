import React, { useState, useEffect } from 'react';
import {
    X,
    ShieldCheck,
    Copy,
    Check,
    Loader2,
    AlertCircle,
} from 'lucide-react';
import { signaturesApi } from '../../api/signatures';
import { SignatureDto } from '../../types/signature';
import { errorMessage } from './index';

interface SignatureDetailsModalProps {
    documentId: string;
    versionId: string;
    versionNo: number;
    documentTitle: string;
    onClose: () => void;
}

export const SignatureDetailsModal: React.FC<SignatureDetailsModalProps> = ({
    documentId,
    versionId,
    versionNo,
    documentTitle,
    onClose,
}) => {
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string>('');
    const [signature, setSignature] = useState<SignatureDto | null>(null);
    const [copiedField, setCopiedField] = useState<string>('');

    useEffect(() => {
        let mounted = true;
        const load = async () => {
            setLoading(true);
            setError('');
            try {
                const data = await signaturesApi.getVersionSignature(documentId, versionId);
                if (mounted) setSignature(data);
            } catch (err: unknown) {
                if (mounted) setError(await errorMessage(err));
            } finally {
                if (mounted) setLoading(false);
            }
        };

        void load();
        return () => {
            mounted = false;
        };
    }, [documentId, versionId]);

    const copyText = async (text: string, fieldName: string) => {
        try {
            await navigator.clipboard.writeText(text);
            setCopiedField(fieldName);
            setTimeout(() => setCopiedField(''), 2000);
        } catch {
            // ignore
        }
    };

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm overflow-y-auto"
            role="dialog"
            aria-modal="true"
            aria-labelledby="sig-modal-title"
        >
            <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-2xl overflow-hidden my-6">
                {/* Header */}
                <div className="bg-slate-50 border-b border-slate-200 px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-emerald-100 text-emerald-700 rounded-lg">
                            <ShieldCheck className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 id="sig-modal-title" className="text-lg font-bold text-slate-800">
                                Chi tiết chữ ký
                            </h2>
                            <p className="text-xs text-slate-500">
                                {documentTitle} · Phiên bản v{versionNo}
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200/60 transition-colors"
                        aria-label="Đóng cửa sổ"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Content */}
                <div className="p-6">
                    {loading ? (
                        <div className="py-12 flex flex-col items-center justify-center">
                            <Loader2 className="w-8 h-8 text-sky-600 animate-spin mb-3" />
                            <p className="text-xs text-slate-500">Đang tải thông tin chữ ký số...</p>
                        </div>
                    ) : error ? (
                        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 flex items-start gap-3 text-sm">
                            <AlertCircle className="w-5 h-5 text-rose-500 flex-shrink-0 mt-0.5" />
                            <div>
                                <p className="font-semibold">Không thể tải thông tin chữ ký</p>
                                <p className="text-xs text-rose-700 mt-1">{error}</p>
                            </div>
                        </div>
                    ) : signature ? (
                        <div className="space-y-4">
                            <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl flex items-center justify-between">
                                <span className="text-xs font-semibold text-emerald-800 flex items-center gap-1.5">
                                    <ShieldCheck className="w-4 h-4 text-emerald-600" /> Đã ký
                                </span>
                                <span className="text-[11px] font-mono bg-white px-2 py-0.5 rounded border border-emerald-300 text-emerald-900">
                                    {signature.signature_format}
                                </span>
                            </div>

                            <div className="grid grid-cols-2 gap-3 text-xs">
                                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                                    <span className="text-slate-400 block mb-0.5">Thuật toán</span>
                                    <span className="font-semibold text-slate-800">{signature.algorithm}</span>
                                </div>
                                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                                    <span className="text-slate-400 block mb-0.5">Thời gian ký</span>
                                    <span className="font-medium text-slate-800">
                                        {new Date(signature.signed_at).toLocaleString('vi-VN')}
                                    </span>
                                </div>
                            </div>

                            <div className="space-y-3 text-xs">
                                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-slate-500 font-medium">Manifest SHA-256</span>
                                        <button
                                            type="button"
                                            onClick={() => copyText(signature.manifest_sha256, 'manifest')}
                                            className="text-sky-600 hover:text-sky-700 flex items-center gap-1 text-[11px]"
                                        >
                                            {copiedField === 'manifest' ? (
                                                <Check className="w-3.5 h-3.5 text-emerald-600" />
                                            ) : (
                                                <Copy className="w-3.5 h-3.5" />
                                            )}
                                            {copiedField === 'manifest' ? 'Đã chép' : 'Sao chép'}
                                        </button>
                                    </div>
                                    <code className="text-slate-700 font-mono text-[11px] break-all block">
                                        {signature.manifest_sha256}
                                    </code>
                                </div>

                                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-slate-500 font-medium">Mã khóa ký</span>
                                        <button
                                            type="button"
                                            onClick={() => copyText(signature.key_id, 'key_id')}
                                            className="text-sky-600 hover:text-sky-700 flex items-center gap-1 text-[11px]"
                                        >
                                            {copiedField === 'key_id' ? (
                                                <Check className="w-3.5 h-3.5 text-emerald-600" />
                                            ) : (
                                                <Copy className="w-3.5 h-3.5" />
                                            )}
                                            {copiedField === 'key_id' ? 'Đã chép' : 'Sao chép'}
                                        </button>
                                    </div>
                                    <code className="text-slate-700 font-mono text-[11px] break-all block">
                                        {signature.key_id}
                                    </code>
                                </div>

                                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-slate-500 font-medium">Chữ ký Base64</span>
                                        <button
                                            type="button"
                                            onClick={() => copyText(signature.signature_b64, 'sig')}
                                            className="text-sky-600 hover:text-sky-700 flex items-center gap-1 text-[11px]"
                                        >
                                            {copiedField === 'sig' ? (
                                                <Check className="w-3.5 h-3.5 text-emerald-600" />
                                            ) : (
                                                <Copy className="w-3.5 h-3.5" />
                                            )}
                                            {copiedField === 'sig' ? 'Đã chép' : 'Sao chép'}
                                        </button>
                                    </div>
                                    <code className="text-slate-700 font-mono text-[10px] break-all block max-h-24 overflow-y-auto bg-white p-2 rounded border border-slate-200">
                                        {signature.signature_b64}
                                    </code>
                                </div>
                            </div>
                        </div>
                    ) : null}

                    <div className="mt-6 flex justify-end">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-5 py-2 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold shadow-sm transition"
                        >
                            Đóng
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
