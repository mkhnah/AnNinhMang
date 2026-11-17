import React, { useEffect, useState } from 'react';
import { X, ShieldCheck, Loader2 } from 'lucide-react';
import { VerificationResultResponse } from '../../types/verify';
import { verifyApi } from '../../api/verify';
import { VerificationResultPanel } from '../../components/Verification/VerificationResultPanel';
import { errorMessage } from './index';

interface VerifyModalProps {
    documentId: string;
    versionId: string;
    versionNo: number;
    documentTitle: string;
    onClose: () => void;
}

export const VerifyModal: React.FC<VerifyModalProps> = ({
    documentId,
    versionId,
    versionNo,
    documentTitle,
    onClose,
}) => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [result, setResult] = useState<VerificationResultResponse | null>(null);

    useEffect(() => {
        let active = true;
        const runVerification = async () => {
            setLoading(true);
            setError(null);
            try {
                const res = await verifyApi.verifyInternal(documentId, versionId);
                if (active) {
                    setResult(res);
                }
            } catch (err: unknown) {
                if (active) {
                    setError(await errorMessage(err));
                }
            } finally {
                if (active) {
                    setLoading(false);
                }
            }
        };

        void runVerification();
        return () => {
            active = false;
        };
    }, [documentId, versionId]);

    return (
        <div role="dialog" aria-modal="true" aria-label="Xác minh tài liệu" className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-white rounded-2xl max-w-4xl w-full shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
                {/* Modal Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50">
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-sky-100 text-sky-700 flex items-center justify-center">
                            <ShieldCheck className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 className="text-base font-bold text-slate-900">
                                Xác minh tài liệu
                            </h2>
                            <p className="text-xs text-slate-500">
                                {documentTitle} · Phiên bản {versionNo}
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        aria-label="Đóng cửa sổ"
                        onClick={onClose}
                        className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Modal Body */}
                <div className="p-6 overflow-y-auto flex-1">
                    {loading && (
                        <div className="py-16 text-center space-y-3">
                            <Loader2 className="w-10 h-10 animate-spin text-sky-600 mx-auto" />
                            <p className="text-sm font-semibold text-slate-700">
                                Đang xác minh…
                            </p>

                        </div>
                    )}

                    {error && (
                        <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-sm text-rose-800">
                            <strong>Lỗi xác minh:</strong> {error}
                        </div>
                    )}

                    {!loading && result && (
                        <VerificationResultPanel
                            result={result}
                            documentTitle={`${documentTitle} (v${versionNo})`}
                        />
                    )}
                </div>

                {/* Modal Footer */}
                <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50 flex justify-end">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-4 py-2 text-sm font-semibold text-slate-700 hover:text-slate-900 bg-white border border-slate-300 rounded-lg shadow-sm hover:bg-slate-50 transition-colors"
                    >
                        Đóng
                    </button>
                </div>
            </div>
        </div>
    );
};
