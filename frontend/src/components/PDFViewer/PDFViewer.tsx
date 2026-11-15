import React, { useEffect, useRef, useState } from 'react';
import * as pdfjsLib from 'pdfjs-dist';
import pdfjsWorker from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { computeFingerprint } from '../../crypto/spki';
import { MAX_PDF_BYTES, boundedScale } from './pdfBudget';
import api from '../../api/client';
import {
    ChevronLeft,
    ChevronRight,
    ZoomIn,
    ZoomOut,
    RotateCw,
    AlertCircle,
    Loader2,
    FileText,
} from 'lucide-react';

// Configure worker using Vite's static asset URL
pdfjsLib.GlobalWorkerOptions.workerSrc = pdfjsWorker;

interface PDFViewerProps {
    documentId: string;
    versionId: string;
    onLoadSuccess?: (numPages: number) => void;
    onError?: (error: string) => void;
    onVerified?: (hash: string) => void;
}

export const PDFViewer: React.FC<PDFViewerProps> = ({
    documentId,
    versionId,
    onLoadSuccess,
    onError,
    onVerified,
}) => {
    const canvasRef = useRef<HTMLCanvasElement | null>(null);
    const renderTaskRef = useRef<pdfjsLib.RenderTask | null>(null);
    const callbacks = useRef({ onLoadSuccess, onError, onVerified });
    callbacks.current = { onLoadSuccess, onError, onVerified };
    const [loaded, setLoaded] = useState<{ doc: pdfjsLib.PDFDocumentProxy; hash: string; identity: string } | null>(null);
    const identity = `${documentId}/${versionId}`;
    const [numPages, setNumPages] = useState(0);
    const [currentPage, setCurrentPage] = useState(1);
    const [scale, setScale] = useState(1);
    const [loading, setLoading] = useState(true);
    const [renderLoading, setRenderLoading] = useState(false);
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        let task: pdfjsLib.PDFDocumentLoadingTask | undefined;
        const controller = new AbortController();
        setLoaded(null);
        setLoading(true);
        setErrorMsg(null);
        void (async () => {
            try {
                const response = await api.get<ArrayBuffer>(
                    `/documents/${documentId}/versions/${versionId}/download`,
                    { responseType: 'arraybuffer', signal: controller.signal }
                );
                if (!active) return;
                if (!response.data.byteLength || response.data.byteLength > MAX_PDF_BYTES) throw new Error('PDF phải có kích thước từ 1 byte đến 20MB');
                const bytes = new Uint8Array(response.data);
                // Hash before PDF.js transfers ownership of the very same preview bytes.
                const hash = await computeFingerprint(bytes);
                if (!active) return;
                task = pdfjsLib.getDocument({ data: bytes, isEvalSupported: false,
                    disableRange: true, disableStream: true, maxImageSize: 16_000_000,
                    canvasMaxAreaInBytes: 16_000_000 });
                const doc = await task.promise;
                if (!active) return; // task.destroy() in cleanup owns document and worker too.
                setLoaded({ doc, hash, identity });
                setNumPages(doc.numPages);
                setCurrentPage(1);
                setScale(1);
                setLoading(false);
                callbacks.current.onLoadSuccess?.(doc.numPages);
            } catch (error: unknown) {
                if (!active) return;
                const message = error instanceof Error ? error.message : 'Không thể tải PDF';
                setErrorMsg(message);
                setLoading(false);
                callbacks.current.onError?.(message);
            }
        })();
        return () => {
            active = false;
            controller.abort();
            renderTaskRef.current?.cancel();
            // PDFDocumentLoadingTask.destroy destroys transport, PDF document and its owned worker.
            if (task) void task.destroy().catch(() => undefined);
        };
    }, [documentId, versionId, identity]);

    useEffect(() => {
        if (!loaded || loaded.identity !== identity || !canvasRef.current) return;
        let active = true;
        let render: pdfjsLib.RenderTask | undefined;
        setRenderLoading(true);
        void (async () => {
            try {
                const previous = renderTaskRef.current;
                previous?.cancel();
                if (previous) await previous.promise.catch(() => undefined);
                if (!active) return;
                const page = await loaded.doc.getPage(currentPage);
                if (!active) return;
                const canvas = canvasRef.current;
                if (!canvas) return;
                const context = canvas.getContext('2d');
                if (!context) throw new Error('Canvas không khả dụng');
                const natural = page.getViewport({ scale });
                const viewport = page.getViewport({ scale: boundedScale(natural.width, natural.height, scale) });
                canvas.width = Math.max(1, Math.floor(viewport.width));
                canvas.height = Math.max(1, Math.floor(viewport.height));
                render = page.render({ canvasContext: context, viewport });
                renderTaskRef.current = render;
                await render.promise;
                page.cleanup();
                if (active) {
                    setRenderLoading(false);
                    callbacks.current.onVerified?.(loaded.hash);
                }
            } catch (error: unknown) {
                if (!active) return;
                const message = error instanceof Error ? error.message : 'Không thể render PDF';
                setErrorMsg(message);
                setRenderLoading(false);
                callbacks.current.onError?.(message);
            }
        })();
        return () => {
            active = false;
            render?.cancel();
        };
    }, [loaded, identity, currentPage, scale]);

    const handlePrev = () => {
        if (currentPage > 1) setCurrentPage((p) => p - 1);
    };

    const handleNext = () => {
        if (currentPage < numPages) setCurrentPage((p) => p + 1);
    };

    const handleZoomIn = () => {
        setScale((s) => Math.min(2.0, s + 0.2));
    };

    const handleZoomOut = () => {
        setScale((s) => Math.max(0.6, s - 0.2));
    };

    const handleResetZoom = () => {
        setScale(1.0);
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-8 bg-slate-50 rounded-xl border border-slate-200 min-h-[320px]">
                <Loader2 className="w-8 h-8 text-sky-600 animate-spin mb-3" />
                <p className="text-sm font-medium text-slate-600">Đang tải và giải mã an toàn tệp PDF...</p>
                <p className="text-xs text-slate-400 mt-1">Đang kiểm tra SHA-256 của bytes PDF dùng để xem trước</p>
            </div>
        );
    }

    if (errorMsg) {
        return (
            <div className="flex flex-col items-center justify-center p-8 bg-rose-50 rounded-xl border border-rose-200 min-h-[280px] text-center">
                <AlertCircle className="w-8 h-8 text-rose-500 mb-2" />
                <p className="text-sm font-semibold text-rose-800">Không thể hiển thị xem trước PDF</p>
                <p className="text-xs text-rose-600 mt-1 max-w-sm">{errorMsg}</p>
            </div>
        );
    }

    return (
        <div className="flex flex-col bg-slate-100 rounded-xl border border-slate-200 overflow-hidden">
            {/* Toolbar */}
            <div className="bg-white border-b border-slate-200 px-4 py-2.5 flex items-center justify-between text-xs text-slate-600">
                <div className="flex items-center gap-1 font-medium">
                    <FileText className="w-4 h-4 text-sky-600 mr-1" />
                    <span>Trang {currentPage} / {numPages}</span>
                </div>

                <div className="flex items-center gap-1.5">
                    <button
                        type="button"
                        onClick={handlePrev}
                        disabled={currentPage <= 1 || renderLoading}
                        className="p-1 rounded hover:bg-slate-100 disabled:opacity-40 disabled:hover:bg-transparent"
                        title="Trang trước"
                    >
                        <ChevronLeft className="w-4 h-4" />
                    </button>
                    <button
                        type="button"
                        onClick={handleNext}
                        disabled={currentPage >= numPages || renderLoading}
                        className="p-1 rounded hover:bg-slate-100 disabled:opacity-40 disabled:hover:bg-transparent"
                        title="Trang sau"
                    >
                        <ChevronRight className="w-4 h-4" />
                    </button>

                    <div className="h-4 w-px bg-slate-200 mx-1" />

                    <button
                        type="button"
                        onClick={handleZoomOut}
                        disabled={scale <= 0.6}
                        className="p-1 rounded hover:bg-slate-100 disabled:opacity-40"
                        title="Thu nhỏ"
                    >
                        <ZoomOut className="w-4 h-4" />
                    </button>
                    <span className="w-10 text-center font-mono">{Math.round(scale * 100)}%</span>
                    <button
                        type="button"
                        onClick={handleZoomIn}
                        disabled={scale >= 2.0}
                        className="p-1 rounded hover:bg-slate-100 disabled:opacity-40"
                        title="Phóng to"
                    >
                        <ZoomIn className="w-4 h-4" />
                    </button>
                    <button
                        type="button"
                        onClick={handleResetZoom}
                        className="p-1 rounded hover:bg-slate-100"
                        title="Đặt lại tỉ lệ"
                    >
                        <RotateCw className="w-3.5 h-3.5" />
                    </button>
                </div>
            </div>

            {/* Canvas Viewport */}
            <div className="flex-1 overflow-auto p-4 flex items-center justify-center min-h-[380px] max-h-[500px] bg-slate-800/5 relative">
                {renderLoading && (
                    <div className="absolute inset-0 bg-white/60 backdrop-blur-[1px] flex items-center justify-center z-10">
                        <Loader2 className="w-6 h-6 text-sky-600 animate-spin" />
                    </div>
                )}
                <div className="shadow-lg bg-white rounded">
                    <canvas ref={canvasRef} className="block max-w-full h-auto" />
                </div>
            </div>
        </div>
    );
};
