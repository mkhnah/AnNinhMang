import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PDFViewer } from '../PDFViewer';
import { computeFingerprint } from '../../../crypto/spki';
const mocks=vi.hoisted(()=>({get:vi.fn(),load:vi.fn(),destroy:vi.fn(),cancel:vi.fn(),render:vi.fn(),page:vi.fn(),cleanup:vi.fn()}));
vi.mock('../../../api/client',()=>({default:{get:mocks.get}}));
vi.mock('pdfjs-dist',()=>({GlobalWorkerOptions:{workerSrc:''},getDocument:mocks.load}));
vi.mock('pdfjs-dist/build/pdf.worker.min.mjs?url',()=>({default:'/worker.mjs'}));
let buffer:ArrayBuffer;
beforeEach(()=>{
    vi.clearAllMocks();
    buffer=new Uint8Array([37,80,68,70]).buffer;
    mocks.get.mockResolvedValue({data:buffer});mocks.destroy.mockResolvedValue(undefined);
    mocks.render.mockReturnValue({promise:Promise.resolve(),cancel:mocks.cancel});
    mocks.page.mockResolvedValue({getViewport:({scale}:{scale:number})=>({width:10000*scale,height:10000*scale}),render:mocks.render,cleanup:mocks.cleanup});
    mocks.load.mockReturnValue({promise:Promise.resolve({numPages:2,getPage:mocks.page}),destroy:mocks.destroy});
    vi.spyOn(HTMLCanvasElement.prototype,'getContext').mockReturnValue({} as CanvasRenderingContext2D);
});
describe('PDFViewer bounded preview and lifecycle',()=>{
    it.each([1,5,10,20])('hashes the exact %iMB preview bytes and caps canvas pixels',async mb=>{
        buffer=new Uint8Array(mb*1024*1024).buffer;mocks.get.mockResolvedValue({data:buffer});
        const verified=vi.fn();const view=render(<PDFViewer documentId="A" versionId="1" onVerified={verified}/>);
        await waitFor(()=>expect(verified).toHaveBeenCalledWith(expect.stringMatching(/^[a-f0-9]{64}$/)));
        expect(verified).toHaveBeenCalledWith(await computeFingerprint(new Uint8Array(buffer)));
        const data=mocks.load.mock.calls[0][0].data as Uint8Array;
        expect(data.buffer).toBe(buffer);
        const canvas=view.container.querySelector('canvas')!;
        expect(canvas.width*canvas.height).toBeLessThanOrEqual(4_000_000);expect(canvas.width).toBeLessThanOrEqual(4096);
        view.unmount();expect(mocks.destroy).toHaveBeenCalledTimes(1);expect(mocks.cancel).toHaveBeenCalled();
    });
    it('refuses files above 20MB before starting PDF.js',async()=>{
        mocks.get.mockResolvedValue({data:new Uint8Array(20*1024*1024+1).buffer});const verified=vi.fn();render(<PDFViewer documentId="A" versionId="1" onVerified={verified}/>);
        await screen.findByText(/PDF phải có kích thước/);expect(mocks.load).not.toHaveBeenCalled();expect(verified).not.toHaveBeenCalled();
    });
    it('aborts outstanding download on unmount',()=>{
        mocks.get.mockImplementation(()=>new Promise(()=>undefined));const view=render(<PDFViewer documentId="A" versionId="1"/>);const signal=mocks.get.mock.calls[0][1].signal as AbortSignal;
        view.unmount();expect(signal.aborted).toBe(true);
    });
    it('destroys an unresolved loading task and its owned worker',async()=>{
        mocks.load.mockReturnValue({promise:new Promise(()=>undefined),destroy:mocks.destroy});const view=render(<PDFViewer documentId="A" versionId="1"/>);
        await waitFor(()=>expect(mocks.load).toHaveBeenCalled());view.unmount();expect(mocks.destroy).toHaveBeenCalledTimes(1);
    });
    it('does not signal verified preview when canvas rendering fails',async()=>{
        mocks.render.mockImplementation(()=>({promise:Promise.reject(new Error('render failed')),cancel:mocks.cancel}));const verified=vi.fn(),error=vi.fn();render(<PDFViewer documentId="A" versionId="1" onVerified={verified} onError={error}/>);
        await screen.findByText('render failed');expect(error).toHaveBeenCalled();expect(verified).not.toHaveBeenCalled();
    });
    it('cancels the previous page before rendering the next page',async()=>{
        const view=render(<PDFViewer documentId="A" versionId="1"/>);await waitFor(()=>expect(mocks.cleanup).toHaveBeenCalledTimes(1));
        fireEvent.click(screen.getByTitle('Trang sau'));await waitFor(()=>expect(mocks.cleanup).toHaveBeenCalledTimes(2));expect(mocks.cancel).toHaveBeenCalled();
        view.rerender(<PDFViewer documentId="B" versionId="2"/>);await waitFor(()=>expect(mocks.load).toHaveBeenCalledTimes(2));expect(mocks.destroy).toHaveBeenCalledTimes(1);
    });
});
