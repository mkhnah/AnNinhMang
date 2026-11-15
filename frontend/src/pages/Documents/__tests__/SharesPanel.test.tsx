import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {beforeEach, expect, it, vi} from 'vitest';
import {SharesPanel} from '../SharesPanel';
import {sharesApi, ShareListItem} from '../../../api/shares';
vi.mock('../../../api/shares', () => ({sharesApi:{list:vi.fn(),revoke:vi.fn()}}));
const rows=(n:number,start=0):ShareListItem[]=>Array.from({length:n},(_,i)=>({id:`id-${i+start}`,version_id:'v',label:`Share ${i+start}`,status:'ACTIVE',expires_at:'2027-01-01T00:00:00Z',revoked_at:null}));
beforeEach(()=>vi.clearAllMocks());
it.each([0,1,20,21,50])('loads every record from %i shares', async n=>{
 const all=rows(n);vi.mocked(sharesApi.list).mockImplementation(async(_d,_v,limit=20,offset=0)=>all.slice(offset,offset+limit));
 render(<SharesPanel documentId="A"/>);
 await waitFor(()=>expect(sharesApi.list).toHaveBeenCalledTimes(1));
 if(n>20){fireEvent.click(await screen.findByText('Tải thêm liên kết'));await screen.findByText('Share 20');}
 if(n>40){fireEvent.click(await screen.findByText('Tải thêm liên kết'));await screen.findByText('Share 49');}
 await waitFor(()=>expect(screen.getByText(`Đã tải ${n} liên kết`)).toBeInTheDocument());
 if(n===0)expect(screen.getByText('Chưa có liên kết QR nào được tạo cho tài liệu này.')).toBeInTheDocument();
});
it('retains pages on page-2 error, retries, deduplicates and revokes page 2 without resetting pages',async()=>{
 vi.mocked(sharesApi.list).mockResolvedValueOnce(rows(20)).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([rows(1,19)[0],rows(1,20)[0]]);
 vi.mocked(sharesApi.revoke).mockResolvedValue(undefined as never);
 render(<SharesPanel documentId="A"/>);fireEvent.click(await screen.findByText('Tải thêm liên kết'));
 fireEvent.click(await screen.findByText('Thử lại tải liên kết'));await screen.findByText('Share 20');
 expect(screen.getByText('Đã tải 21 liên kết')).toBeInTheDocument();expect(screen.getAllByText('Share 19')).toHaveLength(1);
 fireEvent.click(screen.getByLabelText('Thu hồi Share 20'));fireEvent.click(screen.getByText('Xác nhận thu hồi'));
 await screen.findByText('Đã thu hồi');expect(screen.getByText('Share 0')).toBeInTheDocument();expect(sharesApi.list).toHaveBeenCalledTimes(3);
 expect(vi.mocked(sharesApi.list).mock.calls[2][3]).toBe(20);
});
it('discards late document A results after switching to B and aborts A',async()=>{
 let resolve!:(r:ShareListItem[])=>void;
 vi.mocked(sharesApi.list).mockReturnValueOnce(new Promise(r=>{resolve=r;})).mockResolvedValueOnce(rows(1,99));
 const view=render(<SharesPanel key="A" documentId="A"/>);const signal=vi.mocked(sharesApi.list).mock.calls[0][4];
 view.rerender(<SharesPanel key="B" documentId="B"/>);await screen.findByText('Share 99');
 await act(async()=>resolve(rows(20)));expect(screen.queryByText('Share 0')).not.toBeInTheDocument();expect(signal?.aborted).toBe(true);
});
it('reloads explicitly from offset zero',async()=>{
 vi.mocked(sharesApi.list).mockResolvedValueOnce(rows(20)).mockResolvedValueOnce(rows(1,55));
 render(<SharesPanel documentId="A"/>);await screen.findByText('Share 0');fireEvent.click(screen.getByText('Tải lại liên kết'));
 await screen.findByText('Share 55');expect(screen.queryByText('Share 0')).not.toBeInTheDocument();expect(vi.mocked(sharesApi.list).mock.calls[1][3]).toBe(0);
});
