import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { IndependentVerify } from '../IndependentVerify';
const mocks=vi.hoisted(()=>({verify:vi.fn(),export:vi.fn()}));
vi.mock('../../../api/verify',()=>({verifyApi:{verifyIndependent:mocks.verify}}));
vi.mock('../../../components/Verification/VerificationResultPanel',()=>({VerificationResultPanel:({documentTitle,result}:{documentTitle:string;result:{verification_id:string}})=><div><span>Result: {documentTitle}</span><span data-testid="result-id">{result.verification_id}</span><button onClick={mocks.export}>Export current</button></div>}));
const file=(name:string)=>new File(['fixture'],name,{type:name.endsWith('.pdf')?'application/pdf':'application/json'});
const choose=(label:string,name:string)=>fireEvent.change(screen.getByLabelText(label),{target:{files:[file(name)]}});
const submit=()=>fireEvent.click(screen.getByRole('button',{name:'Bắt đầu xác minh'}));
beforeEach(()=>vi.clearAllMocks());
it('discards PDF A response after choosing PDF B, aborts and cannot export stale result',async()=>{
 let resolve!:(r:unknown)=>void;mocks.verify.mockImplementation(()=>new Promise(r=>{resolve=r;}));
 render(<IndependentVerify/>);choose('Chọn tệp PDF','A.pdf');choose('Chọn tệp JSON','A.json');submit();
 const signal=mocks.verify.mock.calls[0][3] as AbortSignal;
 fireEvent.click(screen.getByRole('button',{name:'Đổi tệp khác'}));choose('Chọn tệp PDF','B.pdf');
 await act(async()=>resolve({verification_id:'A'}));
 expect(screen.queryByText(/Result:/)).not.toBeInTheDocument();expect(signal.aborted).toBe(true);expect(mocks.export).not.toHaveBeenCalled();
});
it('invalidates package A, accepts newer response B, discards late A',async()=>{
 const resolve:Array<(r:unknown)=>void>=[];mocks.verify.mockImplementation(()=>new Promise(r=>resolve.push(r)));
 render(<IndependentVerify/>);choose('Chọn tệp PDF','A.pdf');choose('Chọn tệp JSON','A.json');submit();
 fireEvent.click(screen.getByRole('button',{name:'Đổi tệp'}));choose('Chọn tệp JSON','B.json');submit();
 expect(mocks.verify).toHaveBeenCalledTimes(2);
 await act(async()=>resolve[1]({verification_id:'B'}));await screen.findByText('Result: A.pdf');
 await act(async()=>resolve[0]({verification_id:'A'}));expect(screen.getByText('Result: A.pdf')).toBeInTheDocument();expect(screen.getByTestId('result-id')).toHaveTextContent('B');
});
it('aborts on unmount',()=>{
 mocks.verify.mockImplementation(()=>new Promise(()=>undefined));const view=render(<IndependentVerify/>);
 choose('Chọn tệp PDF','A.pdf');choose('Chọn tệp JSON','A.json');submit();
 const signal=mocks.verify.mock.calls[0][3] as AbortSignal;view.unmount();expect(signal.aborted).toBe(true);
});
it('allows retry after network error',async()=>{
 mocks.verify.mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce({verification_id:'ok'});
 render(<IndependentVerify/>);choose('Chọn tệp PDF','A.pdf');choose('Chọn tệp JSON','A.json');submit();
 await waitFor(()=>expect(screen.getByRole('button',{name:'Bắt đầu xác minh'})).toBeEnabled());submit();await screen.findByText('Result: A.pdf');
});

it('recovers from a network abort without displaying a result',async()=>{
 mocks.verify.mockRejectedValueOnce(new DOMException('Network aborted','AbortError')).mockResolvedValueOnce({verification_id:'retry'});
 render(<IndependentVerify/>);choose('Chọn tệp PDF','A.pdf');choose('Chọn tệp JSON','A.json');submit();
 await waitFor(()=>expect(screen.getByRole('button',{name:'Bắt đầu xác minh'})).toBeEnabled());
 expect(screen.queryByText(/Result:/)).not.toBeInTheDocument();submit();await screen.findByText('Result: A.pdf');expect(screen.getByTestId('result-id')).toHaveTextContent('retry');
});
