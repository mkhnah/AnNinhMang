import { StrictMode } from 'react';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SignModal } from '../SignModal';
import { generateRsaPssKeypair, GeneratedKeyBundle } from '../../../crypto/keygen';
import { computeManifestSha256 } from '../../../crypto/manifestCanonicalizer';
import { SignedManifest, SignatureDto } from '../../../types/signature';
import { StoredKeyRecord } from '../../../crypto/keyStorage';

const mocks = vi.hoisted(() => ({ prepare:vi.fn(), submit:vi.fn(), version:vi.fn(), signature:vi.fn(), keys:vi.fn(), local:vi.fn(), record:vi.fn(), sign:vi.fn(), verify:vi.fn(), success:vi.fn(), close:vi.fn(), preview:true, user:{id:"user-1"} }));
vi.mock('../../../context/AuthContext',()=>({useAuth:()=>({user:mocks.user})}));
vi.mock('../../../api/keys',()=>({keysApi:{listMyKeys:mocks.keys}}));
vi.mock('../../../crypto/keyStorage',()=>({listKeysForUser:mocks.local,getKeyFromKeystore:mocks.record}));
vi.mock('../../../api/signatures',()=>({signaturesApi:{prepareSign:mocks.prepare,submitSignature:mocks.submit,getVersionState:mocks.version,getVersionSignature:mocks.signature}}));
vi.mock('../../../crypto/signer',()=>({signManifest:mocks.sign,verifyManifestSignature:mocks.verify}));
vi.mock('../index',()=>({errorMessage:async(e:unknown)=>e instanceof Error?e.message:'Error'}));
vi.mock('../../../components/PDFViewer/PDFViewer',()=>({PDFViewer:({onVerified}:{onVerified:(hash:string)=>void})=><button onClick={()=>onVerified('a'.repeat(64))}>Preview ready</button>}));
const versionId='11111111-1111-4111-8111-111111111111';
const keyId='22222222-2222-4222-8222-222222222222';
const props={documentId:'document-A',versionId,versionNo:1,documentTitle:'PDF A',fileSha256:'a'.repeat(64),onClose:mocks.close,onSuccess:mocks.success};
let bundle:GeneratedKeyBundle;
let alternative:GeneratedKeyBundle;
let manifest:SignedManifest;
let record:StoredKeyRecord;
let saved:SignatureDto;
beforeAll(async()=>{bundle=await generateRsaPssKeypair(false);alternative=await generateRsaPssKeypair(false);});
beforeEach(async()=>{
    vi.clearAllMocks();sessionStorage.clear();
    manifest={manifest_version:1,document_version_id:versionId,document_sha256:'a'.repeat(64),key_id:keyId,signer_fingerprint:bundle.fingerprint,algorithm:'RSA-PSS-3072',signing_nonce:'A'.repeat(43),signing_timestamp:'2026-11-15T00:00:00.000Z',signing_context:'DOCSIGN_DOCUMENT_SIGNATURE_V1'};
    record={fingerprint:bundle.fingerprint,userId:'user-1',algorithm:'RSA-PSS-3072',privateKey:bundle.keyPair.privateKey,publicKey:bundle.keyPair.publicKey,spkiPem:bundle.spkiPem,extractable:false,createdAt:''};
    mocks.keys.mockResolvedValue([{id:keyId,fingerprint:bundle.fingerprint,algorithm:'RSA-PSS-3072',status:'ACTIVE'},{id:'33333333-3333-4333-8333-333333333333',fingerprint:'b'.repeat(64),algorithm:'RSA-PSS-3072',status:'ACTIVE'}]);
    mocks.local.mockResolvedValue([record]);mocks.record.mockResolvedValue(record);
    mocks.prepare.mockImplementation(async()=>({manifest,manifest_sha256:await computeManifestSha256(manifest),expires_at:new Date(Date.now()+300000).toISOString()}));
    saved={id:'signature-1',version_id:versionId,signer_id:'user-1',key_id:keyId,algorithm:'RSA-PSS-3072',manifest_sha256:await computeManifestSha256(manifest),signature_b64:'S'.repeat(512),signature_format:'DETACHED_JCS_V1',signed_at:'',created_at:''};
    mocks.sign.mockResolvedValue('S'.repeat(512));mocks.verify.mockResolvedValue(true);mocks.submit.mockResolvedValue(saved);
    mocks.version.mockResolvedValue({id:versionId,state:'SIGNED'});mocks.signature.mockResolvedValue(saved);
});
function mount(extra:Partial<typeof props>={}){return render(<StrictMode><MemoryRouter><SignModal {...props} {...extra}/></MemoryRouter></StrictMode>);}
async function prepare(preview=true){
    if(preview) fireEvent.click(screen.getByText('Preview ready'));
    const button=await screen.findByRole('button',{name:/Tiếp tục: Chuẩn bị/});
    await waitFor(()=>expect(button).toBeEnabled());fireEvent.click(button);
    await screen.findByRole('checkbox');
}
async function sign(){fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:/Ký số ngay/}));}

describe('SignModal document binding and recovery',()=>{
    it('requires rendered preview and explicit consent before signing',async()=>{
        mount();await prepare(false);
        expect(screen.getByRole('button',{name:/Ký số ngay/})).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('button',{name:/Ký số ngay/})).toBeDisabled();
        fireEvent.click(screen.getByText('Preview ready'));
        fireEvent.click(screen.getByRole('button',{name:/Ký số ngay/}));
        await screen.findByText('Ký số thành công!');expect(mocks.sign).toHaveBeenCalledTimes(1);
    });
    it.each([
        ['version',()=>{manifest.document_version_id='99999999-9999-4999-8999-999999999999';}],
        ['hash',()=>{manifest.document_sha256='b'.repeat(64);}],
        ['key ID',()=>{manifest.key_id='99999999-9999-4999-8999-999999999999';}],
        ['fingerprint',()=>{manifest.signer_fingerprint='b'.repeat(64);}],
        ['algorithm',()=>{manifest.algorithm='ECDSA-P256';}],
        ['context',()=>{Object.assign(manifest,{signing_context:'OTHER'});}],
        ['nonce',()=>{manifest.signing_nonce='bad';}],
        ['timestamp',()=>{manifest.signing_timestamp='2026-02-30T00:00:00.000Z';}],
        ['computed fingerprint',()=>{record.publicKey=alternative.keyPair.publicKey;}],
        ['local public fingerprint',()=>{record.fingerprint=bundle.fingerprint;Object.assign(record,{publicKey:{type:'public',algorithm:{name:'RSA-PSS',modulusLength:2048,hash:{name:'SHA-256'}}}});}],
    ])('never invokes signing for %s mismatch',async(_label,corrupt)=>{
        corrupt();mount();await prepare();await sign();
        await screen.findByRole('alert');expect(mocks.sign).not.toHaveBeenCalled();expect(mocks.submit).not.toHaveBeenCalled();
    });
    it('reconciles a committed signature after POST response is lost',async()=>{
        mocks.submit.mockRejectedValue(new Error('network'));mount();await prepare();await sign();
        await screen.findByText('Ký số thành công!');expect(mocks.version).toHaveBeenCalled();expect(mocks.signature).toHaveBeenCalled();expect(mocks.submit).toHaveBeenCalledTimes(1);
    });
    it('retains UNKNOWN and does not generate a new nonce until reconciliation succeeds',async()=>{
        mocks.submit.mockRejectedValue(new Error('network'));mocks.version.mockRejectedValue(new Error('offline'));mount();await prepare();await sign();
        await screen.findByText(/UNKNOWN:/);expect(mocks.prepare).toHaveBeenCalledTimes(1);expect(screen.getByRole('button',{name:/Ký số ngay/})).toBeDisabled();
        mocks.version.mockResolvedValue({id:versionId,state:'SIGNED'});fireEvent.click(screen.getByRole('button',{name:'Kiểm tra kết quả'}));
        await screen.findByText('Ký số thành công!');expect(mocks.sign).toHaveBeenCalledTimes(1);
    });
    it('never reports success for another signature',async()=>{
        mocks.submit.mockRejectedValue(new Error('network'));mocks.signature.mockResolvedValue({...saved,signature_b64:'different'});mount();await prepare();await sign();await screen.findByText(/UNKNOWN:/);expect(mocks.success).not.toHaveBeenCalled();
    });
    it('retries the exact attempt only after confirmed absence',async()=>{
        mocks.submit.mockRejectedValueOnce(new Error('network'));mocks.version.mockResolvedValue({id:versionId,state:'READY_TO_SIGN'});mocks.signature.mockRejectedValue({response:{status:404}});
        mount();await prepare();await sign();await screen.findByRole('button',{name:'Gửi lại cùng chữ ký'});
        fireEvent.click(screen.getByRole('button',{name:'Gửi lại cùng chữ ký'}));await screen.findByText('Ký số thành công!');
        expect(mocks.sign).toHaveBeenCalledTimes(1);expect(mocks.prepare).toHaveBeenCalledTimes(1);expect(mocks.submit.mock.calls[0]).toEqual(mocks.submit.mock.calls[1]);
    });
    it('restores public pending context after unmount without signing again',async()=>{
        mocks.submit.mockRejectedValue(new Error('network'));mocks.version.mockRejectedValue(new Error('offline'));
        const view=mount();await prepare();await sign();await screen.findByText(/UNKNOWN:/);view.unmount();
        mocks.version.mockResolvedValue({id:versionId,state:'SIGNED'});mount();
        await screen.findByText(/có lần gửi trước/);fireEvent.click(screen.getByRole('button',{name:'Kiểm tra kết quả'}));
        await screen.findByText('Ký số thành công!');expect(mocks.sign).toHaveBeenCalledTimes(1);expect(mocks.prepare).toHaveBeenCalledTimes(1);expect(sessionStorage.length).toBe(0);
    });
    it('invalidates preparation when the selected key changes',async()=>{
        mount();await prepare();fireEvent.click(screen.getByRole('button',{name:'Quay lại'}));
        const radios=screen.getAllByRole('radio');fireEvent.click(radios[1]);expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();expect(mocks.sign).not.toHaveBeenCalled();
    });
    it('discards an in-flight preparation when the document changes',async()=>{
        let resolve!:(value:unknown)=>void;
        mocks.prepare.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));
        const view=mount();const button=await screen.findByRole('button',{name:/Tiếp tục: Chuẩn bị/});await waitFor(()=>expect(button).toBeEnabled());fireEvent.click(button);
        view.rerender(<StrictMode><MemoryRouter><SignModal {...props} documentId="document-B" versionId="44444444-4444-4444-8444-444444444444"/></MemoryRouter></StrictMode>);
        resolve({manifest,manifest_sha256:await computeManifestSha256(manifest),expires_at:new Date(Date.now()+300000).toISOString()});
        await waitFor(()=>expect(button).toBeEnabled());expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();expect(mocks.sign).not.toHaveBeenCalled();
    });
});
