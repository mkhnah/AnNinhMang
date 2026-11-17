import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PkiVerify } from '../PkiVerify';
const mocks = vi.hoisted(() => ({verify:vi.fn(), signature:vi.fn()}));
vi.mock('../../../api/pki', () => ({pkiApi:{verifyCertificate:mocks.verify, verifySignature:mocks.signature}}));
const result = {verified:true, checked_at:'2026-11-16T10:00:00Z', certificate_binding:'MATCHED', certificate_chain:'VALID',
    certificate_validity:'VALID', certificate_revocation:'ACTIVE', identity_binding:'MATCHED', identity_assurance:'ACCOUNT_BOUND',
    subject:'CN=Fixture account', issuer:'CN=Fixture CA', fingerprint:'a'.repeat(64), user_id:'ad46cc70-1111-4444-aaaa-123456789012'};
const file = (name = 'certificate.pem', content = 'certificate-A') => {
    const value = new File([content], name);
    Object.defineProperty(value, 'text', {value:vi.fn().mockResolvedValue(content)});
    return value;
};
const choose = (value:File, label = 'Tải chứng chỉ PEM') => fireEvent.change(screen.getByLabelText(label), {target:{files:[value]}});
const submit = () => fireEvent.click(screen.getByRole('button', {name:'Bắt đầu xác minh'}));
beforeEach(() => vi.clearAllMocks());

describe('Certificate verification lifecycle', () => {
    it('requires only a certificate file and clears it when the replacement exceeds the limit', () => {
        render(<MemoryRouter><PkiVerify /></MemoryRouter>);
        expect(document.querySelectorAll('input[type="file"]')).toHaveLength(1);
        choose(file());
        choose(file('oversized.pem', 'x'.repeat(16385)));
        expect(screen.getByRole('button', {name:'Bắt đầu xác minh'})).toBeDisabled();
        expect(screen.getByRole('alert')).toHaveTextContent('16 KB');
        expect(mocks.verify).not.toHaveBeenCalled();
    });
    it('discards a file read that completes after choosing another certificate', async () => {
        let resolve!: (value:string) => void;
        const pending = new File(['fixture'], 'pending.pem');
        Object.defineProperty(pending,'text',{value:() => new Promise<string>(r => {resolve=r;})});
        render(<MemoryRouter><PkiVerify /></MemoryRouter>);
        choose(pending); submit(); choose(file('replacement.pem'));
        await act(async () => resolve('stale-certificate'));
        expect(mocks.verify).not.toHaveBeenCalled();
    });
    it('discards a late response after replacing the certificate', async () => {
        let resolve!: (value:unknown) => void;
        mocks.verify.mockImplementation(() => new Promise(r => {resolve=r;}));
        render(<MemoryRouter><PkiVerify /></MemoryRouter>);
        choose(file()); submit();
        await waitFor(() => expect(mocks.verify).toHaveBeenCalled());
        const signal = mocks.verify.mock.calls[0][1] as AbortSignal;
        choose(file('replacement.pem'));
        expect(signal.aborted).toBe(true);
        await act(async () => resolve(result));
        expect(screen.queryByRole('status')).not.toBeInTheDocument();
    });
    it('shows certificate information and clears the result when input changes', async () => {
        mocks.verify.mockResolvedValue(result);
        render(<MemoryRouter><PkiVerify /></MemoryRouter>);
        choose(file()); submit();
        expect(await screen.findByText('Đã xác minh trong miền CA DocSign')).toBeInTheDocument();
        expect(mocks.verify).toHaveBeenCalledWith('certificate-A', expect.any(AbortSignal));
        expect(screen.getByText('CN=Fixture account')).toBeInTheDocument();
        expect(screen.getByRole('link', {name:'Đối chiếu UUID người dùng'})).toHaveAttribute('href', '/verify/users?uuid='+result.user_id);
        choose(file('replacement.pem'));
        expect(screen.queryByText('Đã xác minh trong miền CA DocSign')).not.toBeInTheDocument();
    });
});

describe('Signature package verification', () => {
    it('requires signature and certificate files, submits their content, and explains the PDF scope', async () => {
        mocks.signature.mockResolvedValue({...result, purpose:'SIGNATURE_PACKAGE', cryptographic_validity:'VALID', document_integrity:'UNKNOWN',
            timestamp_trust:'TRUSTED_TSA', trusted_timestamp:'2026-11-17T10:00:00Z', timestamp_authority:'CN=DocSign Internal TSA'});
        render(<MemoryRouter><PkiVerify signature /></MemoryRouter>);
        expect(document.querySelectorAll('input[type="file"]')).toHaveLength(2);
        expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
        choose(file());
        expect(screen.getByRole('button', {name:'Bắt đầu xác minh'})).toBeDisabled();
        choose(file('signature-package.json', '{"package_version":2}'), 'Chọn file signature');
        submit();
        await waitFor(() => expect(mocks.signature).toHaveBeenCalledWith('certificate-A', '{"package_version":2}', expect.any(AbortSignal)));
        expect(await screen.findByText(/Tính toàn vẹn của PDF chưa được kiểm tra/)).toBeInTheDocument();
        expect(screen.getByText('Dấu thời gian: TRUSTED_TSA')).toBeInTheDocument();
        expect(mocks.verify).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', {name:'Bỏ Chọn file signature'}));
        expect(screen.queryByRole('status')).not.toBeInTheDocument();
        expect(screen.getByRole('button', {name:'Bắt đầu xác minh'})).toBeDisabled();
    });
    it('clears a signature file when an oversized or wrong-format replacement is selected', () => {
        render(<MemoryRouter><PkiVerify signature /></MemoryRouter>);
        choose(file()); choose(file('signature.json'), 'Chọn file signature');
        choose(file('huge.json', 'x'.repeat(524289)), 'Chọn file signature');
        expect(screen.getByRole('alert')).toHaveTextContent('512 KB');
        expect(screen.getByRole('button', {name:'Bắt đầu xác minh'})).toBeDisabled();
        choose(file('wrong.pdf'), 'Chọn file signature');
        expect(screen.getByRole('alert')).toHaveTextContent('signature-package.json');
    });
    it('discards a late signature response after replacing an input', async () => {
        let resolve!: (value:unknown) => void;
        mocks.signature.mockImplementation(() => new Promise(r => {resolve=r;}));
        render(<MemoryRouter><PkiVerify signature /></MemoryRouter>);
        choose(file()); choose(file('signature.json'), 'Chọn file signature'); submit();
        await waitFor(() => expect(mocks.signature).toHaveBeenCalled());
        const signal = mocks.signature.mock.calls[0][2] as AbortSignal;
        choose(file('replacement.json'), 'Chọn file signature');
        expect(signal.aborted).toBe(true);
        await act(async () => resolve(result));
        expect(screen.queryByRole('status')).not.toBeInTheDocument();
    });
});
