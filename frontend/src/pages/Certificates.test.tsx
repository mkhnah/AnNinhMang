import { beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Certificates } from './Certificates';
import { generateRsaPssKeypair } from '../crypto/keygen';
const mocks = vi.hoisted(() => ({issue:vi.fn(), local:vi.fn(), certificates:vi.fn(), challenge:vi.fn()}));
vi.mock('../context/AuthContext', () => ({useAuth: () => ({user:{id:'owner-qa',role:'USER'}})}));
vi.mock('../crypto/keyStorage', () => ({getKeyFromKeystore:mocks.local}));
vi.mock('../api/keys', () => ({keysApi:{listMyKeys:async () => [{id:'key-qa',fingerprint:'a'.repeat(64),status:'ACTIVE',current_certificate_id:'cert-qa'}]}}));
vi.mock('../api/pki', () => ({pkiApi:{certificates:mocks.certificates, reviews:async()=>[], issue:mocks.issue, challenge:mocks.challenge}}));
const certificate = {id:'cert-qa', key_id:'key-qa', user_id:'owner-qa', subject:'CN=Fixture account', serial:'serial-qa',
    fingerprint:'a'.repeat(64),status:'ACTIVE',identity_assurance:'ACCOUNT_BOUND',not_before:'2026-01-01T00:00:00Z',
    not_after:'2099-01-01T00:00:00Z',revoked_at:null};
beforeAll(async () => {
    const key = await generateRsaPssKeypair(false);
    mocks.local.mockResolvedValue({userId:'owner-qa',privateKey:key.keyPair.privateKey});
});
beforeEach(() => {
    sessionStorage.clear();mocks.issue.mockReset();mocks.certificates.mockReset();mocks.challenge.mockReset();
    mocks.certificates.mockResolvedValue({items:[certificate],total:1});
    mocks.challenge.mockResolvedValue({challenge_id:'challenge-qa',payload:{context:'DOCSIGN_CERTIFICATE_POP_V1',user_id:'owner-qa',key_id:'key-qa'}});
});
it('retains the exact signed renewal request after a lost response and remount', async () => {
    mocks.issue.mockRejectedValueOnce(new Error('Connection lost')).mockResolvedValueOnce(certificate);
    const first = render(<MemoryRouter><Certificates /></MemoryRouter>);
    await screen.findByText('CN=Fixture account');
    fireEvent.click(screen.getByRole('button',{name:'Gia hạn / cập nhật danh tính'}));
    await screen.findByRole('alert');
    const original = mocks.issue.mock.calls[0];
    expect(original[1].pop_signature_b64).toHaveLength(512);
    expect(sessionStorage.getItem('docsign.pending-certificate.v1/owner-qa')).toBeTruthy();
    first.unmount();
    render(<MemoryRouter><Certificates /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button',{name:'Thử gửi lại yêu cầu'}));
    await waitFor(() => expect(mocks.issue).toHaveBeenCalledTimes(2));
    expect(mocks.issue.mock.calls[1]).toEqual(original);
    await waitFor(() => expect(sessionStorage.getItem('docsign.pending-certificate.v1/owner-qa')).toBeNull());
    expect(mocks.challenge).toHaveBeenCalledTimes(1);
});
it('blocks renewal for a revoked certificate', async () => {
    mocks.certificates.mockResolvedValue({items:[{...certificate,status:'REVOKED',revoked_at:'2026-11-16T00:00:00Z'}],total:1});
    render(<MemoryRouter><Certificates /></MemoryRouter>);
    expect(await screen.findByRole('button',{name:'Gia hạn / cập nhật danh tính'})).toBeDisabled();
    expect(screen.getByRole('button',{name:'Chứng minh sở hữu khóa'})).toBeDisabled();
});
