import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { KeyManagement } from './KeyManagement';
import { keysApi } from '../../api/keys';
import * as keystore from '../../crypto/keyStorage';
import * as keygen from '../../crypto/keygen';
import { createProofOfPossession } from '../../crypto/pop';
import type { GeneratedKeyBundle } from '../../crypto/keygen';
import type { PublicKeyDto } from '../../types/key';

vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'phase3-ui-owner' } }) }));
vi.mock('../../api/keys', () => ({ keysApi: { listMyKeys: vi.fn(), requestChallenge: vi.fn(), registerKey: vi.fn(), revokeKey: vi.fn() } }));
vi.mock('../../crypto/keygen', async importOriginal => {
    const original = await importOriginal<typeof import('../../crypto/keygen')>();
    return { ...original, generateRsaPssKeypair: vi.fn(original.generateRsaPssKeypair) };
});
vi.mock('../../crypto/pop', async importOriginal => {
    const original = await importOriginal<typeof import('../../crypto/pop')>();
    return { ...original, createProofOfPossession: vi.fn(original.createProofOfPossession) };
});

let bundle: GeneratedKeyBundle;
let record: keystore.StoredKeyRecord;
let remote: PublicKeyDto;
beforeAll(async () => {
    bundle = await keygen.generateRsaPssKeypair(false);
    record = { fingerprint: bundle.fingerprint, userId: 'phase3-ui-owner', algorithm: 'RSA-PSS-3072', privateKey: bundle.keyPair.privateKey, publicKey: bundle.keyPair.publicKey, spkiPem: bundle.spkiPem, extractable: false, createdAt: '2026-11-14T00:00:00Z', registrationState: 'LOCAL_ONLY' };
    remote = { id: 'remote-key', algorithm: 'RSA-PSS-3072', fingerprint: bundle.fingerprint, status: 'ACTIVE', created_at: record.createdAt };
}, 15000);
beforeEach(async () => {
    vi.clearAllMocks();
    await keystore.saveKeyToKeystore(record);
    vi.mocked(keysApi.listMyKeys).mockResolvedValue([]);
    vi.mocked(keysApi.requestChallenge).mockResolvedValue({ challenge_id: 'challenge-new-1', challenge_nonce: 'nonce-for-retry-123', expires_at: '2099-01-01T00:00:00Z', purpose: 'REGISTER_KEY', expected_algorithm: 'RSA-PSS-3072', expected_fingerprint: bundle.fingerprint });
    vi.mocked(keysApi.registerKey).mockResolvedValue(remote);
});
afterEach(async () => { cleanup(); vi.restoreAllMocks(); await keystore.removeKeyFromKeystore(record.fingerprint); });

describe('Phase 3 offline/retry release gates', () => {
    it('shows persisted local keys when backend is offline and after remount', async () => {
        vi.mocked(keysApi.listMyKeys).mockRejectedValue(new Error('offline'));
        const first = render(<KeyManagement />);
        expect(await screen.findByText(bundle.fingerprint)).toBeInTheDocument();
        expect(screen.getByText(/Không kết nối được máy chủ/)).toBeInTheDocument();
        first.unmount();
        render(<KeyManagement />);
        expect(await screen.findByText(bundle.fingerprint)).toBeInTheDocument();
        const persisted = await keystore.getKeyFromKeystore(bundle.fingerprint);
        expect(persisted?.privateKey.type).toBe('private');
        expect(keygen.generateRsaPssKeypair).not.toHaveBeenCalled();
    });

    it('does not infer unregistered or revoked state when server status is unknown', async () => {
        await keystore.saveKeyToKeystore({ ...record, registrationState: undefined });
        vi.mocked(keysApi.listMyKeys).mockRejectedValue(new Error('offline'));
        render(<KeyManagement />);
        expect(await screen.findByText(/UNKNOWN/)).toBeInTheDocument();
        expect(screen.queryByText(/^LOCAL_ONLY$/)).not.toBeInTheDocument();
        expect(screen.queryByText(/^REVOKED$/)).not.toBeInTheDocument();
    });

    it('retains last-confirmed REGISTERED when offline', async () => {
        await keystore.saveKeyToKeystore({ ...record, registrationState: 'REGISTERED' });
        vi.mocked(keysApi.listMyKeys).mockRejectedValue(new Error('offline'));
        render(<KeyManagement />);
        expect(await screen.findByText('REGISTERED (xác nhận gần nhất)')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Kiểm tra và đăng ký' })).not.toBeInTheDocument();
    });

    it('preserves failure feedback through refresh, then retries with the saved key and new challenge', async () => {
        vi.mocked(keysApi.listMyKeys).mockRejectedValue(new Error('registration offline'));
        render(<KeyManagement />);
        fireEvent.click(await screen.findByRole('button', { name: 'Kiểm tra và đăng ký' }));
        expect(await screen.findByText('REGISTRATION_FAILED')).toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent('registration offline');
        fireEvent.click(screen.getByTitle('Tải lại danh sách'));
        await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('registration offline'));
        vi.mocked(keysApi.listMyKeys).mockResolvedValue([]);
        vi.mocked(keysApi.registerKey).mockImplementation(async () => {
            vi.mocked(keysApi.listMyKeys).mockResolvedValue([remote]);
            return remote;
        });
        await waitFor(() => expect(screen.getByRole('button', { name: 'Thử đăng ký lại' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Thử đăng ký lại' }));
        expect(await screen.findByText(/^REGISTERED$/)).toBeInTheDocument();
        expect(keysApi.requestChallenge).toHaveBeenCalledWith('RSA-PSS-3072', bundle.fingerprint);
        expect(createProofOfPossession).toHaveBeenCalledWith(expect.objectContaining({ type: 'private' }), expect.objectContaining({ challenge_id: 'challenge-new-1', fingerprint: bundle.fingerprint }));
        const request = vi.mocked(keysApi.registerKey).mock.calls[0][0];
        expect(Object.keys(request).sort()).toEqual(['algorithm', 'challenge_id', 'pop_signature_b64', 'public_key_pem']);
        expect(JSON.stringify(request)).not.toContain('PRIVATE KEY');
        expect(keygen.generateRsaPssKeypair).not.toHaveBeenCalled();
        const persisted = await keystore.getKeyFromKeystore(bundle.fingerprint);
        expect(persisted?.registrationState).toBe('REGISTERED');
        const bytes = new TextEncoder().encode('same persisted key after retry');
        const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, persisted!.privateKey, bytes);
        expect(await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, bundle.keyPair.publicKey, signature, bytes)).toBe(true);
    });

    it('requests a fresh challenge on each retry, and keeps local key after API failure', async () => {
        vi.mocked(keysApi.registerKey).mockRejectedValue(new Error('registration rejected'));
        render(<KeyManagement />);
        fireEvent.click(await screen.findByRole('button', { name: 'Kiểm tra và đăng ký' }));
        expect(await screen.findByText('REGISTRATION_FAILED')).toBeInTheDocument();
        await waitFor(() => expect(screen.getByRole('button', { name: 'Thử đăng ký lại' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Thử đăng ký lại' }));
        await waitFor(() => expect(keysApi.requestChallenge).toHaveBeenCalledTimes(2));
        await waitFor(() => expect(screen.getByRole('button', { name: 'Thử đăng ký lại' })).toBeEnabled());
        expect(await keystore.getKeyFromKeystore(bundle.fingerprint)).not.toBeNull();
        expect(screen.getByRole('alert')).toHaveTextContent('registration rejected');
    });

    it('recognizes a successful POST with lost response without registering a duplicate', async () => {
        vi.mocked(keysApi.listMyKeys).mockResolvedValueOnce([]).mockResolvedValue([remote]);
        render(<KeyManagement />);
        fireEvent.click(await screen.findByRole('button', { name: 'Kiểm tra và đăng ký' }));
        expect(await screen.findByText(/^REGISTERED$/)).toBeInTheDocument();
        expect(keysApi.registerKey).not.toHaveBeenCalled();
        expect(keysApi.requestChallenge).not.toHaveBeenCalled();
    });

    it('shows REVOKED from server and prevents registration retry', async () => {
        vi.mocked(keysApi.listMyKeys).mockResolvedValue([{ ...remote, status: 'REVOKED' }]);
        render(<KeyManagement />);
        expect(await screen.findByText(/^REVOKED$/)).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Kiểm tra và đăng ký' })).not.toBeInTheDocument();
    });

    it('persists generated private key before API registration and retains it on failure', async () => {
        await keystore.removeKeyFromKeystore(bundle.fingerprint);
        vi.mocked(keygen.generateRsaPssKeypair).mockResolvedValue(bundle);
        vi.mocked(keysApi.registerKey).mockImplementation(async () => {
            expect((await keystore.getKeyFromKeystore(bundle.fingerprint))?.privateKey.type).toBe('private');
            throw new Error('server unavailable after key generation');
        });
        render(<KeyManagement />);
        fireEvent.click(screen.getByRole('button', { name: /Sinh Cặp Khóa Mới/ }));
        fireEvent.click(screen.getByDisplayValue('MODE_A_SECURE'));
        fireEvent.click(screen.getByRole('button', { name: 'Tạo & Đăng Ký Khóa' }));
        expect(await screen.findByText('REGISTRATION_FAILED')).toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent('server unavailable after key generation');
        expect((await keystore.getKeyFromKeystore(bundle.fingerprint))?.privateKey.type).toBe('private');
        expect(keygen.generateRsaPssKeypair).toHaveBeenCalledExactlyOnceWith(false);
    });

    it('keeps server keys visible when IndexedDB is unavailable', async () => {
        vi.spyOn(keystore, 'listKeysForUser').mockRejectedValue(new Error('storage unavailable'));
        vi.mocked(keysApi.listMyKeys).mockResolvedValue([remote]);
        render(<KeyManagement />);
        expect(await screen.findByText('HOẠT ĐỘNG')).toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent('Không đọc được IndexedDB');
    });
});
