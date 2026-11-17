import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Link } from 'react-router-dom';
import { keysApi } from '../../api/keys';
import { PublicKeyDto } from '../../types/key';
import { generateRsaPssKeypair } from '../../crypto/keygen';
import { createProofOfPossession } from '../../crypto/pop';
import { createEncryptedKeyBackup } from '../../crypto/keyBackup';
import { restoreEncryptedKeyBackup } from '../../crypto/keyRestore';
import {
    saveKeyToKeystore,
    getKeyFromKeystore,
    listKeysForUser,
    removeKeyFromKeystore,
    StoredKeyRecord,
} from '../../crypto/keyStorage';
import {
    Key,
    ShieldCheck,
    ShieldAlert,
    Download,
    Upload,
    Copy,
    Check,
    AlertTriangle,
    RefreshCw,
    Lock,
    X,
    CheckCircle2,
    HardDrive,
} from 'lucide-react';

export const KeyManagement: React.FC = () => {
    const { user } = useAuth();
    const [keys, setKeys] = useState<PublicKeyDto[]>([]);
    const [localKeys, setLocalKeys] = useState<StoredKeyRecord[]>([]);
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [successMessage, setSuccessMessage] = useState<string | null>(null);
    const [copiedFingerprint, setCopiedFingerprint] = useState<string | null>(null);

    const [serverAvailable, setServerAvailable] = useState<boolean | null>(null);
    const [serverError, setServerError] = useState<string | null>(null);
    const [localError, setLocalError] = useState<string | null>(null);

    // Modal state: Generate Key
    const [showGenModal, setShowGenModal] = useState(false);
    const [genMode, setGenMode] = useState<'MODE_B_BACKUP' | 'MODE_A_SECURE'>('MODE_B_BACKUP');
    const [genPassphrase, setGenPassphrase] = useState('');
    const [genPassphraseConfirm, setGenPassphraseConfirm] = useState('');

    // Modal state: Restore Key
    const [showRestoreModal, setShowRestoreModal] = useState(false);
    const [restoreFile, setRestoreFile] = useState<File | null>(null);
    const [restorePassphrase, setRestorePassphrase] = useState('');

    // Modal state: Revoke Key
    const [keyToRevoke, setKeyToRevoke] = useState<PublicKeyDto | null>(null);

    // Refresh errors are separate from operation errors; local storage is independent.
    const loadData = useCallback(async () => {
        if (!user) return;
        setLoading(true);
        const [server, local] = await Promise.allSettled([
            keysApi.listMyKeys(), listKeysForUser(user.id),
        ]);
        if (server.status === 'fulfilled') {
            setKeys(server.value);
            setServerAvailable(true);
            setServerError(null);
        } else {
            setServerAvailable(false);
            setServerError('Không kết nối được máy chủ. Trạng thái đăng ký/thu hồi chưa được xác nhận lại.');
        }
        if (local.status === 'fulfilled') {
            const records = local.value.map(record => {
                if (server.status !== 'fulfilled') return record;
                const remote = server.value.find(key => key.fingerprint === record.fingerprint);
                const registrationState = remote ? (remote.status === 'REVOKED' ? 'REVOKED' : 'REGISTERED') : record.registrationState || 'LOCAL_ONLY';
                return { ...record, registrationState } satisfies StoredKeyRecord;
            });
            setLocalKeys(records);
            setLocalError(null);
            const writes = await Promise.allSettled(records.filter((record, index) => record.registrationState !== local.value[index].registrationState).map(saveKeyToKeystore));
            if (writes.some(result => result.status === 'rejected')) setLocalError('Không thể lưu trạng thái mới vào thiết bị. Khóa vẫn được giữ nguyên.');
        } else {
            setLocalError('Không đọc được IndexedDB. Khóa trên máy chủ vẫn được hiển thị; chưa xác nhận khóa riêng trên thiết bị.');
        }
        setLoading(false);
    }, [user]);

    useEffect(() => { void loadData(); }, [loadData]);

    const handleCopy = (text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedFingerprint(id);
        setTimeout(() => setCopiedFingerprint(null), 2000);
    };

    const isKeyAvailableLocally = (fingerprint: string) => {
        return localKeys.some(
            (k) => k.fingerprint.toLowerCase() === fingerprint.toLowerCase()
        );
    };

    const localState = (key: StoredKeyRecord) => {
        if (serverAvailable) {
            const remote = keys.find(item => item.fingerprint === key.fingerprint);
            if (remote) return remote.status === 'REVOKED' ? 'REVOKED' : 'REGISTERED';
        }
        return key.registrationState || 'UNKNOWN';
    };

    // Retry registration of an existing local key that wasn't registered on server
    const handleRegisterExistingLocalKey = async (localKey: StoredKeyRecord) => {
        if (!user) return;
        setActionLoading(true);
        setError(null);
        setSuccessMessage(null);
        try {
            if (localKey.userId !== user.id) throw new Error('Khóa local không thuộc tài khoản đang đăng nhập.');
            // Reconcile a previous successful POST whose response may have been lost.
            const remote = (await keysApi.listMyKeys()).find(key => key.fingerprint === localKey.fingerprint);
            if (remote) {
                await saveKeyToKeystore({ ...localKey, registrationState: remote.status === 'REVOKED' ? 'REVOKED' : 'REGISTERED' });
                await loadData();
                return;
            }
            const challenge = await keysApi.requestChallenge('RSA-PSS-3072', localKey.fingerprint);
            const popSignature = await createProofOfPossession(localKey.privateKey, {
                schema_version: 1,
                purpose: 'REGISTER_KEY',
                challenge_id: challenge.challenge_id,
                challenge_nonce: challenge.challenge_nonce,
                user_id: user.id,
                algorithm: 'RSA-PSS-3072',
                fingerprint: localKey.fingerprint,
            });
            await keysApi.registerKey({
                public_key_pem: localKey.spkiPem,
                algorithm: 'RSA-PSS-3072',
                challenge_id: challenge.challenge_id,
                pop_signature_b64: popSignature,
            });
            await saveKeyToKeystore({ ...localKey, registrationState: 'REGISTERED' });
            setSuccessMessage(`Đã đăng ký thành công khóa ${localKey.fingerprint.slice(0, 16)}... lên máy chủ!`);
            await loadData();
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : 'Lỗi khi đăng ký khóa lên máy chủ';
            setError(msg);
            try { await saveKeyToKeystore({ ...localKey, registrationState: 'REGISTRATION_FAILED' }); }
            catch { setLocalError('Không thể lưu trạng thái đăng ký; khóa hiện có vẫn được giữ nguyên.'); }
            await loadData();
        } finally {
            setActionLoading(false);
        }
    };

    // --- Key Generation & Registration Flow ---
    const handleGenerateKey = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!user) return;

        const extractable = genMode === 'MODE_B_BACKUP';
        if (extractable) {
            if (genPassphrase.length < 8) {
                setError('Mật khẩu bảo vệ bản sao lưu phải có ít nhất 8 ký tự.');
                return;
            }
            if (genPassphrase !== genPassphraseConfirm) {
                setError('Xác nhận mật khẩu không khớp.');
                return;
            }
        }

        setActionLoading(true);
        setError(null);
        setSuccessMessage(null);

        try {
            // 1. Generate RSA-PSS 3072-bit keypair in browser memory
            const bundle = await generateRsaPssKeypair(extractable);

            // 2. Persist to local IndexedDB FIRST (resilience against loss / crash)
            const localRecord: StoredKeyRecord = {
                fingerprint: bundle.fingerprint,
                userId: user.id,
                algorithm: 'RSA-PSS-3072',
                privateKey: bundle.keyPair.privateKey,
                publicKey: bundle.keyPair.publicKey,
                spkiPem: bundle.spkiPem,
                extractable: extractable,
                registrationState: 'LOCAL_ONLY',
                createdAt: new Date().toISOString(),
            };
            await saveKeyToKeystore(localRecord);

            // 3. Immediately verify key is readable from IndexedDB
            const verified = await getKeyFromKeystore(bundle.fingerprint);
            if (!verified) {
                throw new Error('Không thể xác thực tính toàn vẹn của khóa đã lưu trong IndexedDB.');
            }

            // 4. If Mode B, create and trigger download of encrypted backup (.pem.enc)
            if (extractable) {
                const backup = await createEncryptedKeyBackup(
                    bundle.keyPair.privateKey,
                    bundle.fingerprint,
                    genPassphrase
                );
                const backupBlob = new Blob([JSON.stringify(backup, null, 2)], {
                    type: 'application/json',
                });
                const downloadUrl = URL.createObjectURL(backupBlob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = `docsign_key_${bundle.fingerprint.slice(0, 12)}.pem.enc`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
            }

            // Sensitive memory hygiene
            setGenPassphrase('');
            setGenPassphraseConfirm('');
            setShowGenModal(false);

            // 5. Register Public Key on backend with Proof-of-Possession
            try {
                const challenge = await keysApi.requestChallenge('RSA-PSS-3072', bundle.fingerprint);
                const popSignature = await createProofOfPossession(bundle.keyPair.privateKey, {
                    schema_version: 1,
                    purpose: 'REGISTER_KEY',
                    challenge_id: challenge.challenge_id,
                    challenge_nonce: challenge.challenge_nonce,
                    user_id: user.id,
                    algorithm: 'RSA-PSS-3072',
                    fingerprint: bundle.fingerprint,
                });

                const registeredKey = await keysApi.registerKey({
                    public_key_pem: bundle.spkiPem,
                    algorithm: 'RSA-PSS-3072',
                    challenge_id: challenge.challenge_id,
                    pop_signature_b64: popSignature,
                });

                await saveKeyToKeystore({ ...localRecord, registrationState: 'REGISTERED' });
                setSuccessMessage(
                    `Khóa RSA-PSS 3072-bit (Fingerprint: ${registeredKey.fingerprint.slice(0, 16)}...) đã được lưu an toàn vào trình duyệt và đăng ký thành công lên máy chủ!`
                );
            } catch (serverErr: unknown) {
                await saveKeyToKeystore({ ...localRecord, registrationState: 'REGISTRATION_FAILED' });
                const serverMsg = serverErr instanceof Error ? serverErr.message : 'Lỗi kết nối máy chủ';
                setError(
                    `Khóa đã được lưu vào trình duyệt, nhưng chưa thể xác nhận đăng ký lên máy chủ: ${serverMsg}. Bạn có thể bấm nút "Đăng ký lên máy chủ" ở bên dưới để thử lại bất cứ lúc nào.`
                );
            }

            await loadData();
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : 'Lỗi khi sinh hoặc lưu khóa';
            setError(msg);
        } finally {
            setActionLoading(false);
        }
    };

    // --- Key Restore Flow ---
    const handleRestoreKey = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!user || !restoreFile) {
            setError('Vui lòng chọn tệp sao lưu .pem.enc.');
            return;
        }

        if (restoreFile.size > 1024 * 1024) {
            setError('Tệp sao lưu vượt quá dung lượng tối đa cho phép (1MB).');
            return;
        }

        setActionLoading(true);
        setError(null);
        setSuccessMessage(null);

        try {
            const fileText = await restoreFile.text();
            let backupObj: unknown;
            try {
                backupObj = JSON.parse(fileText);
            } catch {
                throw new Error('Tệp tải lên không phải là JSON hợp lệ.');
            }

            // Decrypt, verify AAD, reconstruct public key, and self-test signature
            const restored = await restoreEncryptedKeyBackup(backupObj, restorePassphrase);

            // Store into IndexedDB
            await saveKeyToKeystore({
                fingerprint: restored.fingerprint,
                userId: user.id,
                algorithm: 'RSA-PSS-3072',
                privateKey: restored.privateKey,
                publicKey: restored.publicKey,
                spkiPem: restored.spkiPem,
                extractable: true,
                createdAt: new Date().toISOString(),
            });

            // Sensitive memory hygiene
            setRestorePassphrase('');
            setRestoreFile(null);
            setShowRestoreModal(false);

            setSuccessMessage(
                `Khôi phục khóa thành công (Fingerprint: ${restored.fingerprint.slice(0, 16)}...). Khóa đã sẵn sàng để ký số trên thiết bị này.`
            );
            await loadData();
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : 'Lỗi khi khôi phục khóa';
            setError(msg);
        } finally {
            setActionLoading(false);
        }
    };

    // --- Key Revocation Flow ---
    const handleRevokeKey = async () => {
        if (!keyToRevoke) return;
        setActionLoading(true);
        setError(null);
        try {
            await keysApi.revokeKey(keyToRevoke.id);
            // Also remove from local IndexedDB
            await removeKeyFromKeystore(keyToRevoke.fingerprint);
            setSuccessMessage(`Đã thu hồi thành công khóa ${keyToRevoke.fingerprint.slice(0, 16)}...`);
            setKeyToRevoke(null);
            await loadData();
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : 'Lỗi khi thu hồi khóa';
            setError(msg);
        } finally {
            setActionLoading(false);
        }
    };

    const downloadPem = (pem: string, fingerprint: string) => {
        const blob = new Blob([pem], { type: 'application/x-pem-file' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `public_key_${fingerprint.slice(0, 12)}.pem`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    return (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {/* Header */}
            <div className="md:flex md:items-center md:justify-between mb-8">
                <div className="flex-1 min-w-0">
                    <h1 className="text-2xl font-bold leading-7 text-slate-900 sm:text-3xl sm:truncate mt-1 flex items-center gap-2">
                        <Key className="w-7 h-7 text-sky-600" />
                        Khóa ký của tôi
                    </h1>

                </div>
                <div className="mt-4 flex md:mt-0 md:ml-4 gap-3">
                    <button
                        type="button"
                        onClick={() => setShowRestoreModal(true)}
                        className="inline-flex items-center px-4 py-2 border border-slate-300 rounded-lg shadow-sm text-sm font-medium text-slate-700 bg-white hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-sky-500"
                    >
                        <Upload className="w-4 h-4 mr-2 text-slate-500" />
                        Khôi phục khóa
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setError(null);
                            setGenPassphrase('');
                            setGenPassphraseConfirm('');
                            setShowGenModal(true);
                        }}
                        className="inline-flex items-center px-4 py-2 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-sky-600 hover:bg-sky-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-sky-500"
                    >
                        <Key className="w-4 h-4 mr-2" />
                        Tạo khóa mới
                    </button>
                </div>
            </div>

            {/* Messages */}
            {error && (
                <div role="alert" className="mb-6 bg-rose-50 border border-rose-200 text-rose-800 rounded-lg p-4 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-rose-600 flex-shrink-0" />
                        <span className="text-sm font-medium">{error}</span>
                    </div>
                    <button onClick={() => setError(null)} className="text-rose-500 hover:text-rose-700">
                        <X className="w-4 h-4" />
                    </button>
                </div>
            )}

            {successMessage && (
                <div className="mb-6 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg p-4 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                        <span className="text-sm font-medium">{successMessage} <Link to="/certificates" className="underline">Xem chứng chỉ đã cấp</Link></span>
                    </div>
                    <button onClick={() => setSuccessMessage(null)} className="text-emerald-500 hover:text-emerald-700">
                        <X className="w-4 h-4" />
                    </button>
                </div>
            )}

            {serverError && <p role="status" className="mb-4 rounded-lg bg-amber-50 p-4 text-sm text-amber-900">{serverError}</p>}
            {localError && <p role="alert" className="mb-4 rounded-lg bg-rose-50 p-4 text-sm text-rose-800">{localError}</p>}
            {localKeys.length > 0 && (
                <section aria-label="Khóa trên thiết bị này" className="mb-6 rounded-xl border border-slate-200 bg-white p-4">
                    <h2 className="font-semibold text-slate-900">Khóa trên thiết bị này</h2>

                    <ul className="mt-3 space-y-3">{localKeys.map(key => {
                        const state = localState(key);
                        return <li key={key.fingerprint} className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3">
                            <div className="min-w-0"><code className="break-all text-xs">{key.fingerprint}</code><p className="text-xs text-slate-600">{state}{serverAvailable === false && (state === 'REGISTERED' || state === 'REVOKED') ? ' (xác nhận gần nhất)' : ''}{state === 'UNKNOWN' ? ' — Chưa xác nhận đăng ký' : ''}</p></div>
                            {!['REGISTERED', 'REVOKED'].includes(state) && <button type="button" disabled={actionLoading} onClick={() => void handleRegisterExistingLocalKey(key)} className="rounded bg-sky-600 px-3 py-2 text-xs text-white disabled:opacity-50">{state === 'REGISTRATION_FAILED' ? 'Thử đăng ký lại' : 'Kiểm tra và đăng ký'}</button>}
                        </li>;
                    })}</ul>
                </section>
            )}

            {/* Keys Table */}
            <div className="bg-white shadow rounded-xl border border-slate-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50/50">
                    <h2 className="text-base font-semibold text-slate-800 flex items-center gap-2">
                        <span>Danh sách khóa</span>
                        <span className="bg-slate-200 text-slate-700 text-xs px-2 py-0.5 rounded-full font-bold">
                            {keys.length}
                        </span>
                    </h2>
                    <button
                        onClick={loadData}
                        disabled={loading}
                        className="inline-flex items-center text-xs font-medium text-slate-600 hover:text-sky-600 p-1.5 rounded hover:bg-slate-100 transition-colors"
                        title="Tải lại danh sách"
                    >
                        <RefreshCw className={`w-3.5 h-3.5 mr-1 ${loading ? 'animate-spin' : ''}`} />
                        Làm mới
                    </button>
                </div>

                {loading ? (
                    <div className="p-12 text-center text-slate-500">
                        <RefreshCw className="w-8 h-8 mx-auto animate-spin text-sky-600 mb-2" />
                        <p className="text-sm">Đang nạp thông tin khóa mật mã...</p>
                    </div>
                ) : keys.length === 0 ? (
                    <div className="p-12 text-center text-slate-500">
                        <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3 text-slate-400">
                            <Key className="w-6 h-6" />
                        </div>
                        <p className="font-medium text-slate-700">{serverAvailable === false ? 'Chưa tải được danh sách khóa từ máy chủ.' : 'Chưa có khóa chữ ký nào được đăng ký.'}</p>

                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-slate-200 text-sm">
                            <thead className="bg-slate-50">
                                <tr>
                                    <th className="px-6 py-3 text-left font-medium text-slate-500 uppercase tracking-wider text-xs">
                                        Thuật toán
                                    </th>
                                    <th className="px-6 py-3 text-left font-medium text-slate-500 uppercase tracking-wider text-xs">
                                        Fingerprint (SHA-256)
                                    </th>
                                    <th className="px-6 py-3 text-left font-medium text-slate-500 uppercase tracking-wider text-xs">
                                        Trạng thái
                                    </th>
                                    <th className="px-6 py-3 text-left font-medium text-slate-500 uppercase tracking-wider text-xs">
                                        Bộ nhớ máy này
                                    </th>
                                    <th className="px-6 py-3 text-left font-medium text-slate-500 uppercase tracking-wider text-xs">
                                        Ngày tạo
                                    </th>
                                    <th className="px-6 py-3 text-right font-medium text-slate-500 uppercase tracking-wider text-xs">
                                        Thao tác
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-slate-200">
                                {keys.map((k) => {
                                    const availableLocally = isKeyAvailableLocally(k.fingerprint);
                                    const isRevoked = k.status === 'REVOKED';

                                    return (
                                        <tr key={k.id} className="hover:bg-slate-50/80 transition-colors">
                                            <td className="px-6 py-4 whitespace-nowrap font-medium text-slate-900 flex items-center gap-2">
                                                <Key className="w-4 h-4 text-sky-600" />
                                                <span>{k.algorithm}</span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap font-mono text-xs text-slate-600">
                                                <div className="flex items-center gap-2">
                                                    <span title={k.fingerprint}>
                                                        {k.fingerprint.slice(0, 16)}...{k.fingerprint.slice(-8)}
                                                    </span>
                                                    <button
                                                        onClick={() => handleCopy(k.fingerprint, k.id)}
                                                        className="text-slate-400 hover:text-slate-600 p-1 rounded"
                                                        title="Sao chép toàn bộ Fingerprint"
                                                    >
                                                        {copiedFingerprint === k.id ? (
                                                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                                                        ) : (
                                                            <Copy className="w-3.5 h-3.5" />
                                                        )}
                                                    </button>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                {isRevoked ? (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-300">
                                                        <ShieldAlert className="w-3 h-3 mr-1 text-slate-500" />
                                                        ĐÃ THU HỒI
                                                    </span>
                                                ) : (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                                        <ShieldCheck className="w-3 h-3 mr-1 text-emerald-600" />
                                                        HOẠT ĐỘNG
                                                    </span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                {availableLocally ? (
                                                    <span className="inline-flex items-center text-xs font-medium text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200" title="Khóa bí mật sẵn sàng trong IndexedDB của trình duyệt này">
                                                        <HardDrive className="w-3 h-3 mr-1 text-emerald-600" />
                                                        {k.status === 'REVOKED' ? 'Có khóa local (đã thu hồi)' : serverAvailable === false ? 'Có khóa local (chưa xác nhận trạng thái)' : 'Có khóa local'}
                                                    </span>
                                                ) : (
                                                    <span className="inline-flex items-center text-xs font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded" title="Chưa có Private Key trên trình duyệt này. Hãy nhập từ file backup .pem.enc">
                                                        <Lock className="w-3 h-3 mr-1 text-slate-400" />
                                                        Chỉ có Public Key
                                                    </span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-slate-500 text-xs">
                                                {new Date(k.created_at).toLocaleString('vi-VN')}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-right text-xs font-medium">
                                                <div className="flex items-center justify-end gap-2">
                                                    {k.spki_pem && (
                                                        <button
                                                            onClick={() => downloadPem(k.spki_pem!, k.fingerprint)}
                                                            className="text-slate-600 hover:text-sky-600 inline-flex items-center px-2 py-1 rounded hover:bg-slate-100"
                                                            title="Tải tệp Public Key (SPKI PEM)"
                                                        >
                                                            <Download className="w-3.5 h-3.5 mr-1" />
                                                            PEM
                                                        </button>
                                                    )}
                                                    {!isRevoked && (
                                                        <button
                                                            onClick={() => setKeyToRevoke(k)}
                                                            className="text-rose-600 hover:text-rose-800 inline-flex items-center px-2 py-1 rounded hover:bg-rose-50"
                                                            title="Thu hồi khóa này"
                                                        >
                                                            <ShieldAlert className="w-3.5 h-3.5 mr-1" />
                                                            Thu hồi
                                                        </button>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Modal: Generate Key */}
            {showGenModal && (
                <div role="dialog" aria-modal="true" aria-label="Tạo khóa ký" className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-2xl shadow-xl max-w-lg w-full p-6 border border-slate-200">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                                <Key className="w-5 h-5 text-sky-600" />
                                Tạo khóa ký
                            </h3>
                            <button
                                onClick={() => !actionLoading && setShowGenModal(false)}
                                className="text-slate-400 hover:text-slate-600"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handleGenerateKey} className="space-y-4">
                            <div>
                                <label className="block text-sm font-semibold text-slate-800 mb-2">
                                    Chế độ lưu khóa
                                </label>
                                <div className="space-y-3">
                                    <label
                                        className={`block p-3 rounded-xl border cursor-pointer transition-all ${
                                            genMode === 'MODE_B_BACKUP'
                                                ? 'border-sky-500 bg-sky-50/50 ring-1 ring-sky-500'
                                                : 'border-slate-200 hover:border-slate-300'
                                        }`}
                                    >
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <input
                                                    type="radio"
                                                    name="genMode"
                                                    value="MODE_B_BACKUP"
                                                    checked={genMode === 'MODE_B_BACKUP'}
                                                    onChange={() => setGenMode('MODE_B_BACKUP')}
                                                    className="text-sky-600 focus:ring-sky-500"
                                                />
                                                <span className="font-medium text-slate-900 text-sm">
                                                    Cho phép sao lưu
                                                </span>
                                            </div>
                                            <Download className="w-4 h-4 text-sky-600" />
                                        </div>

                                    </label>

                                    <label
                                        className={`block p-3 rounded-xl border cursor-pointer transition-all ${
                                            genMode === 'MODE_A_SECURE'
                                                ? 'border-sky-500 bg-sky-50/50 ring-1 ring-sky-500'
                                                : 'border-slate-200 hover:border-slate-300'
                                        }`}
                                    >
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <input
                                                    type="radio"
                                                    name="genMode"
                                                    value="MODE_A_SECURE"
                                                    checked={genMode === 'MODE_A_SECURE'}
                                                    onChange={() => setGenMode('MODE_A_SECURE')}
                                                    className="text-sky-600 focus:ring-sky-500"
                                                />
                                                <span className="font-medium text-slate-900 text-sm">
                                                    Chỉ dùng trên thiết bị này
                                                </span>
                                            </div>
                                            <Lock className="w-4 h-4 text-slate-600" />
                                        </div>
                                    </label>
                                </div>
                            </div>

                            {genMode === 'MODE_B_BACKUP' && (
                                <div className="space-y-3 pt-2 border-t border-slate-100">
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-700 mb-1">
                                            Mật khẩu bản sao lưu
                                        </label>
                                        <input
                                            type="password"
                                            value={genPassphrase}
                                            onChange={(e) => setGenPassphrase(e.target.value)}
                                            placeholder="Tối thiểu 8 ký tự an toàn"
                                            required
                                            minLength={8}
                                            className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-sky-500 focus:border-sky-500"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-700 mb-1">
                                            Xác nhận mật khẩu
                                        </label>
                                        <input
                                            type="password"
                                            value={genPassphraseConfirm}
                                            onChange={(e) => setGenPassphraseConfirm(e.target.value)}
                                            placeholder="Nhập lại mật khẩu"
                                            required
                                            minLength={8}
                                            className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-sky-500 focus:border-sky-500"
                                        />
                                    </div>
                                </div>
                            )}

                            <div className="pt-4 flex justify-end gap-3">
                                <button
                                    type="button"
                                    disabled={actionLoading}
                                    onClick={() => setShowGenModal(false)}
                                    className="px-4 py-2 border border-slate-300 rounded-lg text-sm font-medium text-slate-700 bg-white hover:bg-slate-50"
                                >
                                    Hủy
                                </button>
                                <button
                                    type="submit"
                                    disabled={actionLoading}
                                    className="inline-flex items-center px-4 py-2 bg-sky-600 text-white rounded-lg text-sm font-medium hover:bg-sky-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-sky-500 disabled:opacity-50"
                                >
                                    {actionLoading ? (
                                        <>
                                            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                                            Đang tạo khóa…
                                        </>
                                    ) : (
                                        'Tạo khóa'
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Modal: Restore Key */}
            {showRestoreModal && (
                <div role="dialog" aria-modal="true" aria-label="Khôi phục khóa" className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-2xl shadow-xl max-w-lg w-full p-6 border border-slate-200">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                                <Upload className="w-5 h-5 text-sky-600" />
                                Khôi phục khóa
                            </h3>
                            <button
                                onClick={() => !actionLoading && setShowRestoreModal(false)}
                                className="text-slate-400 hover:text-slate-600"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <form onSubmit={handleRestoreKey} className="space-y-4">
                            <div>
                                <label className="block text-xs font-semibold text-slate-700 mb-1">
                                    Chọn tệp sao lưu (.pem.enc hoặc .json):
                                </label>
                                <input
                                    type="file"
                                    accept=".enc,.json,.pem.enc"
                                    onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
                                    required
                                    className="w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-sky-50 file:text-sky-700 hover:file:bg-sky-100 cursor-pointer border border-slate-200 rounded-lg p-1"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-700 mb-1">
                                    Mật khẩu giải mã:
                                </label>
                                <input
                                    type="password"
                                    value={restorePassphrase}
                                    onChange={(e) => setRestorePassphrase(e.target.value)}
                                    placeholder="Nhập mật khẩu đã đặt khi sao lưu"
                                    required
                                    className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-sky-500 focus:border-sky-500"
                                />
                            </div>



                            <div className="pt-4 flex justify-end gap-3">
                                <button
                                    type="button"
                                    disabled={actionLoading}
                                    onClick={() => setShowRestoreModal(false)}
                                    className="px-4 py-2 border border-slate-300 rounded-lg text-sm font-medium text-slate-700 bg-white hover:bg-slate-50"
                                >
                                    Hủy
                                </button>
                                <button
                                    type="submit"
                                    disabled={actionLoading}
                                    className="inline-flex items-center px-4 py-2 bg-sky-600 text-white rounded-lg text-sm font-medium hover:bg-sky-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-sky-500 disabled:opacity-50"
                                >
                                    {actionLoading ? (
                                        <>
                                            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                                            Đang giải mã...
                                        </>
                                    ) : (
                                        'Giải Mã & Khôi Phục'
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Modal: Confirm Revocation */}
            {keyToRevoke && (
                <div role="dialog" aria-modal="true" aria-label="Thu hồi khóa" className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6 border border-slate-200">
                        <div className="flex items-center gap-3 mb-4 text-rose-600">
                            <div className="w-10 h-10 rounded-full bg-rose-100 flex items-center justify-center flex-shrink-0">
                                <AlertTriangle className="w-5 h-5 text-rose-600" />
                            </div>
                            <div>
                                <h3 className="text-lg font-bold text-slate-900">Xác Nhận Thu Hồi Khóa</h3>
                                <p className="text-xs text-slate-500">Hành động này mang tính vĩnh viễn</p>
                            </div>
                        </div>

                        <p className="text-sm text-slate-600 mb-4">
                            Bạn có chắc chắn muốn thu hồi khóa có Fingerprint{' '}
                            <code className="bg-slate-100 px-1 py-0.5 rounded font-mono text-xs text-slate-800">
                                {keyToRevoke.fingerprint.slice(0, 16)}...
                            </code>
                            ? Khóa sau khi thu hồi sẽ không thể dùng để tạo chữ ký mới cho bất kỳ tài liệu nào.
                        </p>

                        <div className="flex justify-end gap-3">
                            <button
                                type="button"
                                disabled={actionLoading}
                                onClick={() => setKeyToRevoke(null)}
                                className="px-4 py-2 border border-slate-300 rounded-lg text-sm font-medium text-slate-700 bg-white hover:bg-slate-50"
                            >
                                Hủy bỏ
                            </button>
                            <button
                                type="button"
                                disabled={actionLoading}
                                onClick={handleRevokeKey}
                                className="inline-flex items-center px-4 py-2 bg-rose-600 text-white rounded-lg text-sm font-medium hover:bg-rose-700 disabled:opacity-50"
                            >
                                {actionLoading ? (
                                    <>
                                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                                        Đang thu hồi...
                                    </>
                                ) : (
                                    'Xác Nhận Thu Hồi'
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
