import React, { useState, useEffect, useRef } from 'react';
import {
    X,
    Key,
    Shield,
    CheckCircle2,
    AlertTriangle,
    FileCheck,
    Lock,
    Loader2,
    Clock,
    Info,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { keysApi } from '../../api/keys';
import { PublicKeyDto } from '../../types/key';
import { getKeyFromKeystore, listKeysForUser, StoredKeyRecord } from '../../crypto/keyStorage';
import { signaturesApi } from '../../api/signatures';
import { PrepareSignResponse, SignatureDto } from '../../types/signature';
import { SigningAttempt, rememberAttempt, forgetAttempt, restoreAttempt } from '../../crypto/pendingSigning';
import { validateManifestBinding } from '../../crypto/manifestBinding';
import { computeManifestSha256 } from '../../crypto/manifestCanonicalizer';
import { signManifest, verifyManifestSignature } from '../../crypto/signer';
import { PDFViewer } from '../../components/PDFViewer/PDFViewer';
import { errorMessage } from './index';
import { Link } from 'react-router-dom';

interface SignModalProps {
    documentId: string;
    versionId: string;
    versionNo: number;
    documentTitle: string;
    fileSha256: string;
    onClose: () => void;
    onSuccess: () => void;
}

interface KeyOption {
    serverKey: PublicKeyDto;
    hasLocalPrivateKey: boolean;
}

export const SignModal: React.FC<SignModalProps> = ({
    documentId,
    versionId,
    versionNo,
    documentTitle,
    fileSha256,
    onClose,
    onSuccess,
}) => {
    const { user } = useAuth();

    // Step state: 1 = Select Key, 2 = Review Manifest, 3 = Success
    const [step, setStep] = useState<1 | 2 | 3>(1);

    // Key options
    const [keyOptions, setKeyOptions] = useState<KeyOption[]>([]);
    const [selectedKeyId, setSelectedKeyId] = useState<string>('');
    const [loadingKeys, setLoadingKeys] = useState<boolean>(true);
    const [keysError, setKeysError] = useState<string>('');

    // Prepare sign state
    const [preparing, setPreparing] = useState<boolean>(false);
    const [prepareData, setPrepareData] = useState<PrepareSignResponse | null>(null);
    const [confirmedIntent, setConfirmedIntent] = useState<boolean>(false);

    // Signing state
    const [signing, setSigning] = useState<boolean>(false);
    const [signError, setSignError] = useState<string>('');
    const [successSignatureId, setSuccessSignatureId] = useState<string>('');

    // Load user's active keys and correlate with local IndexedDB private keys
    useEffect(() => {
        let mounted = true;
        const loadKeys = async () => {
            if (!user) return;
            setLoadingKeys(true);
            setKeysError('');

            try {
                const [serverKeys, localKeys] = await Promise.all([
                    keysApi.listMyKeys(),
                    listKeysForUser(user.id),
                ]);

                if (!mounted) return;

                const localFingerprints = new Set(
                    localKeys.map((k: StoredKeyRecord) => k.fingerprint.toLowerCase())
                );

                const activeServerKeys = serverKeys.filter((k) => k.status === 'ACTIVE' && !k.revoked_at && k.algorithm === 'RSA-PSS-3072');

                const options: KeyOption[] = activeServerKeys.map((sk) => ({
                    serverKey: sk,
                    hasLocalPrivateKey: localFingerprints.has(sk.fingerprint.toLowerCase()),
                }));

                setKeyOptions(options);

                // Auto-select first key that has a local private key, or first active key
                const preferred = options.find((o) => o.hasLocalPrivateKey) || options[0];
                if (preferred) {
                    setSelectedKeyId(preferred.serverKey.id);
                }
            } catch (err: unknown) {
                if (!mounted) return;
                setKeysError(await errorMessage(err));
            } finally {
                if (mounted) setLoadingKeys(false);
            }
        };

        void loadKeys();
        return () => {
            mounted = false;
        };
    }, [user]);

    const identity = `${documentId}/${versionId}/${selectedKeyId}/${user?.id}/${fileSha256}`;
    const flow = useRef({ identity, generation: 0 });
    if (flow.current.identity !== identity) flow.current = { identity, generation: flow.current.generation + 1 };
    const currentIdentity = useRef('');
    currentIdentity.current = `${identity}#${flow.current.generation}`;
    const mounted = useRef(true);
    const busy = useRef(false);
    const [preview, setPreview] = useState<{ identity: string; hash: string } | null>(null);
    const [pending, setPending] = useState<SigningAttempt | null>(null);
    const [recovery, setRecovery] = useState<'UNKNOWN' | 'NOT_SAVED' | null>(null);
    useEffect(() => {
        mounted.current = true;
        return () => {
            mounted.current = false;
            flow.current.generation += 1;
            currentIdentity.current = '';
        };
    }, []);
    useEffect(() => {
        setPrepareData(null);
        setConfirmedIntent(false);
        setStep(1);
        setSignError('');
        setPreview(null);
        setPending(null);
        setRecovery(null);
        if (user) {
            try {
                const previous = restoreAttempt(user.id, documentId, versionId);
                if (previous) {
                    setPending(previous);
                    setRecovery('UNKNOWN');
                    setSignError('UNKNOWN: có lần gửi trước cần kiểm tra kết quả trước khi ký tiếp.');
                }
            } catch {
                // Fail closed when durable recovery context is unavailable or malformed.
                setRecovery('UNKNOWN');
                setSignError('Không thể đọc context khôi phục. Hãy kiểm tra trạng thái phiên bản trên server.');
            }
        }
    }, [documentId, versionId, fileSha256, user?.id]);
    const isCurrent = (snapshot: string) => mounted.current && currentIdentity.current === snapshot;
    const changeKey = (id: string) => {
        if (busy.current || pending) return;
        setSelectedKeyId(id);
        currentIdentity.current = '';
        setPrepareData(null);
        setConfirmedIntent(false);
        setStep(1);
    };
    const handlePrepareSign = async () => {
        if (!selectedKeyId || busy.current || pending || recovery === 'UNKNOWN') return;
        const snapshot = currentIdentity.current;
        busy.current = true;
        setPreparing(true);
        setSignError('');
        try {
            const data = await signaturesApi.prepareSign(documentId, versionId, selectedKeyId);
            if (!isCurrent(snapshot)) return;
            setConfirmedIntent(false);
            setPrepareData(data);
            setStep(2);
        } catch (error: unknown) {
            if (isCurrent(snapshot)) setSignError(await errorMessage(error));
        } finally {
            busy.current = false;
            if (mounted.current) setPreparing(false);
        }
    };
    const matches = (sig: SignatureDto, attempt: NonNullable<typeof pending>) =>
        sig.version_id === attempt.request.version_id && sig.key_id === attempt.request.key_id &&
        sig.signer_id === attempt.userId && sig.algorithm === 'RSA-PSS-3072' &&
        sig.manifest_sha256 === attempt.hash && sig.signature_b64 === attempt.request.signature_b64;
    const success = (sig: SignatureDto) => {
        setSuccessSignatureId(sig.id);
        setPending(null);
        setRecovery(null);
        setSignError('');
        setStep(3);
        onSuccess();
    };
    const reconcile = async (attempt: NonNullable<typeof pending>, snapshot: string) => {
        const [version, signature] = await Promise.allSettled([
            signaturesApi.getVersionState(attempt.documentId, attempt.request.version_id),
            signaturesApi.getVersionSignature(attempt.documentId, attempt.request.version_id),
        ]);
        if (!isCurrent(snapshot)) return;
        if (version.status === 'fulfilled' && version.value.id === attempt.request.version_id) {
            if (version.value.state === 'SIGNED' && signature.status === 'fulfilled' && matches(signature.value, attempt)) {
                forgetAttempt(attempt);
                success(signature.value);
                return;
            }
            const reason: unknown = signature.status === 'rejected' ? signature.reason : null;
            const status = reason && typeof reason === 'object' && 'response' in reason ?
                (reason.response as { status?: number } | undefined)?.status : undefined;
            if (version.value.state === 'READY_TO_SIGN' && status === 404) {
                setRecovery('NOT_SAVED');
                setSignError('Đã xác nhận chưa lưu. Có thể gửi lại cùng chữ ký hoặc chuẩn bị phiên mới.');
                return;
            }
        }
        setRecovery('UNKNOWN');
        setSignError('UNKNOWN: chưa xác định được kết quả. Kiểm tra lại trước khi tạo phiên ký mới.');
    };
    const submitAttempt = async (attempt: NonNullable<typeof pending>, snapshot: string) => {
        rememberAttempt(attempt);
        setPending(attempt);
        setRecovery('UNKNOWN');
        try {
            const sig = await signaturesApi.submitSignature(attempt.request);
            if (matches(sig, attempt)) forgetAttempt(attempt);
            if (!isCurrent(snapshot)) return;
            if (matches(sig, attempt)) success(sig);
            else await reconcile(attempt, snapshot);
        } catch {
            if (isCurrent(snapshot)) await reconcile(attempt, snapshot);
        }
    };
    const handleExecuteSign = async () => {
        if (!prepareData || !selectedKeyId || !confirmedIntent || busy.current || pending || !user) return;
        const snapshot = currentIdentity.current;
        const selected = keyOptions.find(o => o.serverKey.id === selectedKeyId);
        busy.current = true;
        setSigning(true);
        setSignError('');
        try {
            if (!selected || preview?.identity !== `${documentId}/${versionId}`) throw new Error('Cần xem trước và xác minh PDF trước khi ký');
            const record = await getKeyFromKeystore(selected.serverKey.fingerprint);
            if (!isCurrent(snapshot)) return;
            if (!record?.privateKey) throw new Error('Không tìm thấy Private Key trên trình duyệt');
            await validateManifestBinding(prepareData.manifest, {
                versionId, metadataHash: fileSha256, previewHash: preview.hash,
                keyId: selectedKeyId, fingerprint: selected.serverKey.fingerprint, userId: user.id,
            }, record);
            const hash = await computeManifestSha256(prepareData.manifest);
            if (hash !== prepareData.manifest_sha256 || !Number.isFinite(Date.parse(prepareData.expires_at)) || Date.parse(prepareData.expires_at) <= Date.now()) throw new Error('Phiên ký không hợp lệ hoặc đã hết hạn');
            if (!isCurrent(snapshot)) return;
            const signature = await signManifest(prepareData.manifest, record.privateKey);
            // Verifies the private/public pairing, including non-extractable private keys.
            if (!await verifyManifestSignature(prepareData.manifest, signature, record.publicKey)) throw new Error('Private Key không khớp Public Key');
            if (!isCurrent(snapshot)) return;
            await submitAttempt({ documentId, userId: user.id, request: { version_id: versionId, key_id: selectedKeyId, manifest: prepareData.manifest, signature_b64: signature }, hash }, snapshot);
        } catch (error: unknown) {
            if (isCurrent(snapshot)) setSignError(await errorMessage(error));
        } finally {
            busy.current = false;
            if (mounted.current) setSigning(false);
        }
    };
    const recover = async (retry: boolean) => {
        if (!pending || busy.current) return;
        busy.current = true;
        setSigning(true);
        try {
            if (retry && recovery === 'NOT_SAVED') await submitAttempt(pending, currentIdentity.current);
            else await reconcile(pending, currentIdentity.current);
        } finally { busy.current = false; setSigning(false); }
    };

    const selectedOption = keyOptions.find((o) => o.serverKey.id === selectedKeyId);

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm overflow-y-auto"
            role="dialog"
            aria-modal="true"
            aria-labelledby="sign-modal-title"
        >
            <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-4xl overflow-hidden my-6">
                {/* Header */}
                <div className="bg-slate-50 border-b border-slate-200 px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-sky-100 text-sky-700 rounded-lg">
                            <Lock className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 id="sign-modal-title" className="text-lg font-bold text-slate-800">
                                Ký số Detached Manifest — RFC 8785
                            </h2>
                            <p className="text-xs text-slate-500">
                                {documentTitle} · Phiên bản v{versionNo}
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        disabled={signing || preparing}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200/60 transition-colors"
                        aria-label="Đóng cửa sổ"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Body Content */}
                <div className="p-6">
                    {/* Error Notice */}
                    {signError && (
                        <div
                            role="alert"
                            className="mb-4 p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 flex items-start gap-3 text-sm"
                        >
                            <AlertTriangle className="w-5 h-5 text-rose-500 flex-shrink-0 mt-0.5" />
                            <div className="flex-1">
                                <p className="font-semibold">Trạng thái thực hiện ký số</p>
                                <p className="text-xs text-rose-700 mt-0.5">{signError}</p>
                            </div>
                        </div>
                    )}

                    {pending && <div className="mb-4 flex gap-3 text-sm">
                        <button disabled={signing} onClick={() => void recover(false)}>Kiểm tra kết quả</button>
                        {recovery === 'NOT_SAVED' && <>
                            <button disabled={signing} onClick={() => void recover(true)}>Gửi lại cùng chữ ký</button>
                            <button disabled={signing} onClick={() => { forgetAttempt(pending); setPending(null); setRecovery(null); setPrepareData(null); setConfirmedIntent(false); setStep(1); }}>Chuẩn bị phiên mới</button>
                        </>}
                    </div>}
                    {/* Step 3: Success Screen */}
                    {step === 3 && (
                        <div className="py-8 text-center flex flex-col items-center">
                            <div className="w-16 h-16 bg-emerald-100 text-emerald-600 rounded-full flex items-center justify-center mb-4">
                                <CheckCircle2 className="w-10 h-10" />
                            </div>
                            <h3 className="text-xl font-bold text-slate-800 mb-2">Ký số thành công!</h3>
                            <p className="text-sm text-slate-600 max-w-md mb-6">
                                Chữ ký số RSA-PSS 3072-bit (Detached Manifest RFC 8785) đã được kiểm tra tính toàn vẹn
                                và lưu trữ an toàn trong hệ thống. Phiên bản tài liệu đã chuyển sang trạng thái <strong>SIGNED</strong> và được khóa chống ghi đè vĩnh viễn.
                            </p>

                            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 text-left w-full max-w-lg mb-6 text-xs font-mono space-y-2">
                                <div>
                                    <span className="text-slate-400">Signature ID:</span>{' '}
                                    <span className="text-slate-700 font-semibold">{successSignatureId}</span>
                                </div>
                                <div>
                                    <span className="text-slate-400">File SHA-256:</span>{' '}
                                    <span className="text-slate-600 break-all">{fileSha256}</span>
                                </div>
                                {prepareData && (
                                    <div>
                                        <span className="text-slate-400">Manifest SHA-256:</span>{' '}
                                        <span className="text-slate-600 break-all">
                                            {prepareData.manifest_sha256}
                                        </span>
                                    </div>
                                )}
                            </div>

                            <button
                                onClick={onClose}
                                className="px-6 py-2.5 bg-slate-800 hover:bg-slate-900 text-white font-medium rounded-xl text-sm transition shadow-sm"
                            >
                                Đóng cửa sổ
                            </button>
                        </div>
                    )}

                    {/* Step 1 & 2: Main Flow */}
                    {step !== 3 && (
                        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                            {/* Left: PDF Preview */}
                            <div className="lg:col-span-6 flex flex-col">
                                <div className="flex items-center justify-between mb-2">
                                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                                        Xem trước nội dung ký
                                    </span>
                                    <span className="text-xs text-slate-400 font-mono">
                                        SHA: {fileSha256.substring(0, 16)}…
                                    </span>
                                </div>
                                <PDFViewer key={`${documentId}/${versionId}`} documentId={documentId} versionId={versionId}
                                    onVerified={hash => setPreview({ identity: `${documentId}/${versionId}`, hash })}
                                    onError={() => { flow.current.generation += 1; currentIdentity.current = ''; setPreview(null); setConfirmedIntent(false); }} />
                            </div>

                            {/* Right: Key Selection & Manifest Confirmation */}
                            <div className="lg:col-span-6 flex flex-col justify-between">
                                {step === 1 && (
                                    <div className="space-y-4">
                                        <div>
                                            <h3 className="text-sm font-semibold text-slate-800 mb-1">
                                                1. Chọn Khóa Ký Số (RSA-PSS)
                                            </h3>
                                            <p className="text-xs text-slate-500">
                                                Hệ thống sử dụng khóa cá nhân được lưu bảo mật trong trình duyệt để tạo chữ ký số. Khóa riêng tư không bao giờ được gửi lên máy chủ.
                                            </p>
                                        </div>

                                        {loadingKeys ? (
                                            <div className="p-8 text-center bg-slate-50 rounded-xl border border-slate-200">
                                                <Loader2 className="w-6 h-6 text-sky-600 animate-spin mx-auto mb-2" />
                                                <p className="text-xs text-slate-500">Đang kiểm tra danh sách khóa...</p>
                                            </div>
                                        ) : keysError ? (
                                            <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700">
                                                {keysError}
                                            </div>
                                        ) : keyOptions.length === 0 ? (
                                            <div className="p-5 bg-amber-50 border border-amber-200 rounded-xl text-center">
                                                <AlertTriangle className="w-6 h-6 text-amber-600 mx-auto mb-2" />
                                                <p className="text-xs font-semibold text-amber-900 mb-1">
                                                    Không có cặp khóa hợp lệ
                                                </p>
                                                <p className="text-xs text-amber-700 mb-3">
                                                    Bạn chưa có khóa RSA-PSS 3072 ACTIVE trên hệ thống.
                                                </p>
                                                <Link
                                                    to="/keys"
                                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 text-white rounded-lg text-xs font-medium hover:bg-amber-700 transition"
                                                >
                                                    <Key className="w-3.5 h-3.5" /> Đến trang Quản lý khóa
                                                </Link>
                                            </div>
                                        ) : (
                                            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                                                {keyOptions.map((opt) => (
                                                    <label
                                                        key={opt.serverKey.id}
                                                        className={`block p-3 rounded-xl border cursor-pointer transition ${
                                                            selectedKeyId === opt.serverKey.id
                                                                ? 'border-sky-500 bg-sky-50/50 ring-1 ring-sky-500'
                                                                : 'border-slate-200 hover:border-slate-300 bg-white'
                                                        }`}
                                                    >
                                                        <div className="flex items-start gap-3">
                                                            <input
                                                                type="radio"
                                                                name="signing_key"
                                                                value={opt.serverKey.id}
                                                                checked={selectedKeyId === opt.serverKey.id}
                                                                onChange={() => changeKey(opt.serverKey.id)}
                                                                className="mt-1 text-sky-600 focus:ring-sky-500"
                                                            />
                                                            <div className="flex-1 min-w-0">
                                                                <div className="flex items-center justify-between">
                                                                    <span className="text-xs font-bold text-slate-800">
                                                                        {opt.serverKey.algorithm}
                                                                    </span>
                                                                    {opt.hasLocalPrivateKey ? (
                                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-100 text-emerald-800">
                                                                            <Shield className="w-3 h-3" /> Sẵn sàng ký
                                                                        </span>
                                                                    ) : (
                                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-rose-100 text-rose-700">
                                                                            Thiếu Private Key
                                                                        </span>
                                                                    )}
                                                                </div>
                                                                <p className="text-[11px] font-mono text-slate-500 mt-1 truncate">
                                                                    Fingerprint: {opt.serverKey.fingerprint}
                                                                </p>
                                                            </div>
                                                        </div>
                                                    </label>
                                                ))}
                                            </div>
                                        )}

                                        {selectedOption && !selectedOption.hasLocalPrivateKey && (
                                            <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-start gap-2">
                                                <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                                <span>
                                                    Khóa này chưa có Private Key trong trình duyệt. Bạn cần vào mục{' '}
                                                    <Link to="/keys" className="font-semibold underline">
                                                        Quản lý khóa
                                                    </Link>{' '}
                                                    để khôi phục từ tệp sao lưu trước khi có thể ký số.
                                                </span>
                                            </div>
                                        )}

                                        <div className="pt-4 border-t border-slate-200 flex justify-end gap-3">
                                            <button
                                                type="button"
                                                onClick={onClose}
                                                className="px-4 py-2 text-xs font-medium text-slate-600 hover:text-slate-800 rounded-lg hover:bg-slate-100 transition"
                                            >
                                                Hủy bỏ
                                            </button>
                                            <button
                                                type="button"
                                                disabled={
                                                    !selectedKeyId || !!pending || recovery === 'UNKNOWN' ||
                                                    preparing ||
                                                    loadingKeys ||
                                                    !selectedOption?.hasLocalPrivateKey
                                                }
                                                onClick={handlePrepareSign}
                                                className="inline-flex items-center gap-2 px-5 py-2 bg-sky-600 hover:bg-sky-700 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-sm transition"
                                            >
                                                {preparing && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                                                Tiếp tục: Chuẩn bị Manifest
                                            </button>
                                        </div>
                                    </div>
                                )}

                                {step === 2 && prepareData && (
                                    <div className="space-y-4">
                                        <div>
                                            <h3 className="text-sm font-semibold text-slate-800 mb-1">
                                                2. Xác nhận Manifest & Ký số
                                            </h3>
                                            <p className="text-xs text-slate-500">
                                                Backend đã khởi tạo Signing Session kèm Nonce duy nhất (TTL 5 phút). Bản kê Manifest sẽ được chuẩn hóa theo RFC 8785 (JCS) trước khi ký.
                                            </p>
                                        </div>

                                        {/* Manifest Details Box */}
                                        <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                                            <div className="flex items-center justify-between text-slate-500 border-b border-slate-200 pb-2">
                                                <span className="flex items-center gap-1 font-semibold">
                                                    <Clock className="w-3.5 h-3.5 text-amber-600" /> Hạn phiên ký:
                                                </span>
                                                <span className="font-mono text-slate-700">
                                                    {new Date(prepareData.expires_at).toLocaleTimeString('vi-VN')}
                                                </span>
                                            </div>
                                            <div>
                                                <span className="text-slate-400 block">File SHA-256:</span>
                                                <code className="text-slate-700 font-mono text-[11px] break-all">
                                                    {prepareData.manifest.document_sha256}
                                                </code>
                                            </div>
                                            <div>
                                                <span className="text-slate-400 block">Manifest SHA-256 (JCS RFC 8785):</span>
                                                <code className="text-sky-700 font-mono text-[11px] break-all font-semibold">
                                                    {prepareData.manifest_sha256}
                                                </code>
                                            </div>
                                            <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-200 text-[11px]">
                                                <div>
                                                    <span className="text-slate-400">Thuật toán:</span>{' '}
                                                    <span className="font-medium text-slate-700">
                                                        {prepareData.manifest.algorithm}
                                                    </span>
                                                </div>
                                                <div>
                                                    <span className="text-slate-400">Nonce:</span>{' '}
                                                    <span className="font-mono text-slate-700">
                                                        {prepareData.manifest.signing_nonce.substring(0, 10)}…
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Confirmation Checkbox */}
                                        <label className="flex items-start gap-2.5 p-3 rounded-xl bg-sky-50/60 border border-sky-100 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                disabled={signing}
                                                checked={confirmedIntent}
                                                onChange={(e) => setConfirmedIntent(e.target.checked)}
                                                className="mt-0.5 rounded text-sky-600 focus:ring-sky-500"
                                            />
                                            <span className="text-xs text-slate-700 leading-relaxed">
                                                Tôi đã xem xét đầy đủ nội dung tệp PDF, xác nhận giá trị băm SHA-256 và đồng ý dùng khóa cá nhân RSA-PSS của mình để ký số cam kết văn bản này.
                                            </span>
                                        </label>

                                        <div className="pt-4 border-t border-slate-200 flex justify-between gap-3">
                                            <button
                                                type="button"
                                                disabled={signing || !!pending}
                                                onClick={() => { setStep(1); setConfirmedIntent(false); setPrepareData(null); }}
                                                className="px-4 py-2 text-xs font-medium text-slate-600 hover:text-slate-800 rounded-lg hover:bg-slate-100 transition"
                                            >
                                                Quay lại
                                            </button>
                                            <button
                                                type="button"
                                                disabled={!confirmedIntent || signing || !!pending || preview?.identity !== `${documentId}/${versionId}`}
                                                onClick={handleExecuteSign}
                                                className="inline-flex items-center gap-2 px-5 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-sm transition"
                                            >
                                                {signing ? (
                                                    <>
                                                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                                        Đang tạo chữ ký RSA-PSS...
                                                    </>
                                                ) : (
                                                    <>
                                                        <FileCheck className="w-4 h-4" />
                                                        Ký số ngay (Sign with RSA-PSS)
                                                    </>
                                                )}
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};
