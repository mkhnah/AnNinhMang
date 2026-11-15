import { StrictMode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { VerificationResultPanel } from '../../../components/Verification/VerificationResultPanel';
import { IndependentVerify } from '../IndependentVerify';
import {
    VerificationResultResponse,
    VerificationReportResponse,
} from '../../../types/verify';

const mocks = vi.hoisted(() => ({
    verifyIndependent: vi.fn(),
    generateReport: vi.fn(),
}));

vi.mock('../../../api/verify', () => ({
    verifyApi: {
        verifyIndependent: mocks.verifyIndependent,
        generateReport: mocks.generateReport,
    },
}));

const mockVerifiedResult: VerificationResultResponse = {
    verification_id: 'test-ver-uuid-1234',
    verification_receipt: 'A'.repeat(43),
    verification_mode: 'INDEPENDENT_DETACHED',
    summary_status: 'VERIFIED',
    results: {
        cryptographic_validity: 'VALID',
        document_integrity: 'UNCHANGED',
        key_ownership: 'VERIFIED_POP',
        certificate_trust: 'SELF_REGISTERED',
        key_revocation_status: 'ACTIVE',
        revoked_at: null,
        revocation_checked_at: '2026-11-15T10:00:00Z',
        revocation_source: 'DATABASE_LOCAL',
        server_timestamp: '2026-11-15T10:00:00Z',
        verification_time: '2026-11-15T10:00:01Z',
        trusted_timestamp: null,
        timestamp_trust_level: 'SERVER_RECORDED',
    },
    document_version_id: 'doc-ver-1',
    document_hash_expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    document_hash_computed: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    signer_fingerprint: '3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550',
    key_id: 'key-uuid-1',
    signature_algorithm: 'RSA-PSS-3072',
    signature_format: 'RFC8785-DETACHED-RSA-PSS',
    warnings: [],
};

const mockTamperedResult: VerificationResultResponse = {
    ...mockVerifiedResult,
    summary_status: 'INTEGRITY_COMPROMISED',
    results: {
        ...mockVerifiedResult.results,
        document_integrity: 'TAMPERED',
    },
    document_hash_expected: '1111111111111111111111111111111111111111111111111111111111111111',
    document_hash_computed: '2222222222222222222222222222222222222222222222222222222222222222',
    warnings: ['PDF hash does not match signed manifest!'],
};

const mockRevokedResult: VerificationResultResponse = {
    ...mockVerifiedResult,
    summary_status: 'REVOKED_KEY',
    results: {
        ...mockVerifiedResult.results,
        key_revocation_status: 'REVOKED',
        revoked_at: '2026-11-14T08:00:00Z',
    },
    warnings: ['Signing key was REVOKED prior to verification.'],
};

describe('VerificationResultPanel Component', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders all 6 independent dimensions correctly for a VERIFIED state', () => {
        render(
            <StrictMode>
                <VerificationResultPanel result={mockVerifiedResult} documentTitle="Contract.pdf" />
            </StrictMode>
        );

        expect(screen.getByText(/Xác minh thành công/i)).toBeInTheDocument();
        expect(screen.getByText('VALID')).toBeInTheDocument();
        expect(screen.getByText('UNCHANGED')).toBeInTheDocument();
        expect(screen.getByText('VERIFIED_POP')).toBeInTheDocument();
        expect(screen.getByText('SELF_REGISTERED')).toBeInTheDocument();
        expect(screen.getByText('ACTIVE')).toBeInTheDocument();
        expect(screen.getByText('SERVER_RECORDED')).toBeInTheDocument();
        expect(screen.getByText('Trùng khớp 100%')).toBeInTheDocument();
    });

    it('highlights TAMPERED document integrity and shows hash mismatch', () => {
        render(
            <StrictMode>
                <VerificationResultPanel result={mockTamperedResult} documentTitle="Contract.pdf" />
            </StrictMode>
        );

        expect(screen.getByText(/Cảnh báo vi phạm — Tệp đã bị chỉnh sửa/i)).toBeInTheDocument();
        expect(screen.getByText('TAMPERED')).toBeInTheDocument();
        expect(screen.getByText('Sai lệch mã băm')).toBeInTheDocument();
        expect(screen.getByLabelText('Expected SHA-256')).toHaveTextContent(mockTamperedResult.document_hash_expected);
        expect(screen.getByLabelText('Computed SHA-256')).toHaveTextContent(mockTamperedResult.document_hash_computed);
    });

    it('displays REVOKED_KEY warning and details', () => {
        render(
            <StrictMode>
                <VerificationResultPanel result={mockRevokedResult} documentTitle="Contract.pdf" />
            </StrictMode>
        );

        expect(screen.getByText(/Cảnh báo — Khóa ký đã bị thu hồi/i)).toBeInTheDocument();
        expect(screen.getByText('REVOKED')).toBeInTheDocument();
        expect(screen.getByText(/Signing key was REVOKED prior to verification/i)).toBeInTheDocument();
    });

    it('downloads verification report JSON when clicked', async () => {
        const mockReport: VerificationReportResponse = {
            report_version: 1,
            report_id: 'rep-uuid-1',
            generated_at: '2026-11-15T10:05:00Z',
            verification_result: mockVerifiedResult,
            evidence_source: 'DOCSIGN_STANDALONE_VERIFICATION_V1',
            disclaimer: 'Official cryptographic evidence.',
        };
        mocks.generateReport.mockResolvedValue(mockReport);

        // Mock URL.createObjectURL and revokeObjectURL
        const createObjectURLMock = vi.fn().mockReturnValue('blob:http://localhost/test-blob');
        const revokeObjectURLMock = vi.fn();
        window.URL.createObjectURL = createObjectURLMock;
        window.URL.revokeObjectURL = revokeObjectURLMock;

        render(
            <StrictMode>
                <VerificationResultPanel result={mockVerifiedResult} />
            </StrictMode>
        );

        vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
        const btn = screen.getByRole('button', { name: /Tải báo cáo JSON/i });
        fireEvent.click(btn);

        await waitFor(() => {
            expect(mocks.generateReport).toHaveBeenCalledWith(mockVerifiedResult.verification_receipt, expect.any(AbortSignal));
            expect(createObjectURLMock).toHaveBeenCalled();
        });
    });
});

describe('IndependentVerify Page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders upload instructions and disabled start button initially', () => {
        render(
            <StrictMode>
                <MemoryRouter>
                    <IndependentVerify />
                </MemoryRouter>
            </StrictMode>
        );

        expect(screen.getByText('Xác minh Tài liệu Độc lập')).toBeInTheDocument();
        const startBtn = screen.getByRole('button', { name: /Bắt đầu xác minh/i });
        expect(startBtn).toBeDisabled();
    });

    it('allows submitting verification with JSON text and displays results', async () => {
        mocks.verifyIndependent.mockResolvedValue(mockVerifiedResult);

        render(
            <StrictMode>
                <MemoryRouter>
                    <IndependentVerify />
                </MemoryRouter>
            </StrictMode>
        );

        // Create a fake PDF file
        const file = new File(['%PDF-1.4 test'], 'contract.pdf', { type: 'application/pdf' });
        const pdfInput = screen.getByLabelText('Chọn tệp PDF') as HTMLInputElement;

        // Simulate file input
        fireEvent.change(pdfInput, { target: { files: [file] } });

        // Switch to text mode for JSON
        const textTabBtn = screen.getByRole('button', { name: /Dán JSON/i });
        fireEvent.click(textTabBtn);

        const textarea = screen.getByPlaceholderText(/Dán nội dung JSON ở đây/i);
        fireEvent.change(textarea, { target: { value: '{"package_version":1,"manifest":{}}' } });

        const startBtn = screen.getByRole('button', { name: /Bắt đầu xác minh/i });
        await waitFor(() => expect(startBtn).toBeEnabled());

        fireEvent.click(startBtn);

        await waitFor(() => {
            expect(mocks.verifyIndependent).toHaveBeenCalledWith(
                file,
                null,
                '{"package_version":1,"manifest":{}}',
                expect.any(AbortSignal)
            );
            expect(screen.getByText(/Xác minh thành công/i)).toBeInTheDocument();
        });
    });
});


describe('Hash comparison accessibility', () => {
    it('marks exactly the differing characters and copies each digest independently', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
        const data = { ...mockVerifiedResult, document_hash_expected: 'a'.repeat(64), document_hash_computed: 'a'.repeat(63) + 'b' };
        const view = render(<VerificationResultPanel result={data}/>);
        expect(view.container.querySelectorAll('mark')).toHaveLength(2);
        expect(screen.getAllByLabelText('Khác tại ký tự 64')).toHaveLength(2);
        fireEvent.click(screen.getByRole('button', { name: 'Copy Expected SHA-256' }));
        await waitFor(() => expect(writeText).toHaveBeenCalledWith(data.document_hash_expected));
        fireEvent.click(screen.getByRole('button', { name: 'Copy Computed SHA-256' }));
        await waitFor(() => expect(writeText).toHaveBeenLastCalledWith(data.document_hash_computed));
        expect(screen.getByText(/không cho biết chính xác vị trí byte/)).toBeInTheDocument();
    });
    it('does not download a report after its result was unmounted', async () => {
        let finish!: (value: VerificationReportResponse) => void;
        mocks.generateReport.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
        const create = vi.fn(); URL.createObjectURL = create;
        const view = render(<VerificationResultPanel result={mockVerifiedResult}/>);
        fireEvent.click(screen.getByRole('button', { name: /Tải báo cáo JSON/ }));
        const signal = mocks.generateReport.mock.calls[mocks.generateReport.mock.calls.length - 1]?.[1] as AbortSignal;
        view.unmount(); expect(signal.aborted).toBe(true);
        finish({ report_version:1, report_id:'old', generated_at:'', verification_result:mockVerifiedResult, evidence_source:'', disclaimer:'' });
        await new Promise(resolve => setTimeout(resolve, 0));
        expect(create).not.toHaveBeenCalled();
    });
});


it('does not describe UNKNOWN evidence as CA trust or a hash mismatch', () => {
    const data: VerificationResultResponse = { ...mockVerifiedResult, summary_status:'UNVERIFIABLE', document_hash_computed:'', results: { ...mockVerifiedResult.results, cryptographic_validity:'UNVERIFIABLE', document_integrity:'UNKNOWN', key_ownership:'UNKNOWN', certificate_trust:'UNKNOWN', key_revocation_status:'UNKNOWN' } };
    render(<VerificationResultPanel result={data}/>);
    expect(screen.getByText('Chưa đủ dữ liệu băm')).toBeInTheDocument();
    expect(screen.queryByText('Sai lệch mã băm')).not.toBeInTheDocument();
    expect(screen.getByText('Chưa có bằng chứng khóa hoặc chuỗi chứng thư để đánh giá mức tin cậy.')).toBeInTheDocument();
});
