import api from './client';
import {
    VerificationResultResponse,
    SignaturePackage,
    VerificationReportResponse,
} from '../types/verify';

export const verifyApi = {
    /**
     * Mode B: Independent detached verification (Anonymous/Public).
     * Submits a PDF file and either a package JSON file or package JSON string.
     */
    verifyIndependent: async (
        pdfFile: File,
        packageFile?: File | null,
        packageJson?: string | null,
        signal?: AbortSignal,
        certificateFile?: File | null
    ): Promise<VerificationResultResponse> => {
        const formData = new FormData();
        formData.append('file', pdfFile);
        if (certificateFile) formData.append('certificate_file', certificateFile);

        if (packageFile) {
            formData.append('package_file', packageFile);
        } else if (packageJson) {
            formData.append('package_json', packageJson);
        }

        const response = await api.post<VerificationResultResponse>(
            '/verify/upload',
            formData,
            {
                signal,
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            }
        );
        return response.data;
    },

    /**
     * Mode A: Internal verification (Authenticated).
     * Verifies stored document version signature against database records and stored PDF.
     */
    verifyInternal: async (
        documentId: string,
        versionId: string
    ): Promise<VerificationResultResponse> => {
        const response = await api.get<VerificationResultResponse>(
            `/documents/${documentId}/versions/${versionId}/verify`
        );
        return response.data;
    },

    /**
     * Export detached signature package for a signed version.
     */
    exportSignaturePackage: async (
        documentId: string,
        versionId: string
    ): Promise<SignaturePackage> => {
        const response = await api.get<SignaturePackage>(
            `/documents/${documentId}/versions/${versionId}/signature-package`
        );
        return response.data;
    },

    /**
     * Generate and retrieve standardized verification report JSON.
     */
    generateReport: async (
        receiptId: string,
        signal?: AbortSignal
    ): Promise<VerificationReportResponse> => {
        const response = await api.post<VerificationReportResponse>(
            '/verify/report',
            { receipt_id: receiptId },
            { signal }
        );
        return response.data;
    },
};
