import api from './client';
import {
    PrepareSignResponse,
    SignatureSubmitRequest,
    SignatureDto,
} from '../types/signature';

export const signaturesApi = {
    getVersionState: async (documentId: string, versionId: string): Promise<{ id: string; state: string }> => {
        const response = await api.get<{ id: string; state: string }>(`/documents/${documentId}/versions/${versionId}`);
        return response.data;
    },
    prepareSign: async (
        documentId: string,
        versionId: string,
        keyId: string
    ): Promise<PrepareSignResponse> => {
        const response = await api.post<PrepareSignResponse>(
            `/documents/${documentId}/versions/${versionId}/prepare-sign`,
            { key_id: keyId }
        );
        return response.data;
    },

    submitSignature: async (data: SignatureSubmitRequest): Promise<SignatureDto> => {
        const response = await api.post<SignatureDto>('/signatures', data);
        return response.data;
    },

    getVersionSignature: async (
        documentId: string,
        versionId: string
    ): Promise<SignatureDto> => {
        const response = await api.get<SignatureDto>(
            `/documents/${documentId}/versions/${versionId}/signature`
        );
        return response.data;
    },
};
