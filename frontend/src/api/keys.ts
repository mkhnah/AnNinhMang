import api from './client';
import { PublicKeyDto, ChallengeResponseDto, KeyRegisterRequestDto } from '../types/key';

export const keysApi = {
    requestChallenge: async (algorithm: string = 'RSA-PSS-3072', fingerprint?: string): Promise<ChallengeResponseDto> => {
        const payload: { algorithm: string; fingerprint?: string; purpose: string } = {
            algorithm,
            purpose: 'REGISTER_KEY',
        };
        if (fingerprint) {
            payload.fingerprint = fingerprint;
        }
        const response = await api.post<ChallengeResponseDto>('/keys/challenge', payload);
        return response.data;
    },

    registerKey: async (data: KeyRegisterRequestDto): Promise<PublicKeyDto> => {
        const response = await api.post<PublicKeyDto>('/keys', data);
        return response.data;
    },

    listMyKeys: async (): Promise<PublicKeyDto[]> => {
        const response = await api.get<PublicKeyDto[]>('/keys/my');
        return response.data;
    },

    revokeKey: async (keyId: string): Promise<PublicKeyDto> => {
        const response = await api.post<PublicKeyDto>(`/keys/${keyId}/revoke`);
        return response.data;
    },
};
