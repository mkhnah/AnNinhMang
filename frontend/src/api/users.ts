import api from './client';

export interface UserLookupItem {
    id: string;
    full_name: string;
    email: string;
    status: 'ACTIVE' | 'LOCKED' | 'DISABLED';
}

export interface UserLookupPage {
    items: UserLookupItem[];
    total: number;
    limit: number;
    offset: number;
}

export const usersApi = {
    search: async (query: string, offset = 0, signal?: AbortSignal): Promise<UserLookupPage> =>
        (await api.get<UserLookupPage>('/users/search', {params: {q: query, offset, limit: 20}, signal})).data,
};
