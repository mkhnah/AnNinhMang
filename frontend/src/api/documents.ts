import api from './client';
export interface Document { id: string; title: string; visibility: string; created_at: string; updated_at: string }
export interface Version { id: string; document_id: string; version_no: number; original_filename: string; file_sha256: string; file_size_bytes: number; state: 'DRAFT' | 'READY_TO_SIGN' | 'SIGNED'; created_at: string; locked_at: string | null }
export const documentsApi = {
  limits: async () => (await api.get<{ max_upload_bytes: number }>('/documents/limits')).data,
  list: async (offset = 0) => (await api.get<{ items: Document[]; total: number }>('/documents', { params: { offset, limit: 20 } })).data,
  detail: async (id: string) => (await api.get<Document>(`/documents/${id}`)).data,
  versions: async (id: string, offset = 0) => (await api.get<Version[]>(`/documents/${id}/versions`, { params: { offset, limit: 100 } })).data,
  upload: async (file: File, progress: (n: number) => void, id?: string) => {
    const form = new FormData(); form.append('file', file);
    return (await api.post<Version>(id ? `/documents/${id}/versions` : '/documents', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: event => progress(Math.round((event.loaded / (event.total || file.size)) * 100)),
    })).data;
  },
  ready: async (id: string, version: string) => api.post(`/documents/${id}/versions/${version}/ready`),
  download: async (id: string, version: Version) => {
    const response = await api.get(`/documents/${id}/versions/${version.id}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(response.data);
    const link = document.createElement('a'); link.href = url; link.download = `document-v${version.version_no}.pdf`;
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};
