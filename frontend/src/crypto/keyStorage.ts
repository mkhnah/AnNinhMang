/**
 * Client-Side IndexedDB Key Storage
 * Persists CryptoKey objects directly within the browser's structured clone storage.
 * Only non-extractable or extractable CryptoKey references are stored (never plaintext PEM/raw bytes).
 */

export interface StoredKeyRecord {
    fingerprint: string;
    userId: string;
    algorithm: "RSA-PSS-3072";
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    spkiPem: string;
    extractable: boolean;
    createdAt: string;
    registrationState?: 'LOCAL_ONLY' | 'REGISTERED' | 'REGISTRATION_FAILED' | 'REVOKED';
}

const DB_NAME = "DocSignKeystore";
const DB_VERSION = 1;
const STORE_NAME = "keys";

function openKeystoreDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const idb = typeof window !== "undefined" ? window.indexedDB : globalThis.indexedDB;
        if (!idb) {
            return reject(new Error("IndexedDB không được hỗ trợ trong môi trường này."));
        }

        const request = idb.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (event) => {
            const db = (event.target as IDBOpenDBRequest).result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                const store = db.createObjectStore(STORE_NAME, { keyPath: "fingerprint" });
                store.createIndex("by_user", "userId", { unique: false });
            }
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("Không thể mở cơ sở dữ liệu IndexedDB."));
    });
}

export async function saveKeyToKeystore(record: StoredKeyRecord): Promise<void> {
    const db = await openKeystoreDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        const store = tx.objectStore(STORE_NAME);

        tx.oncomplete = () => {
            db.close();
            resolve();
        };

        tx.onerror = () => {
            db.close();
            const err = tx.error;
            if (err && err.name === "QuotaExceededError") {
                reject(new Error("Dung lượng bộ nhớ lưu trữ trình duyệt (IndexedDB) đã đầy. Vui lòng giải phóng dung lượng đĩa."));
            } else {
                reject(err || new Error("Lỗi khi lưu khóa vào IndexedDB."));
            }
        };

        tx.onabort = () => {
            db.close();
            reject(tx.error || new Error("Giao dịch lưu khóa vào IndexedDB đã bị hủy (Transaction aborted)."));
        };

        store.put(record);
    });
}

export async function getKeyFromKeystore(fingerprint: string): Promise<StoredKeyRecord | null> {
    const db = await openKeystoreDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readonly");
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(fingerprint.toLowerCase());

        tx.onerror = () => reject(tx.error || new Error("Lỗi khi đọc khóa từ IndexedDB."));
        tx.onabort = () => reject(tx.error || new Error("Giao dịch đọc khóa bị hủy."));

        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}

export async function listKeysForUser(userId: string): Promise<StoredKeyRecord[]> {
    const db = await openKeystoreDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readonly");
        const store = tx.objectStore(STORE_NAME);
        const index = store.index("by_user");
        const req = index.getAll(userId);

        tx.onerror = () => reject(tx.error || new Error("Lỗi khi liệt kê danh sách khóa từ IndexedDB."));
        tx.onabort = () => reject(tx.error || new Error("Giao dịch liệt kê khóa bị hủy."));

        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
    });
}

export async function removeKeyFromKeystore(fingerprint: string): Promise<void> {
    const db = await openKeystoreDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        const store = tx.objectStore(STORE_NAME);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("Lỗi khi xóa khóa khỏi IndexedDB."));
        tx.onabort = () => reject(tx.error || new Error("Giao dịch xóa khóa bị hủy."));

        store.delete(fingerprint.toLowerCase());
    });
}
