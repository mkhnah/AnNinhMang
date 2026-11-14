# Phase 3 — Final remediation & release readiness

Ngày kiểm chứng: 14/11/2026. Kết luận: **READY cho phát triển Phase 4 theo các release gate tự động bên dưới**. Đây không phải chứng nhận production security hay bảo đảm browser compatibility toàn diện. Phase 4 chưa được triển khai trong đợt này.

## 1. Root cause, thay đổi và bằng chứng

| Task | Nguyên nhân | Thay đổi | Kiểm chứng |
|---|---|---|---|
| FIX-P3-01 | Vitest transpile được test nhưng không type-check; literal payload bị suy luận string, BufferSource không đúng kiểu, import thừa | Dùng `satisfies PopPayload`, bỏ import thừa; helper `toCryptoBytes` tạo view có ArrayBuffer sở hữu riêng; bỏ các cast kép ở luồng crypto; restore nhận unknown và kiểm tra runtime | tsc strict PASS; build PASS; test crypto thực tế qua Node WebCrypto PASS |
| FIX-P3-02 | Kiểm tra hết hạn trước verify nhưng UPDATE không kiểm tra lại thời gian | Conditional UPDATE chứa `julianday(expires_at) > julianday('now')`, user/purpose/algorithm/fingerprint/is_used; kiểm tra rowcount=1; INSERT cùng transaction; rollback/error response không trả SQL nội bộ | Regression hết hạn giữa read và UPDATE bị từ chối, không tạo key và không tiêu thụ challenge; concurrency chỉ một request thành công; unique conflict rollback rồi dùng lại challenge thành công |
| FIX-P3-03 | Promise.all làm lỗi server che dữ liệu local; refresh xóa operation error và suy luận chưa đăng ký từ danh sách rỗng | Hai nguồn độc lập qua allSettled, error riêng; metadata local ghi trạng thái đăng ký, hiển thị UNKNOWN nếu chưa xác nhận; giữ key khi đăng ký lỗi; retry dùng key đã lưu, challenge mới; reconcile response bị mất | Offline/remount vẫn thấy key; error còn sau refresh; reconnect/retry thành công với keypair cũ; không gọi keygen trong retry; server keys vẫn hiển thị nếu IndexedDB lỗi |
| FIX-P3-04 | Sort JSON tổng quát bị mô tả nhầm là RFC 8785, test cũ chỉ so chuỗi Python | Contract PoP v1 có đúng 7 trường, runtime validation ở JS/Python, schema/value ASCII giới hạn; dùng chung golden vectors; bridge chạy module TypeScript thực tế | Golden bytes JS=Python; Node ký → Python verify → HTTP đăng ký 201; Python ký → frontend verify; loại schema sai/extra field/Unicode/newline |
| FIX-P3-05 | Node bị coi là browser, RSS cuối bị gọi peak, chưa đo KDF mặc định; báo cáo có kết luận tuyệt đối | Viết lại hai benchmark và báo cáo; 3 mẫu tuần tự, PBKDF2 600000 vòng; phân biệt runtime và AES-only với tổng backup/restore; peak ghi Not measured | Đã chạy hai script trên ARM64/8GiB; JSON chứa số đo từng mẫu, mean/median, CPU và RSS before/end |

Không tắt strict mode, không dùng ts-ignore/ts-nocheck hoặc cast any để vượt lỗi BufferSource. Không tách test khỏi type-check để né lỗi. Typed-array view cũng tránh lỗi cross-realm ArrayBuffer giữa jsdom và Node WebCrypto.

### Chi tiết thời gian SQLite

SQLAlchemy SQLite DateTime lưu timestamp UTC không có offset. `julianday()` đọc cùng biểu diễn đó và dùng đồng hồ SQLite ngay trong câu UPDATE, thay vì thời điểm Python đã lấy trước verify/đợi writer lock. Đồng hồ SQLite có độ phân giải thực tế theo millisecond, không phải bằng chứng timestamp tin cậy cho chữ ký tài liệu. TTL challenge vẫn 5 phút. Không dùng SELECT FOR UPDATE.

### Trạng thái khóa local

- LOCAL_ONLY: có keypair lưu local; chưa xác nhận đăng ký qua luồng này.
- REGISTERED: đã có xác nhận server; khi offline hiển thị “xác nhận gần nhất”.
- REGISTRATION_FAILED: lần thử chưa thể xác nhận thành công; không chứng minh server chưa commit.
- REVOKED: server đã xác nhận thu hồi; khi offline có thể là trạng thái cache gần nhất.
- UNKNOWN: chưa biết trạng thái server, ví dụ restore từ backup khi offline. Không suy luận REVOKED/LOCAL_ONLY từ lỗi tải backend.

Trạng thái local phục vụ UI, không thay thế authorization/trạng thái ACTIVE phía backend. Retry kiểm tra danh sách server trước để nhận diện POST thành công nhưng mất response; nếu key chưa có, tạo challenge mới rồi ký bằng chính CryptoKey đã lưu. Không sinh keypair mới. Reload được kiểm tra bằng remount component và đọc lại fake IndexedDB; chưa phải test browser restart/power loss thật.

## 2. PoP v1 serialization contract

**Phase 3 sử dụng canonicalization dành riêng cho PoP schema, không phải implementation RFC 8785 đầy đủ. Phase 4 phải đánh giá riêng định dạng payload ký tài liệu.**

Đúng 7 trường, không trường bổ sung hoặc thiếu. Thứ tự byte JSON cố định:

```text
algorithm, challenge_id, challenge_nonce, fingerprint, purpose, schema_version, user_id
```

- algorithm: chính xác `RSA-PSS-3072`; ECDSA chưa được triển khai trong Phase 3.
- purpose: chính xác `REGISTER_KEY`.
- schema_version: số nguyên 1; không chấp nhận boolean, string hoặc float ngoài schema.
- challenge_id, user_id: ASCII `[A-Za-z0-9_-]`, dài 1–64; ID thực tế do server sinh là UUID.
- challenge_nonce: ASCII Base64URL alphabet, dài 8–128; nonce server thực tế là CSPRNG 32 bytes, Base64URL không padding.
- fingerprint: 64 hex lowercase, backend tính lại SHA-256 của SPKI DER.
- UTF-8 JSON, separators `,` và `:`, không khoảng trắng, BOM hoặc newline cuối. Các chuỗi bị giới hạn alphabet nên không có trường hợp escape/Unicode/number formatting tổng quát.

Golden vectors: `tests/fixtures/pop-v1.json`, gồm 2 payload hợp lệ + bytes UTF-8/Base64 mong đợi và 13 payload không hợp lệ. Frontend và pytest đọc chính file này. Bridge `tests/helpers/pop_webcrypto.cjs` bundle module TypeScript trong memory, dùng Node WebCrypto; chỉ xuất public key/payload/signature, không export/transmit private key.

PoP dùng RSA-PSS, SHA-256, MGF1-SHA256, saltLength=32. Test JS→Python verify chữ ký thật bằng cryptography rồi gửi public-only request qua authenticated TestClient tới POST /keys. Challenge của ca liên thông HTTP được seed trong DB thử nghiệm; issuance API có test riêng. Chiều Python→JS dùng key/signature giả lập và frontend verify thực tế. Không gọi đó là browser E2E.

## 3. Release gate và kết quả đã chạy

| Gate | Kết quả |
|---|---|
| Toàn bộ pytest Phase 1–3 | **134 passed**, 1 deprecation warning thư viện TestClient/httpx |
| Trong đó hồi quy Phase 1 / Phase 2 | **20 / 68 passed** |
| Trong đó Phase 3 | **46 passed**: 28 test hiện có + 18 test release |
| Toàn bộ Vitest | **38 passed**, 3 test files |
| Crypto WebCrypto/backup/restore/IndexedDB | **16 passed** |
| Offline/retry/Keys UI | **9 passed** |
| Documents UI hồi quy | **13 passed** |
| TypeScript strict type-check (bao gồm tests) | PASS |
| Production tsc + Vite build | PASS |
| Golden bytes JS ↔ Python, PoP signatures hai chiều | PASS |
| Expired-at-consumption / concurrency / rollback / unique conflict | PASS |
| Request đăng ký không chứa Private Key | PASS trong các luồng thử nghiệm: allowlist 4 trường public_key_pem, algorithm, challenge_id, pop_signature_b64; kiểm tra key đã lưu vẫn ký được sau retry |
| Alembic schema check | Không phát hiện upgrade operation mới; không cần migration cho đợt sửa này |
| Bảo toàn database thật | SHA-256 file DB trước/sau giống nhau; không chạy reset hoặc migration phá hủy |
| PDF người dùng | Không có PDF trong storage ở baseline đợt sửa này; không thể tuyên bố đã thử trên PDF thật. Hồi quy dùng PDF tổng hợp riêng |

Các lệnh đã chạy từ repository root:

```bash
venv/bin/pytest -q
npm test --prefix frontend -- --reporter=dot
frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit
npm run build --prefix frontend
DEBUG=false venv/bin/alembic check
node scripts/benchmark_webcrypto.js
venv/bin/python scripts/benchmark_phase3.py
```

Chưa chạy browser E2E/Safari/Chrome thực, kiểm thử trực quan trên điện thoại, browser IndexedDB quota/eviction thực, OS reboot/power loss hoặc kiểm tra network toàn diện trong browser. fake-indexeddb/Node WebCrypto không thay thế những kiểm thử đó. React Router có future-flag warnings; không tắt warning để làm sai lệch kết quả.

## 4. Benchmark thực tế

Hai runtime độc lập, 3 mẫu tuần tự mỗi thao tác, tài liệu/khóa tổng hợp. Chạy cuối riêng sau khi regression suite kết thúc để giảm tranh CPU; không kiểm soát mọi tiến trình nền của máy. Không stress test, không thống kê P95/SLA từ ba mẫu. Số đo Node không được suy diễn là hiệu năng Safari/Chrome.

| Runtime / stage | Mean ms | Median ms |
|---|---:|---:|
| Node / rsa3072_keygen | 293.6146 | 312.1253 |
| Node / spki_export_and_fingerprint | 0.2242 | 0.2147 |
| Node / pbkdf2_sha256_600000 | 121.8866 | 121.7530 |
| Node / backup_total_default_600000 | 119.6229 | 119.5715 |
| Node / restore_total_default_600000 | 128.8242 | 127.6553 |
| Python / rsa_pss_verify | 0.0579 | 0.0561 |
| Python / spki_parse | 0.3378 | 0.0056 |
| Python / pbkdf2_sha256_600000 | 61.0150 | 60.3220 |
| Python / aes256gcm_encrypt_pkcs8_only | 0.1722 | 0.0054 |
| Python / aes256gcm_decrypt_pkcs8_only | 0.0036 | 0.0035 |

- Node: Node v20.12.0 WebCrypto, darwin 23.5.0 arm64; RAM vật lý 8GiB. RSS trước/cuối: **35.83/41.64 MiB**; peak RSS: **Not measured**; CPU toàn phép đo: 1.9904s.
- Python: Python 3.13.9 cryptography/OpenSSL, macOS-14.5-arm64-arm-64bit-Mach-O; RAM vật lý 8GiB. RSS trước/cuối: **26.28/28.75 MiB**; peak RSS: **Not measured**; CPU toàn phép đo: 0.6422s.

Raw samples/method: [Node JSON](phase3-benchmark-node.json), [Python JSON](phase3-benchmark-python.json). Node keygen stage gồm export public/fingerprint; Node backup/restore gọi module ứng dụng thực tế và gồm KDF mặc định 600000 vòng. Python AES-only không bao gồm KDF. Không gọi mean này là giới hạn UX đảm bảo; không suy luận memory leak, GC, swap hoặc SSD từ RSS before/end. Browser key persistence latency chưa đo.

## 5. Dữ liệu nhạy cảm và giới hạn bảo mật

Private Key không nằm trong request đăng ký/challenge/list/revoke của luồng ứng dụng đã kiểm thử; backend nhận SPKI public key và PoP signature. Backup-enabled export PKCS#8 plaintext tạm trong JS memory, mã hóa AES-256-GCM rồi xuất JSON `.pem.enc`; ciphertext có authentication tag 128-bit nối cuối theo WebCrypto. AAD của format v1 là chuỗi domain/version/algorithm/fingerprint, các tham số còn lại được kiểm tra theo schema/giới hạn. Không coi mọi metadata là AAD tổng quát.

Mode A non-extractable không bảo đảm Secure Enclave, không chặn JavaScript độc hại cùng origin sử dụng key để ký. Mode B/restore giữ CryptoKey extractable để hỗ trợ backup: mã cùng origin có quyền phù hợp vẫn có thể export key. IndexedDB không phải hộp bảo vệ danh tính riêng cho từng tài khoản trước XSS; backend phải tiếp tục kiểm tra owner và ACTIVE cho mọi hành động Phase 4.

Xóa PKCS#8 typed-array buffer là best effort; chuỗi passphrase, JWK tạm và bản sao của JS engine/WebCrypto không thể được ứng dụng bảo đảm zeroization toàn diện. Không ghi key/passphrase vào URL/log/analytics. Việc password input và state được giải phóng không là bằng chứng xóa RAM vật lý.

Rủi ro/việc chưa kiểm chứng:

- Chưa browser E2E, network interception toàn browser, cross-browser IndexedDB/CryptoKey persistence, quota/eviction/OS reboot, accessibility/visual QA thực tế; Node/jsdom/fake-indexeddb chỉ là automated evidence hiện có.
- PoP chứng minh khả năng dùng Private Key trong context challenge/tài khoản, không là CA hoặc chứng thực danh tính pháp lý. Không chống được backend/frontend cùng origin bị chiếm quyền.
- Passphrase policy hiện là tối thiểu 8 ký tự; không bảo đảm chống brute-force offline nếu người dùng chọn yếu. PBKDF2 mặc định 600000 vòng không thay thế entropy passphrase.
- Limit 5 pending challenges/user không thay thế rate-limit/quota toàn dịch vụ. Chưa stress/multi-worker hoặc fuzz/DoS review toàn diện cho API JSON/PEM.
- Public keys và challenge history chưa có audit log bền vững của Phase 7. Retention/sharing và chính sách backup/quyền OS cần đánh giá riêng trước triển khai rộng.
- Hai cảnh báo moderate của dependency router được ghi nhận ở đợt Phase 2; đợt này không thực hiện lại network dependency audit hoặc nâng major router. Không coi audit cũ là kết quả audit mới.
- Revocation hiện cập nhật trạng thái backend; Phase 4 phải từ chối chữ ký mới với key không ACTIVE và Phase 5 phải tách mathematical validity khỏi thời điểm/revocation evidence. Chưa triển khai những giai đoạn đó.

## 6. Files của đợt final remediation

Sửa mã có sẵn:

- backend/app/services/key_service.py
- frontend/src/crypto/__tests__/crypto.test.ts
- frontend/src/crypto/canonicalJson.ts
- frontend/src/crypto/pop.ts
- frontend/src/crypto/spki.ts
- frontend/src/crypto/keyBackup.ts
- frontend/src/crypto/keyRestore.ts
- frontend/src/crypto/keyStorage.ts
- frontend/src/pages/Keys/KeyManagement.tsx
- tests/test_phase3_keys.py (đổi tên/mô tả test ASCII cũ, không gọi đó là RFC interoperability test)
- scripts/benchmark_webcrypto.js
- scripts/benchmark_phase3.py
- docs/phase3-report.md (thay báo cáo cũ bằng bằng chứng hiện tại)
- plan.md
- todo.md

Tạo mới:

- tests/fixtures/pop-v1.json
- tests/helpers/pop_webcrypto.cjs
- tests/test_phase3_release.py
- frontend/src/pages/Keys/KeyManagement.test.tsx
- docs/phase3-benchmark-node.json
- docs/phase3-benchmark-python.json

Các thay đổi Phase 3 khác đã có trong working tree trước đợt này được giữ nguyên. Không tự commit/push; không reset DB, xóa Private Key/backup/PDF hoặc thay cấu hình macOS. Không có migration mới trong final remediation. Checkpoint SHA-256 live DB chỉ lưu trong `data/tmp/` bị gitignore; không đưa nội dung DB/secret vào báo cáo.

## 7. Demo và Phase 4 readiness

1. Đăng nhập, mở `/keys`, tạo Mode A hoặc backup-enabled; xác nhận khóa local và public registration.
2. Với tài khoản thử nghiệm, cho backend offline rồi refresh: key local vẫn hiện, trạng thái server chưa xác nhận.
3. Kết nối lại và bấm “Thử đăng ký lại”/“Kiểm tra và đăng ký”: dùng keypair cũ; nếu lần POST trước đã thành công thì reconcile thay vì tạo trùng.
4. Restore backup hợp lệ; sai passphrase/tamper hoặc khóa 2048-bit bị từ chối. Kiểm thử tự động dùng dữ liệu tổng hợp, không thao tác private key thật của người dùng.
5. Dùng các lệnh regression ở mục 3 để tái lập bằng chứng; không dùng dữ liệu thật để test.

**READY cho phát triển Phase 4 theo release gate đã yêu cầu:** build/type-check/regressions/atomic expiry/local key resilience/PoP interoperability/report correction đều đạt. Đây là readiness để tiếp tục phát triển, không phải “fully production-ready”. Browser/manual/security work còn lại được liệt kê rõ ở mục 5. Đã dừng ở Phase 3; chưa thêm chức năng ký tài liệu, Blockchain hoặc API Phase 4.
