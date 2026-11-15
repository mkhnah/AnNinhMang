# Phase 5 — Security remediation và independent verification release audit

Ngày kiểm chứng: 15/11/2026. Phạm vi: sửa Phase 5; không triển khai Phase 6, ECDSA, PAdES hoặc blockchain. Không thay đổi private key management và signing transaction Phase 4.

**Trạng thái: READY cho phát triển Phase 6 theo các release gate tự động được liệt kê dưới đây.** Đây không phải chứng nhận production hoặc bảo đảm không còn lỗ hổng. Browser E2E thực tế và kiểm thử tải dài hạn chưa chạy. Một lần regression có parser rejection không ổn định được ghi rõ ở phần giới hạn, không che bằng cách nới budget.

## 1. Root cause và remediation

| Nhóm | Root cause | Sửa | Bằng chứng regression |
| --- | --- | --- | --- |
| FIX-P5-01 | Internal verify bỏ qua hash/canonical/binding của evidence; strict parser lỗi rồi fallback `json.loads` | Pipeline strict JSON → SignedManifest → JCS canonical byte equality → SHA-256 equality → version/key/signer/owner/fingerprint/profile/format binding → RSA verify → actual PDF hash. Export dùng cùng consistency gate. Evidence lỗi trả `evidence_consistency=INCONSISTENT`, `EVIDENCE_INCONSISTENT`, summary UNVERIFIABLE và không gán PoP/danh tính từ manifest lỗi | Wrong stored hash, duplicate keys, cross-version/key/signer, wrong format, noncanonical JSON, context/fingerprint sai đều không VERIFIED; valid path và signature tampering còn kiểm tra mật mã thật |
| FIX-P5-02 | Result response không gắn với snapshot/generation; đổi input khi request chạy làm response A gắn nhãn B | Freeze snapshot của File/package/text/mode lúc submit; generation + AbortController; invalidate khi đổi/chọn/xóa input/mode/reset và unmount; label result lấy từ snapshot; report download hủy/bỏ response khi result đổi hoặc unmount | PDF A→B, package A→B, B response trước A, unmount, abort, network error/retry, không export stale result |
| FIX-P5-03 | Body middleware chỉ bảo vệ documents; package read không giới hạn; rate sau multipart; handler async gọi blocking service | Middleware bảo vệ verify/upload và report, kiểm tra Content-Length và actual bytes cho stream/chunked; rate theo peer + bounded IP state và semaphore trước parse; bounded `read(MAX_PACKAGE_BYTES+1)`; endpoint sync chạy trong threadpool. Admission giữ permit đến khi worker thật sự kết thúc kể cả request bị hủy. Giữ nguyên parser budgets. Native start dùng `--no-proxy-headers` | Oversized declared/actual/chunked/spoofed-small length, valid no-Content-Length upload, rate before receive, forwarded-header spoof, bounded limiter state, job cap + health responsiveness, malformed multipart, oversized package/PDF, parser timeout, temp cleanup sau abort |
| FIX-P5-04 | Package version/format không bị khóa, tự điền default/coerce | Required integer 1 (không bool/float/string), required literal DETACHED_JCS_V1, strict manifest, no extras, canonical Base64 đúng 384 signature bytes/512 chars, SPKI PEM <=4096 bytes, optional public key, JSON <=512KiB và flat schema do Pydantic kiểm tra | API trả 422 cho unsupported/bool/float/missing version, missing/wrong format, bad Base64/length/extras; duplicate/malformed/nonfinite/surrogate JSON bị strict parser từ chối |
| FIX-P5-05 | Lookup fingerprint rồi thay key ID; suy PoP từ record không ràng buộc manifest | Lookup đúng signed key ID; kiểm tra ID + DB fingerprint + actual canonical SPKI fingerprint + RSA algorithm + owner tồn tại. Internal thêm signer/owner binding. Không thay key_id của manifest trong response. Thêm key_registry_binding MATCHED/UNREGISTERED/MISMATCH/UNKNOWN | Không tồn tại key ID nhưng attached key hợp lệ: crypto VALID, PoP UNVERIFIED; ID trỏ key khác: MISMATCH, không PoP và không summary VERIFIED; registry đúng mới PoP |
| FIX-P5-06 | Chỉ kiểm tra RSA >=3072 và không kiểm exponent | SPKI DER canonical, RSA đúng 3072 bits/e65537; SHA-256/MGF1-SHA256/salt32; không đổi algorithm identifier | RSA3072/e65537 accept; RSA2048,4096,e3 và ECDSA trong RSA profile bị từ chối; malformed/unsupported SPKI không nâng trust |
| FIX-P5-07 | Missing bytes bị coi hash mismatch; missing key không biểu diễn được; declared timestamp vào server_timestamp | Missing/unreadable file: integrity UNKNOWN + DOCUMENT_UNAVAILABLE, không VERIFIED. Optional key: UNVERIFIABLE/UNKNOWN khi không có DB binding. Tách declared_timestamp/server_recorded_at/verification_time/trusted_timestamp; alias server_timestamp chỉ chứa server-recorded UTC, không bao giờ chứa declared time. Timestamp level UNKNOWN khi không có evidence. revoked_at !=null cũng được coi revoked | Missing/unreadable file, missing key, registry absent, revoke, declared/server UTC timestamp, no TSA và no-DB verifier |
| FIX-P5-08 | Report API đóng gói bất kỳ result/trust field client gửi | POST report chỉ nhận receipt_id; server lưu immutable JSON snapshot trong bounded receipt store, TTL 600s, random 256-bit capability. Internal report kiểm tra cùng user và current document/version ownership + CSRF. Public receipt theo possession. Export bỏ receipt capability khỏi report. Disclaimer nói rõ chưa ký số/không independently tamper-evident | Fake VERIFIED/CA/TSA/timestamp/extra field bị 422; invalid/expired/cross-user/lost-ownership receipt 404; cookie request thiếu CSRF 403; report đúng snapshot và không chứa receipt token |

Các failing regression đã được chạy trước sửa: backend tái hiện các lỗi false VERIFIED/schema/trust và UI tái hiện stale response sau khi dùng đúng label của input. Không thay đổi thuật toán hoặc tắt kiểm tra để làm test đạt.

## 2. API contract và trust boundary

- `POST /api/v1/verify/upload`: anonymous multipart PDF + đúng một trong package/package_file/package_json. Giới hạn package theo bytes UTF-8; tối đa 20MiB PDF theo cấu hình Phase 2. Không cần private key. File không lưu vào document storage.
- `GET /api/v1/documents/{document_id}/versions/{version_id}/verify`: authenticated owner, ràng buộc document/version trước khi đọc evidence. Không dùng state SIGNED làm bằng chứng thay cho RSA verification.
- `GET .../signature-package`: owner-only; không export evidence có schema/canonical/hash/binding/profile không nhất quán. Manifest export giữ cùng canonical bytes đã ký. `created_at` trong package chỉ là metadata không đáng tin cậy về thời điểm ký.
- Verify response bổ sung `evidence_consistency`, `warning_codes`, `key_registry_binding`, `declared_timestamp`, `server_recorded_at`, `verification_receipt`, `receipt_expires_at`. Các chiều crypto/integrity/PoP/trust/revocation/time vẫn độc lập.
- `POST /api/v1/verify/report`: chỉ chấp nhận `{"receipt_id":"<verification_receipt>"}`. API cũ nhận nguyên VerificationResultResponse được loại bỏ có chủ đích. Frontend đã chuyển sang hợp đồng mới.
- Receipt TTL 10 phút, tối đa 1024 kết quả/process. Cleanup expiry khi issue; entry hết hạn bị từ chối khi lookup; capacity đầy thì entry cũ bị evict. Restart/eviction/expiry cần verify lại, không fallback tin result từ client. Receipt không lưu PDF/manifest/private key/token đăng nhập; chỉ lưu result snapshot phục vụ export.
- Public receipt là bearer capability: không log/share ID. Báo cáo tải xuống loại bỏ receipt và TTL transport metadata. Internal receipt còn cần đúng tài khoản và ownership hiện tại.
- Receipt và limiter là **single-process storage**, không phải distributed quota. Với multi-worker cần shared store hoặc routing/forwarding policy được thiết kế riêng; không giả định cache/limit tự đồng bộ.
- PoP chỉ là registry evidence rằng một tài khoản đã chứng minh khả năng dùng key tại đăng ký, không xác minh danh tính pháp lý. Chỉ SELF_REGISTERED hoặc UNKNOWN, không tự gán TRUSTED_CA. Không có TSA; trusted_timestamp luôn null.
- Report là snapshot tại verification_time, không bảo đảm key/document vẫn giữ trạng thái đó sau này. generated_at không phải trusted timestamp và report chưa được ký.

## 3. Resource controls

Cấu hình mặc định (`backend/app/core/config.py`, có thể chỉnh trong `.env`):

| Control | Mặc định |
| --- | ---: |
| MAX_UPLOAD_BYTES | 20MiB |
| VERIFY_MAX_PACKAGE_BYTES | 512KiB |
| VERIFY_MAX_BODY_BYTES | 21MiB + 64KiB tổng multipart |
| VERIFY_CONCURRENCY | 2 uploads/jobs, không có wait queue vô hạn |
| VERIFY_RATE_PER_MINUTE | 60/peer/60 giây |
| VERIFY_MAX_TRACKED_IPS | 1024; state đầy trả 503 thay vì phát triển vô hạn |
| Report body cap | 16KiB |
| PDF parser | Giữ timeout/CPU/RSS/object/depth limits của Phase 2 |

Rate vượt trả 429/Retry-After; slots đầy trả 503/Retry-After. Không parse package JSON nếu quá giới hạn; không đọc toàn bộ file package không giới hạn. HTTP body thật vẫn bị đếm khi thiếu hoặc giả Content-Length. Temp multipart được framework đóng khi parser lỗi/abort và kết thúc request; fallback BinaryIO dùng TemporaryFile và copy 64KiB có cap, cleanup trong finally.

Blocking worker không chạy trên event loop; health request vẫn trả 200 khi các verification jobs test bị giữ trong threadpool. Khi request đóng giữa lúc worker chạy, Admission không trả permit sớm trước finish_job. Native script bind loopback và tắt Uvicorn proxy-header rewriting để IP limit không bị spoof bằng X-Forwarded-For. Nếu triển khai sau trusted reverse proxy phải cấu hình lại trust boundary; không áp dụng nguyên cấu hình này ra Internet mà không đánh giá.

`verification_events` có retention target 30 ngày, purge khi có verify request thành công (instance không hoạt động có thể giữ lâu hơn đến lần cleanup tiếp theo); không lưu PDF, raw manifest, IP đầy đủ hoặc receipt. Có thể cần indexed/batched cleanup khi lịch sử lớn; hiện không xây dashboard Phase 7.

## 4. Test evidence và release gates

| Lệnh/gate | Kết quả |
| --- | --- |
| `venv/bin/pytest -q --tb=short` | **276 passed** trên lượt release cuối, gồm regression Phase 1–4 |
| `npm test --prefix frontend -- --run` | **86 passed**, 8 files |
| `frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit` | PASS, strict giữ nguyên |
| `npm run build --prefix frontend` | PASS; còn warning chunk >500kB |
| `DEBUG=false venv/bin/alembic check` | PASS, không có schema drift |
| Internal consistency / IDOR / CSRF | PASS; evidence fault simulation chỉ trên DB fixture; signature guard thật không bị sửa |
| Public body/rate/concurrency/cleanup | PASS; có multipart thực, raw ASGI/chunked và parser timeout fixture |
| Key ID/fingerprint/profile/classification | PASS |
| Receipt authenticity boundary | PASS; report chỉ từ server snapshot, không nhận client trust metadata |
| WebCrypto → package → independent verification | PASS, module TS thực tế, không Python signing thay client |
| DB/PDF/backup preservation | PASS; row counts/FK/integrity và checksum captured PDF/backups giữ nguyên |

Test mới:

- `tests/test_phase5_remediation.py`: consistency/schema/key/RSA/classification/receipt/UTC/ownership/CSRF.
- `tests/test_phase5_resources.py`: early cap/rate, spoofed Content-Length/forwarding, concurrency/health, parser timeout, malformed body, cleanup after abort, permit lifetime kể cả HTTP request bị cancel khi worker đang chạy, valid streaming request không Content-Length.
- `tests/test_phase5_interop.py`: Node WebCrypto keypair non-extractable + PoP qua HTTP → backend prepare → actual frontend JCS/signer → Python verify/persistence → owner export → anonymous independent HTTP verify → cùng API với DB dependency là None, không thể query DB gốc. No-DB result crypto VALID/integrity UNCHANGED nhưng PoP UNVERIFIED/revocation UNKNOWN/trust SELF_REGISTERED, không TSA. Report receipt cũng export được ở chế độ này.
- `frontend/src/pages/Verify/__tests__/Lifecycle.test.tsx`: snapshot, stale PDF/package, response ordering, abort/unmount/error/retry.
- Mở rộng `Verify.test.tsx`: receipt-based export, cancel stale report download, exact hash character diff, independent copy controls/accessibility labels, UNKNOWN không bị mô tả như CA hoặc hash mismatch.

Các test cũ được cập nhật fixture format đúng `DETACHED_JCS_V1` và report request đúng receipt contract; không nới lỏng assertions về validity. Bộ Phase 4 WebCrypto/JCS/replay/concurrency vẫn chạy cùng full regression.

**Lịch sử run và giới hạn:** một lượt chạy backend đồng thời với frontend có 2 test Phase 2 upload hợp lệ nhận parser rejection (HTTP 400) và test helper thiếu version_id. Hai test chạy riêng đạt; lượt full có diagnostics rồi lượt full worker nguyên bản chạy tuần tự đạt mà không đổi parser source/budget. Chưa xác định nguyên nhân của lần rejection không ổn định đó. Đây là residual về false rejection/ổn định tải, không chứng minh parser vượt qua file độc hại. Cần điều tra dưới tải dài hạn trước production; không tuyên bố mọi workload hợp lệ luôn được nhận. Diagnostics chỉ dùng worker copy/test fixtures, không sửa worker application.

Browser E2E Chrome/Safari/Firefox thực chưa chạy. jsdom component tests và Node WebCrypto interoperability không thay thế IndexedDB/cookie/worker/browser-download E2E. Có deprecation warning Starlette/httpx và status-code name từ các test Phase 4, không che warning thành kết quả kiểm thử thành công tuyệt đối.

## 5. Benchmark đã đo

Chạy `venv/bin/python scripts/benchmark_phase5.py`; dữ liệu gốc [`phase5-benchmark.json`](phase5-benchmark.json), Python 3.13.9/Darwin arm64. Mỗi kích thước chạy child process mới, 5 mẫu tuần tự, PDF blank-page tổng hợp với content stream padding. App, multipart, parser subprocess thật và SQLite event commit/receipt issuance đều chạy; database chỉ nằm trong TemporaryDirectory.

| PDF mục tiêu | Bytes thực | Median API multipart tổng | Median parser | Sampled parent peak RSS | OS process-lifetime peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1MiB | 1,048,502 | 84.368ms | 76.292ms | 159.67MiB | 166.98MiB |
| 5MiB | 5,242,806 | 97.885ms | 85.160ms | 170.12MiB | 213.88MiB |
| 10MiB | 10,485,688 | 95.911ms | 77.367ms | 180.73MiB | 244.41MiB |
| 20MiB | 20,971,448 | 124.163ms | 89.353ms | 200.19MiB | 324.09MiB |

JSON còn có body-guard microbenchmark, SHA-256, JCS, SPKI/profile, RSA-PSS verify, SQLite event flush/commit, tổng CPU parent và child, và sampled process-tree RSS. Body-guard helper timing được ghi riêng, không gọi là end-to-end. Parent/child CPU là tổng 5 mẫu: 0.0761/0.3464s, 0.0974/0.3563s, 0.1495/0.3622s, 0.1733/0.3931s cho 1/5/10/20MiB.

Đây là FastAPI TestClient multipart end-to-end trong process, không phải browser/network/TCP/TLS benchmark. Sampled RSS chu kỳ 5ms có thể bỏ lỡ đỉnh ngắn; process-tree sum có thể đếm shared pages nhiều lần. `ru_maxrss` trên macOS được đổi từ bytes, là peak suốt lifetime có cả setup/fixture generation; **không dùng RSS cuối tiến trình làm peak**. Không suy ra số đo cho PDF scan/phức tạp/độc hại, tải đồng thời dài hạn hoặc bộ nhớ browser.

## 6. Data safety và migrations

- **Không tạo migration mới trong remediation này.** Receipt là bounded ephemeral storage, không đổi schema. Head giữ `a6f000000006` của Phase 5 người dùng đã triển khai; không sửa lịch sử a4/a5/a6, không downgrade.
- Không chạy security test trên DB/storage thật. Pytest và benchmark tạo DB/PDF riêng; simulation gỡ trigger hoặc sửa evidence chỉ ở fixture database.
- Baseline chụp path DB thực, row counts và checksum của backup/PDF vào `data/tmp/phase5-remediation-preservation.json` (ignored, không in nội dung DB). Sau sửa: counts giữ nguyên, `PRAGMA integrity_check=ok`, FK check sạch, checksums giữ nguyên.
- Backup `docsign.db.bak_pre_phase4` và `docsign.db.bak_pre_phase5` không di chuyển/xóa/sửa, đã được gitignore; không stage/commit/push.
- Không thay đổi signature immutability trigger hay signing engine Phase 4. Không xóa/reset dữ liệu hoặc đổi cấu hình macOS.

## 7. Files remediation

Backend sửa: `backend/app/services/verification_service.py`, `backend/app/schemas/verify.py`, `backend/app/api/v1/verify.py`, `backend/app/core/config.py`, `backend/app/core/upload_limit.py`.

Backend mới: `backend/app/core/verification_limits.py`, `backend/app/services/verification_receipts.py`.

Frontend sửa: `frontend/src/pages/Verify/IndependentVerify.tsx`, `frontend/src/components/Verification/VerificationResultPanel.tsx`, `frontend/src/api/verify.ts`, `frontend/src/types/verify.ts`, `frontend/src/pages/Verify/__tests__/Verify.test.tsx`; thêm `Lifecycle.test.tsx` cùng thư mục.

Tests mới: `tests/test_phase5_remediation.py`, `tests/test_phase5_resources.py`, `tests/test_phase5_interop.py`. Tests cũ sửa: `tests/test_phase5_verification.py` (strict format/receipt contract và assertions).

Khác: `scripts/dev_start.sh`, `scripts/benchmark_phase5.py`, `docs/phase5-benchmark.json`, `docs/phase5-report.md`, `plan.md`, `todo.md`, `README.md`. Các file modified/untracked từ trước remediation được giữ lại; danh sách Git working tree còn bao gồm mã Phase 5 ban đầu của người dùng.

## 8. Residual risks và readiness

- Receipt/limiter là per-process, restart/eviction cần reverify; public receipt là capability. Chưa có shared store, durable report provenance, report signing hoặc TSA/CA validation.
- XSS/browser compromise, server/DB/filesystem admin compromise và chỉnh sửa evidence sau khi gỡ trigger nằm ngoài bảo đảm của các gate này. Fingerprint/PoP không chứng minh danh tính pháp lý.
- Resource cap không chứng minh miễn nhiễm mọi parser/decompression attack. Cần ingress/read deadlines, reverse-proxy policy, per-user fairness và bài tải dài hạn nếu triển khai ngoài native loopback.
- Browser E2E, PDF phức tạp/scanned và false-rejection dưới tải cần kiểm chứng thêm. Warning bundle size và các dependency/runtime follow-up từ Phase 4 vẫn còn; lần remediation này không làm dependency audit mới hay major upgrade router/runtime.
- Report snapshot không có hiệu lực chống sửa đổi độc lập; trạng thái thu hồi có thể đổi sau verification_time. Muốn kết quả mới phải verify lại.
- ECDSA vẫn DEFERRED. Không xây Phase 6/QR, blockchain hoặc PAdES.

Tám FIX-P5 và ba nhóm test bắt buộc đã có bằng chứng tự động; xem todo.md. Có thể tiếp tục **phát triển Phase 6 khi người dùng yêu cầu**. Không tự triển khai Phase 6 và không gọi đây là production-ready.
