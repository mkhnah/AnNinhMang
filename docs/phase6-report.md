# Phase 6 — Final security remediation & release stability audit

Ngày 15/11/2026, macOS Apple Silicon ARM64, Python venv/FastAPI/SQLite/React/WebCrypto.

**READY cho phát triển Phase 7 theo các release gate tự động ở trạng thái source cuối: 319 backend tests, 115 frontend tests, strict tsc/build/Alembic PASS.** Không triển khai Phase 7. Đây không phải production release, chứng nhận bảo mật hoặc khẳng định parser đã ổn định tuyệt đối.

**Giới hạn quan trọng:** nguyên nhân cụ thể của lần PDF worker -24 trước remediation vẫn chưa xác định. Đã xác nhận đó là SIGXCPU, thêm diagnostics và kiểm chứng limit, chạy các nhóm test cùng bốn full runs giới hạn đều đạt; không tuyên bố đã sửa căn nguyên false rejection. Browser/camera/PDF thật vẫn NOT TESTED.

## 1. Root cause và thay đổi

| Nhóm | Root cause | Sửa và bằng chứng |
| --- | --- | --- |
| Final issuance race | Key ACTIVE được lấy trước commit; final code chỉ SELECT version state, không serialize với revoke | Hash/RSA/evidence check trước writer lock; bắt buộc MATCHED registry + VERIFIED_POP. End read transaction, BEGIN IMMEDIATE, conditional INSERT SELECT kiểm tra owner/document/version/SIGNED/signature ID/key/signer/hash/PublicKey owner/ACTIVE/revoked_at NULL; commit nguyên tử. Revoke đã commit trước final gate →422, không ShareToken. Issuance commit trước revoke →201 hợp lệ và public verify sau revoke →REVOKED_KEY. |
| UI UNKNOWN | Boolean else gộp UNKNOWN/UNVERIFIABLE thành TAMPERED/REVOKED/INVALID | Explicit enum mapping, evidence CONSISTENT/INCONSISTENT/NOT_APPLICABLE theo schema thực tế, nhãn “Thời điểm ký khai báo”, SELF_REGISTERED/không CA/TSA. Overall green yêu cầu VALID/UNCHANGED/CONSISTENT/ACTIVE/summary VERIFIED. Tests còn thử summary VERIFIED mâu thuẫn dimensions để tránh false green. |
| Pagination | UI chỉ lấy default20 | SharesPanel gọi limit20/offset, append và deduplicate ID, hasMore theo raw page length; API array không có exact total nên hiển thị “tổng số chưa xác định”. Có load-more, error/retry, reload, revoke giữ pages, AbortController/generation và component key theo document để bỏ stale results. Tests 0/1/20/21/50 records, page2 retry/duplicate/revoke và switch document. |
| Parser false rejection | SIGXCPU đã quan sát, căn nguyên sự kiện cũ chưa xác định | Không tăng budget. Worker ghi bounded JSON numeric/stage diagnostics, signal handler báo signal/CPU trước khi giữ nguyên default termination; parent log safe fields, không log PDF/raw worker output. Đã kiểm tra CPU/RSS/wall/cleanup/order/inherited limits và chạy bounded regression. Chi tiết ở mục3. |
| Benchmark/report | Có p95 không có raw data, RSS delta bị suy thành no-leak, TestClient bị coi là camera/network latency | Script mới giữ mọi samples_ms, mean/median/nearest-rank p95/max; 2-way concurrency8 requests, CPU parent/child, RSS before/after/delta/sampled peak/OS lifetime peak. Giới hạn được tách rõ; không có no-leak/camera latency claim. |
| LAN guide | HTTP LAN signer không có secure context; mở cả private backend ra LAN | Signer chỉ dùng localhost:5173. Public-only entry point phục vụ built SPA/assets/public QR GET, private APIs/docs404. LOCAL_DEMO loopback mặc định; LAN_DEMO phải bật và chọn host thật. Access log tắt, proxy headers tắt. Không chạy LAN trong remediation. |

Không có writer lock trong lúc PDF hash/RSA verification. Verification Engine vẫn ghi event ngắn sau computation; final issuance transaction không dựa vào ORM cache. SQLite writer serialization không bảo vệ khỏi filesystem admin hoặc tiến trình khác sửa PDF trực tiếp; việc hash đã hoàn thành là snapshot tại thời điểm verification.

## 2. Tests mới và release evidence

Regression race được viết và chạy FAIL trước sửa: POST shares vẫn201 sau revoke commit. Regression UI có 8 failing cases trước mapping; cả hai log nằm trong data/tmp (ignored). Không thay validation để vượt test.

| Gate / lệnh | Kết quả thực tế |
| --- | --- |
| `venv/bin/pytest -q --tb=short` lượt release cuối | **319 passed**, 4 warnings,80.79s, gồm Phase1–6 |
| Full runs trước đó trong cùng remediation | **310 passed**/77.31s; sau thêm tests **314 passed**/73.30s rồi **318 passed**/76.78s; không dùng chúng thay thế lượt319 cuối |
| `venv/bin/pytest -q tests/phase2 --tb=short` | **68 passed**,6.30s |
| Nhóm PDF + Phase5 verification + race regression trong điều tra | **63 passed**,9.64s |
| Test nonce từng lỗi, chạy riêng | **1 passed**,0.30s; full release cuối cũng chạy test này |
| Atomic/race/interop group | **6 passed**,3.21s: 5 final-issuance tests và real WebCrypto integration |
| Additional security | **4 passed**: ADMIN ownership, anonymous/raw share cannot download/package, slot503+headers, access-log redaction |
| Real CPU runaway worker | **1 passed**: synthetic worker copy hit SIGXCPU với CPU budget1, structured diagnostics và no remaining parser PID |
| Public demo boundary | **1 passed**: public route hoạt động, private document/shares/auth/docs404 |
| `npm test --prefix frontend -- --run` | **115 passed**,12 files,17.76s |
| Strict TypeScript và `npm run build --prefix frontend` | **PASS**; main JS787.81kB, còn chunk warning >500kB |
| `DEBUG=false venv/bin/alembic check` | **PASS**, no schema drift |
| Data preservation | **PASS**: 11 table counts và checksums các PDF/backups chụp đầu remediation không đổi; integrity ok, FK sạch; head a7f000000007 |

Logs xác minh trong data/tmp: p6-full-release.log, p6-frontend-release.log, p6-build-release.log, p6-alembic-final.log, p6-phase2-final.log, p6-parser-diagnostic.log, p6-atomic-interop.log, p6-cpu-security.log. Chúng không được commit và không chứa dữ liệu người dùng thật.

Tests backend mới:

- tests/phase6/test_final_issuance.py: hai Session + Events/Barrier thực; revoke-before-final-gate; RESERVED writer lock chặn revoke xen vào INSERT; issue-before-revoke; rollback unique-token collision không orphan; concurrent revoke idempotency; stale ShareToken identity sau revoke khi public request đang chạy.
- tests/phase6/test_parser_diagnostics.py: CPU bound parser fixture bị dừng bởi limit thật và có signal diagnostics, không nới budget.
- tests/phase6/test_final_security.py: ADMIN/no ownership, bearer share không thành JWT/download/package, resource slot503, log filter.
- tests/phase6/test_public_demo_boundary.py: public-only app không mount private APIs.

Frontend: mở rộng PublicShare.test.tsx (mapping/evidence/lifecycle); SharesPanel.test.tsx (8 paging tests); QR PNG test assert data URL, download filename và anchor click với canvas mock. Mock PNG không phải ảnh thật/camera proof. Documents tests mock share API đúng scope để tránh network ngoài ý muốn.

Real interop test dùng Node bridge chạy module TS/JCS/WebCrypto thật → PoP → PDF upload/prepare/sign → backend signature persistence → share creation → anonymous public verify → owner revoke → anonymous404. Python signing chỉ dùng fixture của các unit/security tests và benchmark, không thay real interop.

Legacy test17/18 trong test_shares.py vốn chạy revoke tuần tự; không gọi chúng là concurrent proof. Bằng chứng interleaving thực đến từ test_final_issuance.py. Các API IDOR/CSRF/expiry/revocation/public allowlist Phase6 cũ cùng regression Phase1–5 nằm trong full319.

## 3. PDF worker -24 và budgets

Lần review trước full run **306 passed,1 failed**: nonce test chờ200 nhưng nhận400, worker rejected=False/returncode=-24/output rỗng; chạy riêng lại đạt. Không xóa lịch sử lỗi này.

Trên macOS, Python signal.Signals(24) là SIGXCPU. [Apple setrlimit documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html) mô tả SIGXCPU khi vượt soft CPU limit. Điều đó xác định loại termination, **không chứng minh** PDF hợp lệ thật sự tiêu thụ vượt CPU budget hoặc xác định vì sao chỉ xuất hiện ở full run.

Đã kiểm tra code Popen/wait/kill/reap/finally/stream seek, bounded semaphore2, timeout/RSS polling, fixture rollback và DB/storage riêng, cpu limits của worker. Thí nghiệm tối thiểu giới hạn40 child processes sau parent dùng khoảng3.2CPU seconds không tái hiện lỗi; không kết luận inherited CPU accounting là căn nguyên. Trong bốn full reruns của remediation không quan sát lại false rejection. Test cố ý CPU runaway vẫn bị SIGXCPU và cleanup đúng; wall/RSS/object/depth/security tests cũng đạt. Không retry parser tự động để che rejection, không chấp nhận worker lỗi thành valid PDF.

Instrumentation parent chỉ log signal name/code, safe stage, sampled CPU/RSS, worker CPU, wall, input size, PID và budgets. Worker JSON ≤4096 bytes ở protocol gate; không ghi PDF, path, exception message hoặc raw stdout vào application log. SIGXCPU handler ghi numeric diagnostic rồi trả về default signal termination. Early termination trước worker handler vẫn có parent samples; không bảo đảm mọi kernel event đều có đầy đủ CPU/stage.

**Cấu hình giữ nguyên baseline trước final remediation:** parent wall10s, worker CPU soft6s/hard7s, alarm7s, RSS256MiB/worker, max2 parser/process; object50,000/depth64. Không tăng thêm giới hạn để làm test đạt. .env.example/docs/todo đã đồng bộ; Phase2 report giữ số đo lịch sử5s/3s và có chú thích cấu hình hiện tại. Giữ10/6 để tránh thay đổi đồng thời chính sách baseline trong lúc chẩn đoán, không coi đó là fix cho lỗi cũ. So với Phase2, ngân sách CPU và thời gian chiếm tài nguyên lớn hơn; app overhead/OS scheduling không nằm trong phép cộng256×2MiB.

**Residual:** căn nguyên lần SIGXCPU cũ vẫn chưa xác định. Nếu tái xuất hiện, thu diagnostics mới và điều tra trước deployment; không tuyên bố parser stability solved hoặc chịu mọi tải/PDF phức tạp.

## 4. Benchmark đã chạy, có raw samples

Nguồn dữ liệu: [phase6-benchmark.json](phase6-benchmark.json), sinh bởi `DEBUG=false venv/bin/python scripts/benchmark_phase6.py`. Python3.13.9/Darwin arm64. PDF synthetic blank page **431 bytes**; không suy số đo cho PDF20MiB, scan, malformed hoặc long-running load.

Đơn vị bảng: milliseconds; p95 nearest rank. Raw samples_ms có trong JSON cho từng nhóm.

| Nhóm | N | Mean | Median | P95 | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| Token generation | 1000 | 0.0007 | 0.0007 | 0.0009 | 0.0087 |
| SHA-256 token | 1000 | 0.0005 | 0.0005 | 0.0005 | 0.0015 |
| Indexed SQLite lookup | 100 | 0.0518 | 0.0471 | 0.0574 | 0.3328 |
| Create share API + gate | 10 | 4.3828 | 4.3312 | 4.7563 | 4.7563 |
| Public verify API | 20 | 3.3558 | 3.2791 | 3.5317 | 5.0702 |
| Public verify, 2 workers | 8 | 5.8457 | 6.0259 | 7.5182 | 7.5182 |
| Revoke API | 10 | 2.4713 | 2.3734 | 2.9698 | 2.9698 |

Concurrent benchmark:2 workers,4 batches,8 requests; status codes `[200, 200, 200, 200, 200, 200, 200, 200]`. Đây là in-process FastAPI TestClient/SQLite với gate thật, không TCP/TLS/network/browser/camera scan benchmark. Không khẳng định mọi lần quét <5ms.

Resource interval có cả setup/cleanup fixture: parent CPU0.540658s, child CPU0.070903s, wall0.499415s. RSS before159.00MiB, after163.52MiB, delta4.52MiB; sampled parent peak167.55MiB/5ms, OS process-lifetime peak167.58MiB. OS peak gồm cả imports/setup; sampling có thể bỏ lỡ đỉnh ngắn. Delta không chứng minh no-leak. Không đo browser heap/GPU hoặc camera latency.

## 5. Data safety và migration

Không có migration mới trong final remediation; giữ head a7f000000007, không downgrade/reset DB. Snapshot read-only đầu remediation ở data/tmp/phase6-final-preservation.json chứa path/counts/checksums, không in row contents. Sau sửa11 table counts giữ nguyên, integrity_check ok, foreign_key_check sạch; các PDF/backups được chụp checksum không đổi. Không sửa triggers/signatures/private keys/PDF thật. Tests và benchmark đều dùng DB/PDF synthetic riêng.

## 6. Demo và giới hạn triển khai

| Hạng mục | Trạng thái |
| --- | --- |
| Automated integration | PASS |
| Browser E2E thực tế | NOT TESTED |
| Mobile camera scan | NOT TESTED |
| User-selected real PDF demo | NOT TESTED |

[Mobile guide](phase6-mobile-demo.md) giữ signer localhost, public-only entry point tùy chọn và không tự chạy listener LAN. Không có HTTP encryption trên LAN. Rate/receipt state per-process; SQLite serial writer có thể tạo contention. Entry point demo không phải production ingress; chưa có long-load/complex PDF/browser/layout320px/camera proof. QR/canvas mocks không thay việc decode PNG hoặc scan thật.

Warning Starlette/httpx và deprecated HTTP422 names từ test cũ còn tồn tại. Main bundle >500kB. PoP/fingerprint không chứng minh danh tính pháp lý; SELF_REGISTERED không phải CA, không có TSA. Public QR chỉ xem server assessment, không tự hash file trên điện thoại. Không triển khai Phase7/blockchain/PAdES/ECDSA.

## 7. File changes và todo

Backend: share_service.py (atomic issuance), pdf_worker.py/pdf_validator.py (controlled diagnostics), public_demo.py mới (public-only boundary). Frontend: PublicShare.tsx, SharesPanel.tsx mới và DocumentDetail integration, api/shares.ts (signal), PublicShare/SharesPanel/QR/Documents tests. Tests backend mới4 files ở trên và mở rộng test_phase6_interop.py để revoke/invalidation. Khác: benchmark_phase6.py, start_public_demo.sh, .env.example, README, plan/todo và docs Phase2/Phase6/benchmark.

Các file Phase6 modified/untracked do người dùng có từ trước vẫn được giữ. Không stage/commit/push. Todo phản ánh automated gates và tách riêng browser/camera/PDF thật chưa hoàn thành; follow-up parser root-cause còn mở. Có thể tiếp tục phát triển Phase7 khi người dùng yêu cầu, không đồng nghĩa production-ready.
