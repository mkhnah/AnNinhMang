# Phase 4 — Security remediation và release audit

Ngày kiểm chứng: 15/11/2026. Phạm vi: RSA-PSS-3072, SHA-256, detached manifest RFC 8785/JCS; không triển khai Phase 5, PAdES, ECDSA hay blockchain.

**Kết luận: READY cho phát triển Phase 5 theo các release gate tự động dưới đây.** Đây không phải chứng nhận production hoặc bảo đảm không còn lỗ hổng. Browser E2E thực tế chưa chạy; giới hạn được ghi riêng bên dưới.

## Nguyên nhân, cách sửa và bằng chứng

| Nhóm | Root cause | Sửa và file chính | Bằng chứng |
| --- | --- | --- | --- |
| FIX-P4-01 | Kiểm tra quyền document nhưng đọc signature chỉ bằng version ID | `backend/app/services/signature_service.py`: JOIN Signature → DocumentVersion → Document, ràng buộc cả document ID, version ID và owner ID | Own signature 200; cross-user, document A + version B, cross-document, ID không tồn tại và ADMIN không sở hữu đều 404; anonymous 401; UUID sai 422 |
| FIX-P4-02 | Expiry/key/state chỉ được kiểm tra trước thao tác tốn thời gian; UPDATE consume thiếu điều kiện trạng thái cuối | Cùng service: hash file + verify RSA trước DML; UPDATE consume đầu tiên lấy SQLite writer lock và kiểm tra `julianday(expires_at) > julianday('now')`, user/version/key/nonce, hash/canonical bytes, key ACTIVE, revoked_at NULL, public material/fingerprint/algorithm, owner, version READY và chưa có signature. Insert + state transition + commit cùng transaction | 5 trường hợp thay đổi từ connection riêng **sau crypto verify, ngay trước consume**: expiry, revoke, revoked_at, version state, session hash đều 409, không consume/không insert/không SIGNED; rollback và real writer contention 503; retry sau rollback đạt |
| FIX-P4-03 | TypedArray generic có thể trỏ ArrayBufferLike, không thỏa BufferSource | `frontend/src/crypto/manifestCanonicalizer.ts`, `signer.ts`: dùng `toCryptoBytes` cho digest/sign/verify; bỏ cast vòng qua unknown → ArrayBuffer | Strict tsc, production build và crypto vectors đạt; không dùng any/ts-ignore hay tắt strict |
| FIX-P4-04 | Ký trực tiếp manifest server, chưa đối chiếu preview bytes và selection | `manifestBinding.ts`, `SignModal.tsx`, `PDFViewer.tsx`: hash đúng bytes đưa vào PDF.js trước transfer; so version/hash metadata/hash preview/key ID/fingerprint SPKI thực tế/user/schema/context/algorithm/nonce/timestamp; kiểm tra hash canonical và expiry của response. Flow generation vô hiệu hóa callback cũ khi đổi selection/document; cần preview render thành công + consent | SignModal tests cho PDF A/manifest A, version/hash/key ID/fingerprint/algorithm/context/nonce/timestamp/public-key mismatch; mismatch không gọi signer hoặc POST. StrictMode, stale prepare khi đổi document và đổi key được kiểm tra |
| FIX-P4-05 | Schema tự điền default/coerce và normalize; duplicate JSON đã mất trước Pydantic | `backend/app/schemas/signature.py`: tất cả 9 trường bắt buộc, strict, version là int 1 (không bool/float/string), lowercase UUID/hex, canonical 32-byte base64url nonce, UTC timestamp chính xác milliseconds, RSA duy nhất. `api/v1/signatures.py`: APIRoute kiểm tra raw UTF-8 JSON trước parser FastAPI; `crypto/jcs.py` từ chối duplicate, nonfinite, lone surrogate | API thực tế kiểm tra thiếu từng trường, sai kiểu/giá trị/unknown field, duplicate cả escaped name, NaN, overflow 1e999, lone surrogate. JSON syntax lỗi 400; giá trị/schema/duplicate lỗi 422 |
| FIX-P4-06 | 6 FK có CASCADE trong migration a4 nhưng ORM không có; thiếu DB immutability signature | `models/signature.py` + migration mới `a5f000000005_signature_retention.py`: NO ACTION FK, giữ unique/index/check; trigger cấm mọi UPDATE/DELETE signature. Writer rollback trả lỗi tổng quát, không lộ SQL/params | Raw SQL sửa signature, manifest, hash, signer/key/version hoặc DELETE bị chặn. Duplicate/FK sai/parent delete bị chặn. SIGNED transition cần signature. Migration a4 → head với **fixture có chữ ký** giữ nguyên toàn bộ hàng; FK check + Alembic check đạt |
| FIX-P4-07 | PDF.js cũ, chỉ cancel render, canvas không giới hạn; POST lỗi bị coi là chưa ký | PDF.js pin `4.10.38`, worker `.mjs?url`; `PDFViewer.tsx` + `pdfBudget.ts`: AbortController, cancel render, loading-task.destroy (hủy document/transport/worker sở hữu), cleanup page, tối đa 4 triệu canvas pixels/4096 mỗi chiều, một trang, cap input 20MiB và image size. `SignModal.tsx`, `pendingSigning.ts`, `api/signatures.ts`: query cả version và signature, so chính xác request/hash/signature/signer/key; UNKNOWN nếu không xác nhận; retry cùng chữ ký sau khi xác nhận absence | PDF lifecycle tests, render failure không báo preview verified; lost-response đã commit, offline UNKNOWN, signature khác, exact retry và remount recovery đều đạt. Context public được lưu sessionStorage; không có private key/token/passphrase |
| FIX-P4-08 | Chỉ có helper tests; hai implementation chưa chạy chung, chưa có client signer → persistence | `tests/helpers/signing_webcrypto.cjs`, `test_phase4_interop.py`, `test_phase4_remediation.py`, hai frontend suites mới | Bridge bundle các module TS thực tế bằng esbuild, WebCrypto keypair non-extractable ở Node, PoP đăng ký public key, backend prepare, frontend JCS/sign, Python verify, DB signature + SIGNED. Không dùng Python ký thay client trong integration này |

## Kết quả kiểm thử đã chạy

| Gate / lệnh | Kết quả |
| --- | --- |
| `venv/bin/pytest -q --tb=short` | **196 passed**: toàn bộ Phase 1–3 regression và Phase 4 |
| `npm test --prefix frontend -- --run` | **72 passed**, 6 files; có 18 SignModal và 9 PDFViewer tests |
| `frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit` | PASS; strict giữ nguyên |
| `npm run build --prefix frontend` | PASS; worker asset được build; còn warning bundle >500kB |
| `DEBUG=false venv/bin/alembic check` | PASS, `No new upgrade operations detected` sau upgrade trên DB thật |
| Signature read IDOR | PASS; relationship chain + owner được kiểm tra; không có endpoint đọc trực tiếp bằng signature ID/export khác trong phạm vi hiện tại |
| Expiry tại consume / revoked key / final binding | PASS; kiểm thử late race sau verify bằng connection riêng |
| Strict schema / duplicate raw JSON / JCS invalid input | PASS |
| Raw SQL tampering / retention / FK / uniqueness | PASS |
| Replay / concurrency | PASS: cùng nonce và khác nonce cùng version; chỉ một signature được commit, một session consumed |
| Rollback / DB busy | PASS: lỗi insert rollback cả nonce/state; khóa SQLite thật trả 503 rồi retry thành công |
| PDFViewer cleanup | PASS trong component tests với PDF.js mocks; benchmark render PDF.js thật riêng bên dưới |
| Lost response | PASS: chỉ báo thành công nếu chữ ký khớp; UNKNOWN giữ context; exact retry không ký lại/không tự cấp nonce mới |
| T-22 TS ↔ Python | PASS: byte-for-byte từ bridge thực tế; golden vectors + Unicode tiếng Việt/combining forms, emoji/UTF-16 ordering, ECMAScript number thresholds/-0; từ chối surrogate/nonfinite. Raw duplicate API được kiểm tra riêng, không tuyên bố JSON.parse của JS có khả năng giữ duplicate keys |
| WebCrypto → Python → DB | PASS: `test_real_webcrypto_frontend_signer_to_python_db` |
| DB thật / backup | PASS: không xóa/reset DB; giữ mọi row count baseline, integrity_check=ok, foreign_key_check sạch; checksum backup cũ không đổi; backup không tracked và đã ignored |

Cảnh báo kiểm thử còn lại: deprecation Starlette/httpx và tên HTTP status 422; không phải failure của test. Các vector và bridge chỉ kiểm chứng phạm vi test đã ghi, không phải bằng chứng về mọi đầu vào RFC 8785 có thể có.

## Migration và an toàn dữ liệu

- Migration mới: `backend/alembic/versions/a5f000000005_signature_retention.py`, parent `a4f000000004`.
- Không sửa lịch sử migration a4. Batch rebuild hai bảng giữ dữ liệu, đổi 6 CASCADE FK thành NO ACTION; khôi phục version trigger, thêm signature UPDATE/DELETE guards. Dùng `BEGIN IMMEDIATE` khi pysqlite chưa có transaction thực, kiểm tra FK và số hàng trong transaction để rollback khi lỗi.
- Đã thử trên bản sao DB và trên database fixture có signature/session consumed/key/document/user. Sau đó mới backup SQLite online và upgrade DB thật; kiểm tra integrity/FK/counts sau upgrade.
- Tạo thêm backup trong `data/db/backups/` (ignored). File `data/db/docsign.db.bak_pre_phase4` không bị xóa, di chuyển hay sửa; checksum đối chiếu đạt. Không in nội dung dữ liệu DB thật ra báo cáo.
- `.gitignore` bổ sung `*.db.bak*`, `*.sqlite.bak*`, `*.sqlite3.bak*`; `git ls-files` xác nhận backup cũ chưa được Git track; không stage/commit/push.
- Fixture pytest dùng database riêng và tạo lại **schema test** giữa test vì retention trigger cấm DELETE. Không áp dụng cách cleanup này lên DB thật.
- Linearization point là conditional UPDATE consume. Revoke commit trước writer UPDATE → chữ ký bị từ chối. Nếu signing đã giữ writer lock, revoke phải chờ; signing commit trước revoke là thứ tự hợp lệ. Không có khoảng SELECT kiểm tra cuối ngoài cơ chế đồng bộ ghi.

## PDF.js, bộ nhớ và dependency

Advisory chính thức [GHSA-wgrm-67xf-hhpq](https://github.com/mozilla/pdf.js/security/advisories/GHSA-wgrm-67xf-hhpq) nêu phiên bản <=4.1.392 bị ảnh hưởng và bản vá 4.2.67. Đã thay 3.11.174 bằng **4.10.38**, pin exact để tương thích Node 20 hiện tại; `isEvalSupported: false` chỉ là defense-in-depth. Vite build xác nhận worker `.mjs` tương thích.

`npm view` tại lần kiểm tra này: PDF.js mới nhất 6.5.438 yêu cầu Node >=22.13 hoặc >=24, trong khi máy dùng 20.12.0. Không khẳng định nhánh 4.x còn được upstream bảo trì dài hạn. Cần đánh giá nâng runtime/project dependency trong công việc riêng; không thay cấu hình macOS. `npm audit` lần này không báo advisory PDF.js, nhưng điều đó không bảo đảm không còn lỗ hổng.

Benchmark đã chạy: `venv/bin/python scripts/benchmark_pdf_preview.py`; kết quả trong [`phase4-pdf-memory.json`](phase4-pdf-memory.json). Mỗi kích thước chạy một tiến trình Node mới, PDF.js legacy thực tế + native canvas, WebCrypto hash, render một trang rồi destroy. Dùng cùng hàm giới hạn canvas của component.

| Fixture mục tiêu | Bytes thực tế | Process peak RSS | Thời gian hash/load/render/destroy |
| --- | ---: | ---: | ---: |
| 1MiB | 1,048,502 | 103.42MiB | 61ms |
| 5MiB | 5,242,806 | 112.63MiB | 64ms |
| 10MiB | 10,485,688 | 130.58MiB | 92ms |
| 20MiB | 20,971,448 | 159.75MiB | 122ms |

Đây là PDF tổng hợp blank-page với content stream padding; kích thước thực tế hơi nhỏ hơn mục tiêu. Không suy ra bộ nhớ cho PDF scan, font/image lớn hoặc file độc hại. Component tests kiểm tra buffer 1/5/10/20MiB, vượt 20MiB bị từ chối, page cực lớn bị cap 4M pixels, abort/cancel/destroy, lỗi render không cho ký. Chưa đo browser worker/GPU/heap, chưa stress mở/đóng lặp lâu dài. Không nhận Web Worker là sandbox bảo mật tuyệt đối. Input và canvas cap không chặn mọi decompression/parser CPU hoặc memory abuse.

`npm audit --prefix frontend --json`: còn **2 moderate** qua React Router/React Router DOM, GHSA-wrjc-x8rr-h8h6 và GHSA-337j-9hxr-rhxg; npm đề xuất major upgrade 7.18.5. Chưa thay router major trong remediation này. Cần đánh giá open redirect khi có URL do người dùng điều khiển và SSR hydration nếu bổ sung SSR. Hiện ứng dụng dùng client routing; không suy ra advisory không có tác động chỉ từ việc tests pass. `canonicalize@5.1.0` khai báo Node >=22 nên npm có engine warning trên Node 20.12; module đã chạy qua bridge/build/tests ở môi trường này, nhưng môi trường chưa nằm trong engine support được công bố. Cần chốt runtime được hỗ trợ trước release production.

## Giới hạn còn lại và công việc tiếp theo

- **Chưa chạy browser E2E** Chrome/Safari/Firefox thật cho auth cookie/CSRF + IndexedDB CryptoKey + worker Vite + giao diện ký hoàn chỉnh. Node WebCrypto bridge và jsdom component tests không thay thế bài này.
- Cần thử PDF nhiều trang/scanned/font lớn và theo dõi heap/worker/GPU qua các lần mở/đóng trên Mac 8GB; benchmark hiện tại chỉ chứng minh workload tổng hợp đã đo.
- Fingerprint được tính từ SPKI của public CryptoKey; chữ ký vừa tạo còn được verify với public key đó để phát hiện private/public pairing hỏng, kể cả private key non-extractable. Không export/đưa private material vào backend. Trường hợp private key bị tráo nhưng metadata/public key còn đúng được phát hiện ở local verify sau sign, trước POST.
- XSS/same-origin code có thể gọi WebCrypto bằng CryptoKey trong browser. Non-extractable không chống mọi hành vi ký bị chiếm quyền. Người có toàn quyền SQLite/filesystem có thể gỡ trigger hoặc thay evidence; trigger chỉ chặn đường DML thông thường. Không tuyên bố SQLite tự verify mật mã khi người có quyền DB chèn dữ liệu trực tiếp.
- Server hash file trước writer transaction; quyền OS của storage phải hạn chế sửa file ngoài ứng dụng. Không bao phủ attacker chiếm quyền máy/đổi file đồng thời từ filesystem.
- Không có timestamp authority, PAdES, trust-chain/certificate validation hay verification engine Phase 5. ECDSA được trì hoãn, manifest API hiện chỉ chấp nhận RSA-PSS-3072.
- Pending context chứa public manifest/signature trong sessionStorage theo user/document/version, sống qua remount/reload trong cùng tab. Mất storage/tab vẫn cần đọc trạng thái server; backend single-signature constraint tiếp tục ngăn duplicate. Không có tự động POST/nonce mới khi UNKNOWN.

Các giới hạn browser/runtime/dependency cần được xử lý trước release production. Toàn bộ release gates Phase 4 được yêu cầu trong prompt đã có bằng chứng tự động đạt; có thể bắt đầu phát triển Phase 5 khi người dùng yêu cầu, chưa triển khai Phase 5 trong lần làm này.

## Danh sách file remediation

Những file chỉnh/sinh trong đợt remediation này (ngoài mã Phase 4 người dùng đã có):

- Backend: `backend/app/services/signature_service.py`, `backend/app/api/v1/signatures.py`, `backend/app/schemas/signature.py`, `backend/app/crypto/jcs.py`, `backend/app/models/signature.py`, `backend/alembic/versions/a5f000000005_signature_retention.py`.
- Frontend: `frontend/src/crypto/manifestCanonicalizer.ts`, `signer.ts`, `manifestBinding.ts`, `pendingSigning.ts`; `frontend/src/pages/Documents/SignModal.tsx`; `frontend/src/components/PDFViewer/PDFViewer.tsx`, `pdfBudget.ts`; `frontend/src/api/signatures.ts`; `frontend/package.json`, `frontend/package-lock.json`.
- Tests: `tests/conftest.py`, `tests/test_phase4_signatures.py` (nonce fixture hợp lệ), `tests/test_phase4_remediation.py`, `tests/test_phase4_interop.py`, `tests/helpers/signing_webcrypto.cjs`; `frontend/src/crypto/__tests__/manifest.test.ts` (nonce fixture hợp lệ), `frontend/src/pages/Documents/__tests__/SignModal.test.tsx`, `frontend/src/components/PDFViewer/__tests__/PDFViewer.test.tsx`.
- Benchmark/report/tracking: `scripts/benchmark_pdf_preview.cjs`, `scripts/benchmark_pdf_preview.py`, `docs/phase4-pdf-memory.json`, `docs/phase4-report.md`, `plan.md`, `todo.md`, `.gitignore`.

Các file Phase 4 khác đã modified/untracked trước remediation được giữ lại. Không commit hoặc stage các thay đổi.
