# Phase 6 — Kiểm tra lại sau sửa, 15/11/2026

> Đây là review lịch sử trước final remediation. Trạng thái hiện tại và bằng chứng release nằm trong [phase6-report.md](phase6-report.md). Các finding dưới đây phản ánh source tại thời điểm review.

**Kết luận: NOT READY theo release gates hiện tại.** Nhiều lỗi của review đầu đã được sửa đúng, nhưng còn lỗi có thể tái hiện và full backend run lần này chưa đạt.

Đây là review, không sửa application source hoặc tài liệu triển khai của người dùng. Test bổ sung dùng DB/PDF synthetic riêng. File probe tạm đã gỡ sau khi chạy; không migrate DB thật, không bật LAN, không upload/chia sẻ PDF thật, không commit/push.

## Các sửa đã xác nhận

| Phát hiện trước | Trạng thái hiện tại |
| --- | --- |
| Tạo share bỏ qua Verification Engine | Đã gọi verify_shared và kiểm tra consistency, crypto VALID, PDF UNCHANGED, key ACTIVE, PoP; tests tampered/missing/invalid/revoked ban đầu đạt. Còn race riêng ở thời điểm insert, nêu dưới. |
| Recheck đọc ShareToken cũ trong identity map | Đã truy vấn scalar columns. Probe độc lập dùng hai Session, revoke sau verification trong cửa sổ cũ → public response 404. |
| PublicShare response A ghi đè B | Đã có generation/token guard, reset và AbortController; test A/B ordering và unmount đạt. |
| pytest_plugins cấp con làm collection lỗi | Đã bỏ; full suite thu thập được 307 tests. |
| Public security headers sai | Middleware bảo vệ success/error; tests headers và rate-limit đạt; frontend có no-referrer meta. |
| Quản lý shares trộn tài liệu | API và UI đã lọc document, có expiry/label/revoke confirmation và trạng thái; frontend pagination vẫn chưa có. |
| Thiếu Phase 6 evidence | Đã thêm 31 backend tests, 13 frontend tests, real TS/Node WebCrypto integration, report/demo guide/benchmark script. Báo cáo vẫn có kết luận vượt bằng chứng. |
| Canonical token / public DTO / receipt cache | Đã kiểm tra canonical Base64URL, DTO public riêng và tắt issue_receipt cho shared verification. |

## Findings còn lại

### P1 — Key revoke giữa verification và insert vẫn phát hành share

Vị trí: `backend/app/services/share_service.py:106–151`.

ACTIVE được lấy từ kết quả verify_shared. Hàm này commit verification event; sau đó create_share chỉ recheck DocumentVersion.state, không xác nhận lại trạng thái khóa trong transaction lưu ShareToken.

Probe API thực trên fixture riêng:

1. Ký PDF hợp lệ, bắt đầu create_share.
2. Chạy verify_shared thật, nhận key ACTIVE.
3. Session khác commit key REVOKED và revoked_at trước khi create_share insert.
4. Create response vẫn **201**, có share token mới.
5. Quét token đó qua public API trả **REVOKED_KEY**.

Public verify không falsely VERIFIED trong repro này. Lỗi là creation policy công bố khóa phải ACTIVE tại issuance bị vượt qua. Cần ràng buộc owner/version/key ACTIVE + revoked_at NULL trong transaction insert, ví dụ conditional INSERT ... SELECT hoặc short SQLite write transaction phù hợp; không chỉ đọc lại thêm một lần rồi insert ngoài transaction bảo vệ. Thêm hai-session regression có synchronization barrier.

### P2 — UI biến UNKNOWN/UNVERIFIABLE thành kết luận sai

Vị trí: `frontend/src/pages/Verify/PublicShare.tsx:156–215`.

Ba biểu thức boolean dùng mọi nhánh else làm kết luận phủ định:

| Dữ liệu thực | UI hiện tại | UI cần có |
| --- | --- | --- |
| document_integrity UNKNOWN | ĐÃ BỊ SỬA ĐỔI (TAMPERED) | Chưa xác định / không có PDF để hash |
| key_revocation_status UNKNOWN | ĐÃ BỊ THU HỒI | Không xác định trạng thái thu hồi |
| cryptographic_validity UNVERIFIABLE | KHÔNG HỢP LỆ | Chưa đủ bằng chứng để xác minh |

Component probe đã render cả ba nhãn sai từ payload UNKNOWN/UNVERIFIABLE. Cần mapping theo từng enum, không dùng phép phân loại hai nhánh. Test mới hiện chỉ bao phủ valid/error/lifecycle nên chưa bắt lỗi này. Nhãn declared_timestamp cũng nên ghi rõ “Thời điểm ký khai báo”, không suy thành thời điểm ký đã được TSA chứng thực.

### P2 — Frontend chưa quản lý được shares ngoài trang đầu

Vị trí: `frontend/src/pages/Documents/index.tsx:102–108`; API mặc định limit=20.

loadShares chỉ gọi sharesApi.list(id) một lần. Không có state offset, hasMore hoặc nút tải trang sau cho danh sách share. Khi tài liệu có hơn 20 shares, UI không cho xem/thu hồi các share cũ dù API đã hỗ trợ pagination. Bổ sung paging riêng cho shares và test hơn 20 items.

### P2 — Report/benchmark/mobile evidence cần sửa trước khi kết luận READY

- Full run lần review này không đạt 307/307; xem số đo bên dưới. Không phủ nhận một run trước có thể đã đạt, nhưng không được dùng nó để che lỗi không ổn định hiện tại.
- `test_17_concurrent_revoke_idempotency` thực hiện ba revoke tuần tự. `test_18_identity_map_stale_refresh_concurrent_revoke` revoke hoàn tất trước khi bắt đầu public request. Tên test không chứng minh concurrent interleaving. Probe độc lập của review xác nhận scalar fix, nhưng report không nên gọi các test tuần tự là concurrency proof.
- QR PNG test mock toDataURL và chỉ click nút; chưa assert PNG bytes, decode QR hoặc chứng minh camera quét được. Cần ghi riêng Automated integration, Browser E2E, Mobile camera scan, Real user-selected PDF demo. Ba mục sau chưa được kiểm thử trong review này; report hiện thiếu bảng trạng thái bắt buộc đó.
- Benchmark là TestClient trong process, không phải đo quét camera/browser/network; cần ghi scope rõ, kích thước PDF synthetic và giới hạn workload. Chưa đo concurrent QR requests hay CPU theo yêu cầu.
- `phase6-report.md` ghi p95 token generation/hash/revoke, nhưng JSON và script không lưu các p95 tương ứng, nên không đối soát được. Không suy “mỗi lần quét <5ms” từ median/mean TestClient; JSON còn có max public verify 5.88ms.
- Đo RSS trước/sau +4.73MiB chỉ là delta. Nó không chứng minh không có memory leak hoặc peak usage.
- Demo guide cho phép thao tác ký ở HTTP LAN; cần chỉ dẫn signer dùng localhost hoặc HTTPS phù hợp với WebCrypto, điện thoại chỉ mở public verify. Cần bổ sung cảnh báo HTTP LAN không mã hóa, chỉ dùng tài liệu không nhạy cảm; bỏ tuyên bố “bảo vệ 100% quyền riêng tư của tài liệu mật”. Hướng dẫn chưa bao quát cookie/CSRF/firewall troubleshooting theo prompt.

## Ghi chú về parser budget

`backend/app/core/config.py` đổi default wall timeout **5→10 giây**, CPU **3→6 giây**; demo guide cũng yêu cầu các giá trị mới. Cần ghi rõ thay đổi này, lý do và ảnh hưởng tới thời gian giữ tài nguyên. Các tài liệu Phase 2/todo vẫn mô tả 5/3 giây. Không thể coi tăng budget là bằng chứng đã giải quyết căn nguyên parser false rejection: hiện vẫn quan sát worker exit -24.

## Kết quả chạy thực tế

| Lệnh / kiểm tra | Kết quả |
| --- | --- |
| `venv/bin/pytest -q --tb=short` | **306 passed, 1 failed**, 4 warnings, 94.93s; collection đã được sửa |
| Test lỗi | `TestAdditionalVerificationEdgeCases.test_tampered_manifest_nonce_fails_math_verification`: chờ 200 nhưng nhận 400; PDF worker `rejected=False, returncode=-24, output=b''` |
| Chạy riêng test lỗi | **1 passed**, 0.35s; chưa xác định căn nguyên sự không ổn định |
| Tests Phase 6 trong full run | 31 tests không có failure được báo; real WebCrypto → share → anonymous public verify chạy trong bộ này |
| `npm test --prefix frontend -- --run` | **99 passed**, 11 files; còn jsdom AggregateError/network và navigation warning |
| Strict tsc | PASS |
| Production build | PASS; warning chunk >500kB, main JS khoảng 787kB |
| Alembic check | PASS, không schema drift |
| Backend probes bổ sung | 2 passed theo assertions tái hiện: key race còn; stale ShareToken recheck đã sửa |
| UI probe bổ sung | 1 passed theo assertions tái hiện UNKNOWN bị gán nhãn sai |

Probe tái hiện lỗi được viết để assert hành vi đang sai; probe PASS không có nghĩa remediation đã hoàn thành. Các probe không được cộng vào số tests chính thức trong repository.

Chưa chạy lại benchmark và chưa sửa số liệu benchmark của người dùng. Không có bằng chứng mới về browser thật/camera điện thoại/PDF thật. Trạng thái của ba mục đó trong review: **NOT TESTED**.
