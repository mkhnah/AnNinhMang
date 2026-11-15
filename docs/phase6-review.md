# Phase 6 — Review triển khai ngày 15/11/2026

> Đây là review lịch sử trước final remediation. Trạng thái hiện tại và bằng chứng release nằm trong [phase6-report.md](phase6-report.md). Các finding dưới đây phản ánh source tại thời điểm review.

**Kết luận: NOT READY cho phát triển Phase 7 theo release gates của prompt.**

Đây là review mã Phase 6 hiện tại, không phải remediation hoặc triển khai lại. Không sửa application source, không migrate DB thật, không mở LAN/Internet, không dùng PDF thật, không commit/push. Các probe chỉ dùng fixture DB/storage riêng; file test tạm đã được gỡ sau khi chạy.

## Kết quả kiểm thử thực tế

| Kiểm tra | Kết quả |
| --- | --- |
| `venv/bin/pytest -q --tb=short` | FAIL collection: `pytest_plugins` trong non-top-level conftest |
| `venv/bin/pytest -q --ignore=tests/phase6 --tb=short` | 276 passed, 4 warnings; regression Phase 1–5 |
| `venv/bin/pytest tests/phase6 -q --tb=short` | 2 passed; không đủ để gọi full regression PASS |
| `npm test --prefix frontend -- --run` | 86 passed, 8 files; chưa có tests cho QR/PublicShare/share management; có jsdom network AggregateError trong output |
| `frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit` | PASS |
| `npm run build --prefix frontend` | PASS; bundle khoảng 774kB, warning chunk >500kB |
| `DEBUG=false venv/bin/alembic check` | PASS, không schema drift |
| Read-only DB thật | Head a7f000000007; integrity ok; FK violations 0; trigger share_token_immutable tồn tại |
| Backend probe bổ sung | Tái hiện phát hành share cho PDF tampered/missing, concurrent revoke race và header sai |
| Frontend component probe bổ sung | Tái hiện response A đến muộn ghi đè kết quả B khi route đang ở token B |

Probe cố ý assert hành vi lỗi hiện tại để chứng minh tái hiện; probe PASS không có nghĩa lỗi đã được sửa. Không dùng tổng các lần chạy riêng làm số full-suite PASS.

## Findings cần sửa

### P1 — Phát hành share trước khi xác minh evidence và PDF

`backend/app/services/share_service.py:39–54` chỉ kiểm tra state SIGNED và sự tồn tại của Signature, sau đó phát hành token. Không gọi Phase 5 Verification Engine, không kiểm tra evidence consistency, actual PDF hash, RSA validity hoặc revocation trước khi tạo share.

Tái hiện qua API thực: ký PDF synthetic hợp lệ, sửa bytes PDF trong private fixture storage rồi POST shares → **201**. Public verify sau đó trả **200 / INTEGRITY_COMPROMISED**. Xóa PDF fixture rồi tạo share khác vẫn **201**.

Public engine đã nhận ra PDF bị sửa; vấn đề ở creation gate, không phải bằng chứng rằng public engine trả VERIFIED cho tampered PDF. Cần inject storage, chạy shared Phase 5 verification pipeline trước khi sinh/lưu token và từ chối phát hành khi bằng chứng không đạt chính sách.

### P1 — Recheck sau verify có thể đọc ORM state cũ khi concurrent revoke

`backend/app/services/share_service.py:113–116` SELECT lại ShareToken trong cùng Session không bắt buộc refresh các thuộc tính của object đã có trong identity map.

Probe chạy verification thật; sau commit của verify, public Session load ShareToken còn active; Session khác commit revoked_at rồi public verify tiếp tục recheck. Kết quả request đang chạy vẫn **200**, request mới sau đó **404**. Đây là cửa sổ race của recheck, không phải token được phục hồi vĩnh viễn.

Cần đọc các scalar columns trực tiếp từ DB hoặc dùng refresh/populate_existing với transaction boundary phù hợp; kiểm tra lại revoked/expiry ngay trước khi trả response. Thêm test có hai Session và đồng bộ thời điểm commit. Revoke API cũng cần giữ idempotent semantics khi conditional UPDATE không còn cập nhật được hàng vì request revoke khác vừa hoàn thành.

### P1 — Public page có stale response khi đổi token

`frontend/src/pages/Verify/PublicShare.tsx:12–14` không có AbortController/generation guard/cleanup và không reset result/error theo token.

Component probe: mở token A, chuyển sang B, nhận response B trước rồi A sau → component hiển thị **Document A** trong route B. Lỗi cũ cũng có thể tiếp tục che kết quả của token mới do error không được reset.

Cần snapshot token, invalidate khi route thay đổi, abort khi unmount và chỉ cập nhật state từ request hiện hành. Bổ sung A/B ordering, error→valid, unmount và retry tests.

### P1 — Full backend regression không chạy được

`tests/phase6/conftest.py:1` khai báo `pytest_plugins = ["tests.test_phase5_verification"]` trong conftest cấp con. Pytest từ repository root dừng collection với thông báo không hỗ trợ non-top-level pytest_plugins.

Chạy riêng thư mục Phase 6 đạt 2 tests không khắc phục release gate này. Đưa fixtures dùng chung vào vị trí phù hợp hoặc import fixtures rõ ràng, rồi chạy full suite từ root.

### P2 — Security headers không đạt hợp đồng public share

`backend/app/api/v1/shares.py:70–71` đặt no-store/no-referrer, nhưng `backend/app/main.py:73` ghi đè Referrer-Policy trên mọi response.

Đo qua HTTP TestClient:

- Share thành công: Cache-Control no-store; Referrer-Policy **strict-origin-when-cross-origin**, không phải no-referrer.
- Token lỗi 404: **không có Cache-Control**, Referrer-Policy cũng strict-origin-when-cross-origin.
- X-Content-Type-Options nosniff đang có.

Cần áp dụng policy cho cả success/error/429/503. Đồng thời áp dụng no-referrer cho trang HTML public vì header trên API JSON không thiết lập referrer policy cho document đang chứa bearer token trong URL. Hiện frontend/index.html không có referrer meta policy và Vite chưa cấu hình policy riêng.

### P2 — Share management chưa đầy đủ và dễ nhầm tài liệu

`frontend/src/pages/Documents/index.tsx:98` lấy toàn bộ shares của user, nhưng phần hiển thị trong DocumentDetail không lọc theo document/version của trang. Share của document khác hiện v? và vẫn có nút revoke. Đây là nhầm ngữ cảnh quản lý trong cùng tài khoản; không phải cross-user IDOR đã được chứng minh.

Thiếu chọn expiry/label trước khi tạo, revoke confirmation, empty/loading/error riêng, trạng thái expired; lỗi list bị nuốt bởi catch rỗng. API limit 100 không có pagination nên share cũ có thể biến mất khỏi UI quản lý. Cần lọc theo document hoặc tạo trang quản lý có document metadata được phép, và có pagination.

### P2 — Release evidence và todo chưa khớp

Chưa có `docs/phase6-report.md`, `docs/phase6-mobile-demo.md` hoặc benchmark Phase 6. Chưa có cấu hình LOCAL_DEMO/LAN_DEMO; startup và Vite vẫn bind loopback, nên chỉ đổi PUBLIC_APP_BASE_URL chưa làm điện thoại truy cập được.

Phase 6 hiện chỉ có 2 backend tests, dùng Python signing helper. Chưa có chuỗi real frontend WebCrypto → share → public verification. Interoperability Phase 5 đã PASS không tự chứng minh nhánh Phase 6. Chưa có test mới cho expiry/revoke/concurrency/IDOR/CSRF/privacy/PNG/stale UI của Phase 6. Trong khi đó todo đánh dấu 10/10 và khẳng định T-09/T-10 đã kiểm chứng.

Cần mở lại các task thiếu bằng chứng, hoàn thiện test/report/demo guide và ghi NOT TESTED cho browser/camera/PDF thật cho đến khi thực sự làm.

## Góp ý bổ sung

- `share_service.py:92–95` chỉ kiểm tra độ dài và alphabet, chưa decode/re-encode Base64URL để xác nhận canonical encoding. Generation 32 random bytes hiện đúng; đây là thiếu validation theo prompt, không phải bằng chứng entropy yếu.
- `SHARE_DEFAULT_EXPIRY_DAYS` chưa được dùng: request schema vẫn hardcode 7. TTL vượt max bị silently clamp; nên xác định hợp đồng rõ ràng. Validate PUBLIC_APP_BASE_URL về scheme/host/credentials/query/fragment để tránh tạo link sai do cấu hình.
- Revoke/list hiện authorize theo created_by, chưa JOIN document/version/current owner như yêu cầu. Cần regression rõ chính sách ownership; hiện chưa tái hiện được IDOR qua API ownership-transfer vì không có luồng đó trong review này.
- Public response lồng toàn bộ VerificationResultResponse; nên dùng public DTO riêng với allowlist để trường mới ở Phase 5 không tự xuất hiện ở share API. Chưa thấy PDF bytes/storage path/email/private key trong response đã kiểm tra.
- UI chưa hiển thị declared signing timestamp; nhãn xanh chỉ dựa summary. Nên kiểm tra thêm validity/integrity/evidence consistency để tránh kết luận xanh khi dữ liệu không nhất quán.
- Clipboard API có thể không khả dụng trên HTTP LAN; QR modal cần bắt lỗi copy và có cách sao chép thủ công. Không được ghi PNG download/camera scan PASS chỉ từ việc có nút trong source.
- verify_shared gọi _finish rồi xóa receipt khỏi response, nhưng receipt đã được cấp và đưa vào cache. Nên cho pipeline tắt receipt issuance khi share endpoint không cung cấp report; tránh anonymous scans chiếm cache receipt không sử dụng.
- Trigger chống đổi token_hash/un-revoke đang có. Không mở rộng tuyên bố thành API constant-time; indexed hash lookup không chứng minh điều đó.

## Trạng thái demo

| Nhóm | Trạng thái |
| --- | --- |
| Automated integration | PARTIAL; full backend collection FAIL, các lỗi nêu trên còn tồn tại |
| Browser E2E | NOT TESTED |
| Mobile camera scan | NOT TESTED |
| Real user-selected PDF demo | NOT TESTED |

Review không tự chọn/upload/chia sẻ PDF thật và không bật LAN. DB check chỉ xác nhận trạng thái hiện tại; không đủ bằng chứng để xác nhận backup và row-count preservation trước/sau migration mà người dùng đã chạy trước review.
