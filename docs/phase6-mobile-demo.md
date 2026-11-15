# Phase 6 — Demo MacBook → điện thoại

**Browser E2E, camera điện thoại và PDF thật: NOT TESTED trong đợt remediation này.** Đây là hướng dẫn để người dùng chủ động thực hiện, không phải bằng chứng đã demo thành công.

Chỉ dùng PDF không nhạy cảm do chính người dùng chọn và cho phép. HTTP LAN không mã hóa PDF metadata hoặc bearer URL/token; người trên mạng có thể quan sát. Không dùng tài liệu mật, không dùng cloud tunnel, không mở cổng Internet, không tắt auth/CSRF hoặc tự thay firewall.

## 1. LOCAL_DEMO mặc định: ký trên MacBook

Giữ backend riêng tư ở `127.0.0.1:8000`, Vite ở localhost:5173; dùng script native hiện có hoặc chạy riêng hai lệnh sau trong hai Terminal:

```bash
DEBUG=false venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --reload
```

```bash
npm run dev --prefix frontend -- --host localhost --port 5173
```

Người phát hành mở **http://localhost:5173** để đăng nhập, sinh/chọn khóa, đăng ký PoP, upload PDF do mình chọn, prepare và ký RSA-PSS thật. Localhost là ngữ cảnh được trình duyệt hỗ trợ cho WebCrypto. Không chuyển màn hình sinh khóa/ký sang HTTP bằng IP LAN; WebCrypto trên HTTP LAN thông thường không có secure context.

Muốn kiểm tra bản build public chỉ trên máy, sau build chạy:

```bash
npm run build --prefix frontend
bash scripts/start_public_demo.sh
```

Đây là LOCAL_DEMO: public entry point chỉ bind 127.0.0.1:5174. Script không tự bật LAN.

## 2. LAN_DEMO bật tường minh: chỉ public QR trên điện thoại

Xác định IP thật của MacBook, ví dụ với Wi-Fi en0:

```bash
ipconfig getifaddr en0
```

Nếu không có IP, kiểm tra tên interface đang hoạt động; không sao chép một IP ví dụ vào source. Hai thiết bị phải cùng Wi-Fi; một số mạng khách bật client isolation nên không kết nối được dù cùng SSID.

Trước khi tạo share, đặt `PUBLIC_APP_BASE_URL` trong `.env` thành `http://<IP_THẬT>:5174`, rồi restart **backend localhost** để nạp cấu hình. Thay placeholder bằng IP thật; không phát hành URL còn placeholder. Khóa IndexedDB của signer nằm ở origin localhost:5173, không chuyển sang origin IP LAN.

Build frontend và khởi chạy public entry point bằng IP vừa xác định:

```bash
npm run build --prefix frontend
DEMO_MODE=LAN_DEMO DEMO_HOST="IP_THẬT_CỦA_MACBOOK" DEMO_PORT=5174 bash scripts/start_public_demo.sh
```

Lệnh chỉ là ví dụ cú pháp: thay giá trị DEMO_HOST trước khi chạy. Người dùng chủ động chạy lệnh này mới mở listener LAN. Không cần bind backend 8000 hoặc Vite 5173 ra LAN.

Public entry point `backend.app.public_demo:app` chỉ có:

- GET `/verify/share/{token}`: HTML build.
- GET `/assets/...`: assets build.
- GET `/api/v1/verify/share/{token}`: kết quả server đánh giá lại.

Không mount private document/upload/download/package/shares-management/auth APIs; các đường dẫn đó trả 404. Access logging bị tắt ở entry point này để bearer URL không vào access log. Proxy headers bị tắt. Vẫn có rate/concurrency cap của public verification; limiter là per-process, không phải quota dùng chung với native backend.

Frontend public dùng API cùng origin qua `/api/v1`, nên điện thoại không cần cookie đăng nhập hay CORS wildcard. Không thêm `*` vào CORS. Signer localhost vẫn dùng cookie và CSRF như trước. Nếu một deployment khác tách API origin, phải thiết kế CORS allowlist/HTTPS/cookie phù hợp riêng; hướng dẫn này không yêu cầu việc đó.

Trên MacBook, vẫn ở localhost:5173, mở tài liệu SIGNED, chọn thời hạn/nhãn, tạo share rồi xem QR. Quét QR bằng camera iPhone/Android và mở URL IP thật:5174. Điện thoại chỉ xem kết quả server: không nhận PDF, không sinh private key, không ký và không tự hash PDF gốc.

## 3. Kiểm tra thủ công cần ghi nhận

1. QR mở đúng tài liệu/version, expiry và fingerprint. Không có PDF/package download.
2. VALID/UNCHANGED/CONSISTENT hiển thị đúng; SELF_REGISTERED không phải CA, timestamp khai báo không phải TSA.
3. Owner revoke trên localhost, reload điện thoại → 404; token hết hạn → 410. Khác biệt 410/404 là tín hiệu tồn tại token được chấp nhận theo đồ án.
4. PNG tải được và camera thực sự đọc được URL. Unit test canvas/download không thay bằng chứng này.
5. Dùng bản PDF thử nghiệm riêng trong Independent Verify để chứng minh sửa bytes → TAMPERED. Không sửa PDF đã ký trong storage thật.

Lưu browser/OS, bước thực hiện, trạng thái PASS/FAIL và thời điểm khi thực sự demo; không ghi raw token hoặc ảnh QR vào báo cáo công khai.

## 4. Troubleshooting

| Triệu chứng | Kiểm tra |
| --- | --- |
| Điện thoại không truy cập được | IP hiện tại, đúng port5174, public process còn chạy, cùng Wi-Fi, VPN và client isolation |
| Firewall chặn | Xem cảnh báo macOS và hỏi người dùng trước khi thay đổi; không tắt firewall toàn bộ |
| URL mở localhost trên điện thoại | PUBLIC_APP_BASE_URL sai hoặc QR cũ; restart backend rồi tạo share mới; QR cũ không tự đổi URL |
| Màn hình trắng/assets404 | Chạy build trước public entry point; kiểm tra dist/assets, chưa có browser E2E chứng minh layout |
| API network error | Mở URL QR cùng origin:5174; xem process public; không đưa phone API về localhost:8000 |
| 429/503 | Chờ Retry-After; single-process rate/job cap là chủ đích, không vô hiệu hóa để demo |
| 404/410 | Token sai/thu hồi/hết hạn; không tiết lộ metadata qua response lỗi |
| Login hoặc upload ở IP LAN trả404 | Public-only boundary đang hoạt động; đăng nhập/upload/ký trên localhost:5173 |
| Cookie/CSRF lỗi trên signer | Giữ đúng origin localhost, cookie, X-CSRF-Token và anti-CSRF header; không tắt CSRF |
| WebCrypto/IndexedDB không có khóa | Quay về origin localhost đã tạo khóa; HTTP LAN không phải nơi ký; dùng HTTPS được tin cậy nếu cần kiến trúc khác |
| Copy link không hoạt động trên HTTP | Dùng ô liên kết và copy thủ công; QR modal có fallback |
| Cần bảo mật truyền tải | HTTP LAN không mã hóa; phải thiết kế HTTPS và đánh giá deployment riêng trước dữ liệu nhạy cảm |

## 5. Tắt LAN_DEMO

Ctrl+C Terminal public entry point. Giữ hoặc đóng backend/Vite localhost tùy nhu cầu. Đưa PUBLIC_APP_BASE_URL về http://localhost:5173 rồi restart backend cho phiên local mới. Thu hồi các shares đã demo nếu không cần giữ hiệu lực. Không xóa lịch sử token/DB/PDF và không tự đổi firewall.
