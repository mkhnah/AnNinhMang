# AnNinhMang - Digital Document Signing and Verification System

> **Đồ án môn An ninh mạng**: Nghiên cứu và xây dựng hệ thống ký số và xác thực tài liệu điện tử  
> **Kiến trúc**: Monorepo Native-First (Tối ưu hóa tài nguyên cho macOS 8GB RAM, không bắt buộc Docker)

---

## 🚀 Tính năng chính

### 1. Phân hệ Xác thực & Quản lý Phiên An Toàn (Phase 1)
- **Băm mật khẩu Argon2id**: Sử dụng tham số chuẩn $m=64\text{ MB}$, $t=3$, $p=4$ kèm cơ chế chống timing attacks (`dummy_verify`), ngăn chặn hoàn toàn kỹ thuật liệt kê người dùng qua độ trễ phản hồi.
- **Cơ chế chống Brute-Force**: Tự động khóa tài khoản tạm thời 15 phút (`locked_until`) sau 5 lần nhập sai mật khẩu liên tiếp.
- **Quản lý phiên bằng HttpOnly Cookie + CSRF Protection**:
  - Access Token (JWT 15 phút) lưu trong cookie HttpOnly chống tấn công XSS trích xuất token.
  - Refresh Token Rotation (7 ngày) với **Token Reuse Detection**: Tự động thu hồi tất cả phiên của người dùng trên toàn hệ thống nếu phát hiện Refresh Token cũ bị gửi lại (phát hiện token bị đánh cắp).
  - Double Submit Cookie kết hợp Custom Request Header (`X-Requested-With`, `X-CSRF-Token`) triệt tiêu nguy cơ CSRF.
- **Phân quyền vai trò RBAC (Role-Based Access Control)**: Phân tách rõ ràng giữa quyền `USER` thông thường và `ADMIN` hệ thống.
- **Security Headers Middleware**: Áp dụng các tiêu chuẩn bảo mật HTTP (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`).

### 2. Kế hoạch các Phân hệ tiếp theo
- **Phase 2**: Quản lý tệp PDF cục bộ, kiểm tra Magic Bytes, AST Sanitization loại bỏ JavaScript nhúng độc hại, bất biến phiên bản (Version Immutability).
- **Phase 3**: Zero-Trust Key Management (WebCrypto RSA-PSS 3072-bit / ECDSA P-256 sinh trực tiếp tại trình duyệt client, sao lưu PBKDF2 + AES-GCM, xác thực quyền sở hữu Proof-of-Possession).
- **Phase 4**: Lõi ký số Detached Manifest (RFC 8785 JSON Canonicalization Scheme - JCS).
- **Phase 5**: Động cơ xác minh đa chiều (Tính toàn vẹn SHA-256, chữ ký mật mã, trạng thái thu hồi khóa).
- **Phase 6 - 10**: Chia sẻ qua QR Code, Audit Log chuỗi băm Merkle, bộ 28 bài kiểm thử an ninh chuyên sâu.

---

## 🛠️ Công nghệ sử dụng

- **Backend**: Python 3.13, FastAPI, SQLAlchemy 2.x, Alembic, SQLite native.
- **Mật mã học**: Argon2id (`argon2-cffi`), PyJWT, Cryptography (NIST FIPS 180-4, PKCS#1 v2.1).
- **Frontend**: React 18, TypeScript, Tailwind CSS, Vite, Axios, Lucide React.
- **Kiểm thử & Đo lường**: Pytest, HTTPX, PSUtil.

---

## ⚡ Hướng dẫn cài đặt và khởi chạy (macOS Native)

### 1. Chuẩn bị mã nguồn và biến môi trường
```bash
git clone https://github.com/mkhnah/AnNinhMang.git
cd AnNinhMang

# Sao chép cấu hình môi trường chuẩn
cp .env.example .env
```

### 2. Thiết lập Backend & Dữ liệu
```bash
# Tạo môi trường ảo Python
python3 -m venv venv
source venv/bin/activate

# Cài đặt các thư viện cần thiết
pip install -r requirements.txt

# Nạp database migration (SQLite native)
cd backend && alembic upgrade head && cd ..

# Khởi tạo tài khoản mẫu (Admin, Alice, Bob)
python scripts/seed_users.py
```

### 3. Thiết lập Frontend
```bash
cd frontend
npm install
cd ..
```

### 4. Khởi động toàn bộ hệ thống (1-Click)
```bash
chmod +x scripts/dev_start.sh
./scripts/dev_start.sh
```
- **Backend API**: `http://localhost:8000` (Tài liệu Swagger: `http://localhost:8000/docs`)
- **Frontend Web**: `http://localhost:5173`

---

## 🔑 Tài khoản mẫu phục vụ thử nghiệm & Demo

| Email | Mật khẩu | Quyền hạn (Role) | Chức năng kiểm thử |
| :--- | :--- | :---: | :--- |
| `admin@cyber.edu` | `Admin@Secure2026!` | `ADMIN` | Truy cập trang Quản trị `/admin`, theo dõi người dùng & phiên. |
| `alice@cyber.edu` | `Alice@Secure2026!` | `USER` | Người dùng thông thường, kiểm thử phân quyền 403 Forbidden. |
| `bob@cyber.edu` | `Bob@Secure2026!` | `USER` | Người dùng thông thường, kiểm thử phân quyền 403 Forbidden. |

---

## 🧪 Chạy bộ kiểm thử an ninh (Security Test Suite)

Dự án tích hợp bộ kiểm thử tự động 20 kịch bản tấn công và kiểm tra an ninh:
```bash
./scripts/run_security_tests.sh
```
Hoặc chạy trực tiếp với pytest:
```bash
./venv/bin/pytest tests/security/test_phase1_security.py -v
```

---

## 📊 Kết quả đo đạc thực tế (Apple Silicon M-Series, 8GB RAM)

- **Bộ nhớ RAM sử dụng (RSS)**:
  - Backend FastAPI: ~141 MB (Idle) $\to$ ~144 MB (Peak sau 80 thao tác mật mã nặng).
  - Frontend Vite Dev Server: ~80 MB.
  - Tổng RAM: **< 230 MB** (Tiết kiệm > 90% so với việc khởi chạy máy ảo Docker).
- **Độ trễ xử lý (Latency)**:
  - Đăng ký (Argon2id 64MB): ~33 ms.
  - Đăng nhập (Argon2id verify + JWT): ~33 ms.
  - Lấy thông tin cá nhân (`/users/me`): ~2.4 ms.
  - Token Rotation: ~3.7 ms.

## Phase 2 — PDF và phiên bản

Mở `/documents` sau đăng nhập để tải PDF lên, xem lịch sử, tải xuống và sao chép SHA-256. Mỗi phiên bản giữ nguyên bytes. Chức năng khóa chỉ chuyển `DRAFT → READY_TO_SIGN`; ký số chưa được triển khai.

```bash
venv/bin/pip install -r requirements.txt
DEBUG=false venv/bin/alembic upgrade head
npm ci --prefix frontend
venv/bin/pytest -q
npm test --prefix frontend
npm run build --prefix frontend
DEBUG=false bash scripts/dev_start.sh
```

`DEBUG=false` tránh xung đột nếu shell có biến `DEBUG=release`. Giới hạn mặc định 20 MiB; thay `MAX_UPLOAD_BYTES` trong `.env` và restart backend, UI đọc giới hạn qua API. Các giới hạn parser được mô tả trong `.env.example`. Multipart spool và temp của worker ở `data/tmp/`.

- [Báo cáo Phase 2, API, kiểm thử, phục hồi và rủi ro](docs/phase2-report.md)
- [Số đo benchmark thực tế](docs/phase2-benchmark.json)
- Khi cần kiểm tra sau crash: dừng upload, chạy `DEBUG=false venv/bin/python scripts/reconcile_storage.py`. Script chỉ báo cáo, không xóa dữ liệu.
