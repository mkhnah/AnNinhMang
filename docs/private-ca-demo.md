# Demo CA, chứng chỉ và chữ ký v2

Ngày cập nhật 17/11/2026. Mỗi bước dưới đây sử dụng dữ liệu QA; tài liệu thật và private CA đang vận hành được giữ riêng.

## Khởi chạy

Backend thường dùng cấu hình `.env` với CA thật đã được tạo. Để demo tách biệt hoàn toàn, mở terminal WSL tại project và chạy:

```bash
venv-wsl/bin/python scripts/serve_pki_qa.py
```

Script tạo database/CA QA mới trong `/tmp`, storage riêng trong `data/tmp/pki-qa/`, giữ private key CA QA có mã hóa và file mode 0600. Server chỉ bind loopback cổng 8000. Tài khoản giả lập là `ca-qa-owner@cyber.edu` và `ca-qa-admin@cyber.edu`, password demo `QaDemo@2026!`. Thông tin này chỉ dùng với database QA do script tạo. Có thể tiếp tục cùng dữ liệu bằng `--resume <QA-workspace-được-in-ra>`. Dừng bằng Ctrl+C.

Trong terminal Windows ở `frontend`, chạy:

```powershell
npm run dev
```

Mở `http://localhost:5173`. PDF mẫu được script tạo tại `data/tmp/pki-qa/sample.pdf`. Đóng server QA và frontend sau demo.

## Luồng owner

1. Đăng nhập owner, vào Quản lý khóa. Sinh RSA-PSS 3072; chọn chế độ backup hoặc non-extractable theo nhu cầu. Backend nhận public key và PoP, trả certificate do CA QA ký.
2. Vào Chứng chỉ của tôi. Kiểm tra subject, serial, fingerprint, hạn và assurance ACCOUNT_BOUND; tải PEM.
3. Bấm Chứng minh sở hữu khóa. Browser ký challenge bằng khóa local và API xác nhận possession tại thời điểm thực hiện. Gửi lại cùng challenge phải bị từ chối.
4. Upload PDF mẫu, mở phiên bản, chuẩn bị ký và chọn certificate. Xem trước PDF, xác nhận ý định ký, ký manifest v2. Private key ở browser.
5. Xác minh nội bộ. Các chiều PDF, chữ ký, certificate binding, CA, thời hạn, thu hồi và identity phải đạt. Xuất signature-package v2 và report.
6. Mở Xác minh tài liệu PDF, chọn PDF + file signature-package.json. Chứng chỉ và chuỗi CA đã nằm trong package v2. Để đối chiếu một chứng chỉ riêng, dùng trang Xác minh chữ ký số với package + PEM. Thử tráo PEM bằng certificate sau renewal; kết quả không được xác minh đầy đủ.
7. Tạo QR/share, mở liên kết công khai. Chỉ các dimension tối thiểu được hiển thị; hồ sơ identity review giữ riêng tư.

## Danh tính và trang kiểm tra riêng

1. Owner gửi yêu cầu đối chiếu tên và mã hồ sơ riêng tại trang Chứng chỉ của tôi.
2. ADMIN mở CA và danh tính, đối chiếu bằng chứng theo quy trình vận hành của chủ CA, nhập lý do và duyệt/từ chối. Mỗi review chỉ quyết định một lần; không tự duyệt chính mình.
3. Owner gia hạn/cập nhật certificate bằng PoP mới. Certificate mới có CN là tên đã duyệt và assurance ADMIN_REVIEWED. Certificate đã cấp trước đó giữ nguyên bytes và mức assurance.
4. Trang `/verify/certificate` chỉ nhận file chứng chỉ PEM (.pem/.crt) và hiển thị thông tin chủ thể, CA, thời hạn, thu hồi, account binding và assurance.
5. Trang `/verify/signature` nhận file signature-package.json + file chứng chỉ PEM. Máy chủ xác minh chữ ký trên manifest bằng khóa trong chứng chỉ và kiểm tra certificate binding, CA, thời hạn, thu hồi. Không cần PDF; kết quả ghi rõ tính toàn vẹn PDF chưa được kiểm tra. Kiểm tra PDF cùng signature dùng trang `/verify`.
6. Khi bật TSA nội bộ, ký phiên bản PDF mới và xuất signature-package; kết quả phải có `TRUSTED_TSA`, thời gian TSA chứng thực và phạm vi nội bộ. Chữ ký cũ vẫn giữ `DECLARED`/`SERVER_RECORDED`. Cách bật và quản lý trust: [hướng dẫn TSA](timestamps.md).

## Các trường hợp thất bại

- Sửa PDF, chữ ký, manifest, signer ID hoặc fingerprint certificate: kết quả tài liệu không VERIFIED.
- Thay certificate khác cùng key sau renewal: certificate binding MISMATCH dù chữ ký vẫn có thể đúng về toán học.
- Thu hồi certificate: xác minh lại bị chặn bởi trạng thái hiện tại; certificate/key/audit cũ vẫn được giữ.
- Thu hồi key: toàn bộ certificate liên quan bị thu hồi trong cùng transaction.
- CA COMPROMISED: tắt phát hành và làm certificate liên quan không đạt trust policy. Trạng thái compromise không thể đảo ngược.
- Thiếu nguồn thu hồi/registry trong chế độ offline: UNKNOWN; không tuyên bố xác minh đầy đủ.
- Chữ ký v1: vẫn xác minh crypto và PDF, có nhãn LEGACY_NO_CERTIFICATE_BINDING. Cấp certificate cho key cũ không sửa evidence của chữ ký cũ.

## Kết quả kiểm tra Chrome ngày 16/11/2026

Đã quan sát trên Chrome thật: đăng nhập tài khoản QA, sinh khóa RSA-PSS non-extractable, tự cấp certificate, hiển thị serial/fingerprint/assurance trên trang quản lý và xác nhận possession thành công bằng khóa local. Các thao tác dùng database và CA QA riêng.

Chủ máy dừng Computer Use bằng Escape trước khi hoàn tất lượt browser ký/verify tài liệu và viewport 320px. Phần này vẫn là gate demo thủ công còn lại của PKI-18. Backend QA và Vite đã được dừng; không mở lại Computer Use sau Escape. Kiểm thử tự động chạy signer và certificate binding TypeScript thật qua WebCrypto, rồi xác minh/lưu/xuất/kiểm tra bằng Python.
