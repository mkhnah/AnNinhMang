# Dấu thời gian TSA nội bộ

Chữ ký mới có thể kèm token RFC 3161 do **DocSign Internal TSA** cấp. TSA có khóa riêng RSA 3072, chứng chỉ được CA đang cấu hình cấp, EKU `timeStamping` critical và không dùng cho ký PDF/tài khoản. Token chứng thực SHA-256 của bytes chữ ký RSA-PSS đã hoàn tất; qua đó ràng buộc manifest và hash PDF đã ký. Token chứng minh chữ ký đã tồn tại tại `genTime`, không chứng minh chính xác thời điểm người dùng bấm ký.

Đây là TSA nội bộ cùng miền quản trị DocSign. Đồng hồ lấy từ hệ điều hành; cần đồng bộ NTP. Không phải dịch vụ dấu thời gian công cộng hoặc chứng thực độc lập. Token không bỏ qua các kiểm tra thu hồi/thời hạn chứng chỉ người ký hiện tại.

## Cài đặt và bật

Chạy từ WSL/Ubuntu, tại thư mục dự án. CA hiện tại phải sẵn sàng (`PKI_ENABLED=true`). Không tạo lại CA.

```bash
cd /mnt/d/ANM/AnNinhMang
venv-wsl/bin/pip install -r requirements.txt
venv-wsl/bin/python scripts/upgrade_pki_database.py
venv-wsl/bin/python scripts/init_tsa.py \
  --output-dir "$HOME/.local/share/docsign/tsa" --configure-env .env
```

Thư mục TSA phải mới, nằm trên filesystem Linux có quyền riêng tư; script không ghi đè thư mục đã có. Script tạo private key **mã hóa**, password ngẫu nhiên trong file mode 0600, chứng chỉ công khai; chỉ cập nhật `.env` sau khi cấp và xác minh token thử thành công. Không in password hay nội dung khóa. Runtime dùng khóa TSA, không dùng khóa CA để cấp từng token. Lưu backup encrypted key và password riêng theo quy trình vận hành của dự án.

Khởi động lại backend để nạp cấu hình và ký một phiên bản PDF mới:

```bash
venv-wsl/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Kết quả xác minh hiển thị `TRUSTED_TSA`, thời gian chứng thực, tên TSA và phạm vi `DOCSIGN_PRIVATE_TSA`. File `signature-package.json` xuất ra có `timestamp_token_b64`; dùng được với PDF + signature hoặc signature + chứng chỉ. Report và liên kết chia sẻ cũng mang thời gian TSA đã kiểm tra.

## Quy tắc và bảo toàn dữ liệu

- Bật `TSA_ENABLED=true`: nếu không lấy/kiểm tra được token, trả 503 trước bước tiêu thụ nonce và lưu chữ ký. Thử lại cùng phiên khi phiên còn hạn; hết hạn cần chuẩn bị lại.
- Token lưu riêng trong bảng `signature_timestamps`, cùng transaction với chữ ký. Migration b1 chỉ thêm bảng, không viết lại chữ ký/PDF cũ; chặn UPDATE/DELETE token. Downgrade bị chặn khi có bằng chứng TSA.
- File chữ ký cũ không có token vẫn đọc được, giữ `DECLARED` hoặc `SERVER_RECORDED`. Không gán ngược dấu thời gian cho ngày ký cũ. Muốn có TSA, tạo và ký phiên bản mới.
- Token được kiểm tra DER/CMS, SHA-256 imprint, nonce khi cấp, chữ ký/ESS, EKU, chain, pin SHA-256 của đúng signer và root; thời hạn chain được kiểm tra tại thời điểm token. Từ chối token tương lai quá 5 phút. Token sai hoặc mất trust có `timestamp_status=INVALID`, không được nâng `TRUSTED_TSA` và làm kết quả đầy đủ `UNVERIFIABLE`.
- Phải cấu hình pin từ nguồn tin cậy ở verifier khác. Không tự tin root/chứng chỉ đính kèm package. Không cần private key TSA khi xác minh.
- TSA dùng chung CA với registry: CA bị COMPROMISED/RETIRED làm timestamp không đạt trust khi kiểm tra trực tuyến. Khi khóa TSA bị lộ, loại fingerprint khỏi `TSA_SIGNER_SHA256` trên mọi verifier. Hiện chưa triển khai CRL/OCSP riêng cho TSA, lưu trữ chứng cứ thu hồi dài hạn hoặc gia hạn timestamp để bảo toàn chữ ký sau khi thuật toán suy yếu.
- Khi thay TSA signer, `TSA_SIGNER_SHA256` có thể chứa nhiều fingerprint phân cách bằng dấu phẩy để giữ trust signer cũ an toàn. `TSA_ROOT_SHA256` ghim một root; thay root cần giữ cấu hình verifier phù hợp cho chứng cứ lịch sử.

Tham khảo giao thức và lệnh kiểm tra: [OpenSSL ts — RFC 3161](https://docs.openssl.org/3.0/man1/openssl-ts/).
