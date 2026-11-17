# Vận hành CA riêng và API chứng chỉ

Ngày cập nhật 16/11/2026. Các tính năng PKI-01 đến PKI-17 đã triển khai. PKI-18 có kiểm thử tự động, tài liệu vận hành và kịch bản demo; còn lượt kiểm tra Chrome đầy đủ/320px bị dừng bằng Escape.

## Trạng thái triển khai

- Profile v1 dùng Root CA RSA-4096/SHA-256 ký trực tiếp leaf RSA-3072. Leaf dùng digitalSignature, SAN gắn tài khoản, SKI/AKI và hạn mặc định 365 ngày trong giới hạn hạn CA.
- Khóa user tiếp tục được sinh tại browser. Đăng ký public key qua PoP thành công tự cấp chứng chỉ `ACCOUNT_BOUND` khi PKI được bật.
- Đăng ký key/cert, consume challenge, cập nhật pointer và audit được commit nguyên tử. Retry cùng request được đối chiếu request digest và idempotency key để lấy lại certificate đã cấp.
- API hỗ trợ chứng chỉ cho key cũ, gia hạn bằng PoP mới, owner/admin đọc/tải/thu hồi, owner phân trang và ADMIN tra cứu toàn hệ thống.
- Gia hạn tạo certificate mới và giữ certificate cũ. Thu hồi key thu hồi các certificate liên quan trong cùng transaction.
- ADMIN xét duyệt danh tính; certificate cấp sau khi duyệt có subject snapshot và mức `ADMIN_REVIEWED`. Certificate cũ giữ nguyên assurance ban đầu.
- Ký mới khi bật PKI dùng manifest v2 có `signer_user_id` và hash DER certificate. Xác minh nội bộ, upload, QR và report cùng kiểm tra binding, CA, thời hạn và thu hồi.
- Có trang quản lý certificate, trang ADMIN CA/danh tính, trang kiểm tra certificate và trang kiểm tra chữ ký riêng. Challenge sở hữu khóa có context riêng, TTL 5 phút và chỉ dùng một lần.

## Cấu hình trên máy hiện tại

Database project đã nâng tới `b0f000000010`. Backup trước migration v2 nằm tại `data/db/backups/docsign_pre_pki_v2_20261116_195529.db`. Dữ liệu của cả 18 bảng trước upgrade được đối chiếu row counts và SHA-256, FK check và integrity check đạt. Backup trước sáu task đầu vẫn nằm tại `data/db/backups/docsign_pre_pki_20261116_095803.db`.

Đã khởi tạo `DocSign Private CA` với thời hạn 1825 ngày. Cấu hình `.env` cục bộ có `PKI_ENABLED=true`, đường dẫn certificate/key và đường dẫn password file. Key mã hóa và password file nằm trong các thư mục riêng dưới `~/.local/share/docsign/` của tài khoản WSL. File secret có mode 0600 và thư mục chứa có mode 0700.

Root fingerprint công khai của CA cục bộ hiện tại được ghi dưới đây để đối chiếu với `.env`.

```text
c334d84cd9332b3fb38d5c0c53cc455fad1b9210aba91e7cbb159954e5f0a66f
```

Khi khởi chạy backend trong WSL, môi trường đọc đúng những đường dẫn này. Backend đang chạy cần restart để nạp cấu hình mới.

## Khởi tạo CA khác bằng CLI

Trong terminal WSL, tại thư mục project, thực hiện lệnh sau.

```bash
cd /mnt/d/ANM/AnNinhMang
venv-wsl/bin/python scripts/init_ca.py \
  --output-dir ~/.local/share/docsign/authorities/my-ca \
  --name "DocSign Private CA"
```

CLI yêu cầu nhập và xác nhận password tối thiểu 16 byte qua getpass. Thư mục output phải là thư mục mới. Kết quả gồm `ca-key.pem` mã hóa PKCS#8 và `ca-cert.pem`, kèm fingerprint public in ra terminal.

Chuẩn bị password file chứa cùng password trong thư mục runtime-secrets có quyền owner-only, rồi đặt các biến môi trường tương ứng.

```dotenv
PKI_ENABLED=true
CA_PRIVATE_KEY_PATH=/absolute/linux/path/ca-key.pem
CA_CERTIFICATE_PATH=/absolute/linux/path/ca-cert.pem
CA_PRIVATE_KEY_PASSWORD_FILE=/absolute/linux/path/ca-password
CA_TRUSTED_ROOT_SHA256=<sha256-DER-certificate>
CA_ADDITIONAL_TRUSTED_ROOT_SHA256=<optional-comma-separated-previous-root-pins>
CA_USER_CERT_VALIDITY_DAYS=365
PKI_CERTIFICATES_PER_DAY=60
```

Có thể dùng `CA_PRIVATE_KEY_PASSWORD` dưới dạng process environment thay cho password file. Mỗi cấu hình chỉ chọn một nguồn password. Giá trị này dùng `SecretStr` trong settings.

Loader kiểm tra file secret thường, symlink, kích thước tối đa, owner và quyền POSIX, encrypted PEM, key/cert khớp và fingerprint đã pin. Cấu hình Windows native cần ACL phù hợp. Với WSL, dùng filesystem Linux cho CA để kiểm tra mode có ý nghĩa.

Backup private key dạng mã hóa, public certificate và fingerprint. Quản lý bản lưu password tách biệt với bản backup key và thử phục hồi trên môi trường riêng. Private key CA đã mở khóa tồn tại trong bộ nhớ tiến trình trong lúc cấp chứng chỉ.

## API đăng ký khóa

`POST /api/v1/keys` giữ các trường public_key_pem, algorithm, challenge_id và pop_signature_b64 hiện có. Trường tùy chọn `idempotency_key` nhận 16–128 ký tự chữ, số, gạch dưới hoặc gạch ngang. Khi bỏ qua, backend dùng challenge_id làm định danh retry trong chế độ PKI.

Response bổ sung `current_certificate_id` và object `certificate`, gồm PEM public, DER fingerprint, serial dạng hex, issuer ID, subject, thời hạn, trạng thái và `identity_assurance=ACCOUNT_BOUND`.

Retry phải gửi lại đúng request, bao gồm cùng PoP signature và idempotency key. RSA-PSS sinh chữ ký ngẫu nhiên mỗi lần nên client cần giữ request đã gửi để retry. Request khác dùng cùng idempotency key nhận 409. Request được xác nhận đã commit có thể được đọc lại cả khi CA tạm thời không thể cấp mới.

Trong compatibility mode `PKI_ENABLED=false`, đăng ký vẫn hoạt động với public key và PoP theo luồng cũ. Certificate API đọc và thu hồi lịch sử hoạt động dựa trên registry.

## Cấp certificate cho key cũ và gia hạn

1. Owner gửi `POST /api/v1/certificates/challenge` với key_id và purpose `ISSUE_CERT` cho key chưa có certificate pointer. Gia hạn dùng purpose `RENEW_CERT` và certificate_id hiện có.
2. Response có challenge_id, payload và expires_at. Client ký canonical JCS của toàn bộ payload bằng RSA-PSS/SHA-256 với saltLength 32.
3. Client gửi challenge_id, pop_signature_b64 và idempotency_key tới `/api/v1/certificates/issue-for-key` hoặc `/api/v1/certificates/{id}/renew`.
4. Challenge tồn tại tối đa 5 phút, dùng một lần và gắn context `DOCSIGN_CERTIFICATE_POP_V1`, owner, key, purpose, fingerprint và certificate đích.

PoP đăng ký khóa hiện có tiếp tục dùng context/schema của luồng REGISTER_KEY. Client ký đúng payload mà API certificate challenge trả về khi cấp thêm hoặc gia hạn.

Quota mặc định gồm 5 challenge certificate đang chờ trên mỗi tài khoản và 60 certificate được cấp trong 24 giờ. Quota cấp certificate kiểm tra trước CA signing và được kiểm tra lại bên trong writer transaction. Thu hồi certificate nhận reason thuộc KEY_COMPROMISE, SUPERSEDED, CESSATION hoặc USER_REQUEST.

## Danh sách endpoint

| Endpoint | Quyền |
| --- | --- |
| `POST /api/v1/certificates/challenge` | Owner của key |
| `POST /api/v1/certificates/issue-for-key` | Owner với PoP mới |
| `GET /api/v1/certificates/me?limit=20&offset=0` | Tài khoản hiện tại |
| `GET /api/v1/certificates/{id}` | Owner hoặc ADMIN |
| `GET /api/v1/certificates/{id}/download` | Owner hoặc ADMIN |
| `POST /api/v1/certificates/{id}/renew` | Owner với PoP mới |
| `POST /api/v1/certificates/{id}/revoke` | Owner hoặc ADMIN |
| `GET /api/v1/admin/pki/status` | ADMIN, kiểm tra CA readiness |
| `GET /api/v1/admin/pki/certificates?user_id=...` | ADMIN, phân trang và lọc owner |

Các mutation áp dụng CSRF hiện có của ứng dụng. PEM download và các API PKI đặt no-store. Trạng thái certificate phản ánh vòng đời, hạn và registry key/CA. Xác minh tài liệu v2 bổ sung đầy đủ các chiều certificate/identity; khi một chiều bắt buộc thất bại hoặc thiếu nguồn thu hồi, kết quả tổng thể không đạt VERIFIED.

## Schema và bất biến

Migration bổ sung 6 bảng PKI, current_certificate_id trên public_keys và các retention/ownership guards. Pointer dùng trigger SQLite kiểm tra certificate thuộc đúng key và user, giúp tránh vòng FK giữa key và certificate. Insert key ban đầu đặt pointer null; transaction cấp certificate gán pointer sau khi lưu certificate.

Subject/PEM/serial/fingerprint/thời hạn của certificate đã cấp và evidence CA được bảo vệ khỏi UPDATE. Certificate và signature-certificate binding được giữ lại bằng trigger và FK. Metadata thu hồi certificate chỉ chuyển một lần; repeat revoke giữ nguyên thời điểm/lý do ban đầu.

Identity review giữ claims snapshot và chỉ chuyển PENDING sang APPROVED/REJECTED một lần, có reviewer/time/reason. ADMIN không tự duyệt hồ sơ của chính mình. Claims/evidence reference chỉ owner và ADMIN được xem; audit không lưu các nội dung này. Certificate tự cấp mặc định có assurance ACCOUNT_BOUND. Legacy account có ID dạng opaque dùng URI thuộc `https://docsign.invalid/accounts/`, account UUID dùng `urn:uuid:`.

## Kiểm chứng

Kiểm thử PKI được đặt tại `tests/test_pki.py`, gồm X.509/OpenSSL, load secret/configuration errors, atomic issuance, lost response/idempotency, simultaneous requests, owner/admin/CSRF, quotas, corrupted legacy keys, expiry/revocation races và migration dữ liệu lịch sử.

```bash
venv-wsl/bin/python -m pytest tests/test_pki.py -q
venv-wsl/bin/python -m alembic check
```

Để chạy full suite có kiểm tra POSIX file mode từ máy Windows, dùng bản sao source trên filesystem Linux và binary esbuild Linux phù hợp. Các test tự dùng database tạm và CA test trong `/tmp`; root conftest tắt PKI mặc định, fixture PKI nạp CA test riêng.

Phiên bản được kiểm chứng hiện tại là cryptography 50.0.2 và OpenSSL 3.5.5 trong WSL. Các gate release và kết quả lượt cuối được ghi trong `private-ca-plan.md`.

## Ký và xác minh với chứng chỉ

Khi `PKI_ENABLED=true`, prepare-sign tạo manifest v2 và trả certificate leaf cùng public issuer certificate. Client có thể chọn certificate đang hoạt động của key; API prepare-sign nhận thêm `certificate_id`. Browser kiểm tra hash DER, SPKI fingerprint, SAN account, thời hạn và chữ ký CA, kiểm tra trạng thái trực tuyến rồi ký JCS bằng RSA-PSS/SHA-256 saltLength 32.

Manifest v2 bổ sung các trường sau vào các binding PDF/key/nonce hiện có:

```json
{
  "manifest_version": 2,
  "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V2",
  "signer_user_id": "<stable-account-id>",
  "certificate_sha256": "<sha256-of-exact-leaf-DER>"
}
```

Đây là phần trích minh họa; client luôn ký toàn bộ manifest do prepare-sign trả về. Submit xác minh signature, consume nonce có điều kiện, lấy writer lock và kiểm tra lại account/key/cert/CA tại thời điểm ghi. Signature, certificate binding, trạng thái phiên bản và audit cùng commit hoặc rollback. Thu hồi/expiry/đổi trust xảy ra giữa prepare và submit làm yêu cầu thất bại.

Package v2 có `package_version=2`, `signature_format=DETACHED_JCS_V2`, toàn bộ manifest, signature Base64, SPKI public, `certificate_pem` và `issuer_chain_pem` gồm đúng một Root. Root gửi kèm chỉ là bằng chứng; verifier chọn root theo fingerprint trong cấu hình tin cậy. Đổi certificate dù cùng SPKI sau renewal không vượt qua DER binding.

`POST /api/v1/verify/upload` vẫn nhận PDF + package, hỗ trợ thêm trường multipart `certificate_file` tối đa 16 KB khi cần đối chiếu PEM riêng. Dùng PEM riêng với v1 bị từ chối vì v1 không ký fingerprint certificate. Certificate đã nằm trong package v2 nên không bắt buộc gửi PEM lần nữa.

Các chế độ internal/upload/share dùng chung policy. Kết quả v2 chỉ VERIFIED khi chữ ký hợp lệ, PDF nguyên vẹn, key registry không mâu thuẫn và mọi chiều bắt buộc về certificate/identity đạt. Revocation là trạng thái hiện tại từ registry trực tuyến; khi thiếu nguồn, UNKNOWN làm full verification không đạt. Thời gian khai báo không thay thế TSA và không dùng để bỏ qua expiry/revocation hiện tại.

Khi đọc v1, hệ thống giữ nguyên bytes và thuật toán trước đây, thêm nhãn `LEGACY_NO_CERTIFICATE_BINDING`. Muốn có certificate binding phải tạo chữ ký v2 mới theo quy tắc phiên bản của ứng dụng.

## API danh tính, kiểm tra riêng và CA

| Endpoint | Nội dung / quyền |
| --- | --- |
| `POST /api/v1/pki/identity-requests` | Owner gửi full_name và evidence_reference riêng |
| `GET /api/v1/pki/identity-requests` | Owner đọc hồ sơ của mình, limit/offset |
| `GET /api/v1/admin/pki/identity-requests` | ADMIN đọc hồ sơ, ưu tiên PENDING, limit/offset |
| `POST /api/v1/admin/pki/identity-requests/{id}/decision` | ADMIN quyết định APPROVED/REJECTED và reason; cấm tự duyệt |
| `POST /api/v1/verify/certificate` | Công khai, nhận certificate_pem, không cần private key CA |
| `POST /api/v1/verify/signature` | Công khai, nhận certificate_pem và signature_package (nội dung file JSON); vẫn hỗ trợ message_b64 + signature_b64 cho client cũ |
| `POST /api/v1/pki/possession/challenge` | Owner xin challenge cho certificate_id |
| `POST /api/v1/pki/possession/verify` | Owner gửi challenge_id và signature_b64 trên JCS payload |
| `GET /api/v1/admin/pki/authorities` | ADMIN đọc public CA registry |
| `POST /api/v1/admin/pki/authorities/{id}` | ADMIN đổi trust_status/issuance_enabled, audit nguyên tử |

Tên trên certificate đã duyệt được giới hạn 64 byte UTF-8 theo profile CN. Evidence reference là mã hồ sơ riêng; ứng dụng không tự xác thực giấy tờ dựa trên nội dung người dùng khai. ADMIN thực hiện đối chiếu theo quy trình của chủ CA. Certificate cấp trước khi duyệt giữ ACCOUNT_BOUND; owner cần gia hạn để nhận certificate mới có snapshot đã duyệt.

Ba trang xác minh có đầu vào riêng:

| Trang | File đầu vào | Phạm vi |
| --- | --- | --- |
| `/verify` | PDF + signature-package.json | Kiểm tra hash PDF, chữ ký và bằng chứng chứng chỉ kèm package |
| `/verify/signature` | signature-package.json + chứng chỉ PEM | Kiểm tra chữ ký trên manifest và đối chiếu chứng chỉ; tính toàn vẹn PDF là UNKNOWN |
| `/verify/certificate` | Chứng chỉ PEM (.pem/.crt) | Xem thông tin và kiểm tra CA, thời hạn, thu hồi chứng chỉ |
| `/verify/users` | Họ tên, email hoặc UUID | Tra cứu tài khoản để đối chiếu UUID; yêu cầu đăng nhập |

Mục **Tra cứu người dùng** tìm kiếm từ 2 ký tự, không phân biệt hoa/thường (gồm tên tiếng Việt trên SQLite), phân trang 20 kết quả và cho sao chép UUID đầy đủ. Nút **Đối chiếu UUID người dùng** trong kết quả chứng chỉ mở `/verify/users?uuid=...`; kết quả ghi rõ khớp/không khớp UUID đang đối chiếu. Trang quản trị CA có liên kết **Tra cứu UUID** cạnh bộ lọc mã tài khoản.

API `GET /api/v1/users/search?q=...&limit=20&offset=0` yêu cầu phiên đăng nhập hợp lệ. Kết quả chỉ có `id`, `full_name`, `email`, `status`; giới hạn tối đa 50 kết quả mỗi trang, không lưu cache. Họ tên tài khoản là thông tin do người dùng khai báo, không tự nâng mức đảm bảo danh tính trên chứng chỉ.

Chữ ký riêng dùng RSA-PSS 3072/SHA-256 salt32 và certificate policy. Package tối đa 512 KB; chứng chỉ tối đa 16 KB. Client cũ vẫn có thể gửi `message_b64` (tối đa 1 MB) cùng `signature_b64`. Kiểm tra tài liệu PDF có manifest dùng endpoint upload. Possession dùng context `DOCSIGN_VERIFY_POSSESSION_V1`, ràng buộc certificate fingerprint, user, nonce ngẫu nhiên, TTL 5 phút và consume một lần. Mỗi user có tối đa 5 challenge đang chờ.

Public certificate/signature requests chịu giới hạn body trước parser, giới hạn độ dài PEM/message/signature, rate limit và admission semaphore dùng chung verification. Chế độ triển khai native hiện tại dùng một process; multi-worker/distributed rate limit thuộc phạm vi mở rộng.

## Rotation, trust và thu hồi CA

1. Tạo Root mới bằng CLI trong thư mục mới; giữ public cert và encrypted key cũ để phục hồi/lưu lịch sử.
2. Đặt key/cert/password-source và `CA_TRUSTED_ROOT_SHA256` theo Root mới, restart backend. Các lần cấp mới dùng Root mới.
3. Để tiếp tục tin certificate cũ, thêm fingerprint Root cũ vào `CA_ADDITIONAL_TRUSTED_ROOT_SHA256` (phân cách bằng dấu phẩy), giữ CA cũ ở TRUSTED và đặt issuance_enabled=false. Certificate lịch sử vẫn tham chiếu đúng CA đã cấp trong registry.
4. RETIRED ngừng trust theo policy hiện tại; COMPROMISED ghi mốc sự cố, ngừng cấp và làm mọi certificate liên quan không đạt policy. COMPROMISED không thể chuyển lại TRUSTED. Không đánh dấu CA bị lộ chỉ để thử trên database thật.

CA cùng tên nhưng khác key/certificate không được tin. Private key CA chỉ được nạp khi phát hành hoặc kiểm tra readiness; verifier sử dụng public certificate, configured pins và registry. TSA RFC 3161 nội bộ dùng khóa chuyên biệt, xem [hướng dẫn dấu thời gian](timestamps.md). CRL/OCSP offline, intermediate CA, HSM và PAdES vẫn nằm ngoài MVP này.

## Vận hành và kiểm thử

Các trang mới là `/certificates`, `/admin/pki`, `/verify/certificate` và `/verify/signature`. Dashboard có số liệu certificate/review và cảnh báo CA mất trust, certificate sắp hết hạn 30 ngày, kiểm tra PKI thất bại liên tiếp. Audit có sự kiện cấp/gia hạn/thu hồi/verify certificate, xét duyệt danh tính và trạng thái CA; không lưu claims, evidence reference, PEM hoặc secret.

Retry cấp/gia hạn lưu đúng request đã ký và idempotency token trong sessionStorage theo user, gồm bằng chứng public và không chứa private key. Sau mất response hoặc reload, chọn gửi lại yêu cầu đang chờ để đối chiếu bản ghi đã commit.

Các lệnh sau chạy trong WSL từ thư mục project:

```bash
# Nâng database đã có: backup trước, upgrade, đối chiếu mọi bảng cũ và integrity.
venv-wsl/bin/python scripts/upgrade_pki_database.py

# Kiểm tra bản sao encrypted key/cert trong thư mục tạm, không cấp certificate.
venv-wsl/bin/python scripts/verify_ca_backup.py

# Kiểm thử đầy đủ trên bản sao source được đối chiếu SHA-256 trong filesystem Linux.
venv-wsl/bin/python scripts/run_linux_tests.py tests -q

# Chạy backend thường bằng .env (khởi động lại để nạp cấu hình mới).
venv-wsl/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Migration b0 mở constraint cho v1/v2 và giữ retention guards. Downgrade b0 bị chặn khi đã có v2 signature, binding hoặc identity review; chỉ có thể downgrade database chưa phát sinh các bằng chứng này. Luôn giữ backup và dừng các writer trước khi phục hồi database.

Kiểm tra recovery CA cục bộ đã đạt với đúng public fingerprint ở phần cấu hình. Việc này xác nhận phục hồi từ bản sao encrypted key/cert bằng password source hiện có. Người vận hành vẫn cần giữ backup encrypted key và password theo hai vị trí lưu trữ được quản lý độc lập, phù hợp hạ tầng thực tế.
