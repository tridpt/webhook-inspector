# 📖 Hướng Dẫn Sử Dụng Toàn Tập — NetPulse (8 Vũ Khí Chủ Lực)

**NetPulse** là bộ công cụ chạy cục bộ giúp bạn **bắt gói tin HTTP/Webhook thời gian thực**, **bật Public Tunnel 1-click nhận Webhook từ Internet**, **dò API trang web bằng trình duyệt ngầm (Headless Chrome/Edge)**, **giải mã & giả mạo JWT (`alg:none` / dò khóa yếu)**, **so sánh Diff 2 gói tin**, **chỉnh sửa bắn lại request (Replay)** và **kiểm thử lỗ hổng API (Fuzzer)**.

---

## 1. Khởi động ứng dụng

### Cách 1: Chạy 1-click (Khuyên dùng trên Windows)
Nháy đúp vào file **[start.bat](file:///d:/AI_App/webhook-inspector/start.bat)**.
Ứng dụng tự động bật server tại cổng `4080` và mở trình duyệt vào:
👉 **http://localhost:4080**

### Cách 2: Chạy bằng Terminal / PowerShell
```powershell
cd D:\AI_App\webhook-inspector
node server.js
```

---

## 2. Chi tiết 8 Vũ Khí Chủ Lực

### Vũ khí 1: 📡 Bắt Gói Tin Webhook & Xuất File Postman
- Mọi HTTP Request (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`) gửi tới `http://localhost:4080/hook/<slug>` đều được bắt và hiển thị tức thì.
- **Test nhanh không cần code:** Bấm các nút **`💳 Thanh toán (JWT + HMAC)`**, **`🤖 Telegram Bot`** hoặc **`⚠️ Payload Nghi vấn`** trên thanh trên cùng.
- **📦 Xuất Postman Collection:** Bấm nút **`📦 Postman`** ở cột bên trái để tải toàn bộ danh sách gói tin ra file `.postman_collection.json` (chuẩn v2.1).

### Vũ khí 2: 🔓 Giải Mã Tự Động (JWT, Base64, Hex & Chữ Ký HMAC)
Khi bấm chọn 1 gói tin, khung bên phải có 5 tab mổ xẻ:
1. **🔍 Giải Mã & Tổng Quan:** Tự động quét Header, Query, Body để bung nội dung **JWT** (báo luôn còn hạn hay hết hạn), **Basic Auth** và chuỗi **Base64** ẩn.
2. **📋 Headers & Query:** Xem toàn bộ tham số URL và HTTP Headers.
3. **📦 Body & Hex Dump:** Xem JSON căn lề đẹp song song với bảng mã **Hex + ASCII (512 bytes đầu)**.
4. **🔐 Kiểm Tra Chữ Ký HMAC:** Nhập Secret Key (VietQR, SePay, Casso, Stripe, GitHub, Telegram...) để đối chiếu chữ ký hoặc tính mã băm `HMAC-SHA256 / SHA1 / SHA512`.
5. **💻 Xuất Code:** Chuyển gói tin thành lệnh **cURL**, **PowerShell**, **Python (`requests`)** hoặc **JS (`fetch`)**.

### Vũ khí 3: 🔁 Replay Studio + 📥 cURL + 🌐 Biến Môi Trường + ✅ Assertions + 🛡️ CORS
- **📥 Dán lệnh cURL từ Chrome F12:** Dán lệnh `Copy as cURL (bash / cmd)` từ trình duyệt vào Replay Studio hoặc API Fuzzer — hệ thống tự động tách Method, URL, Headers/Cookies và Body.
- **🌐 Quản lý Biến Môi Trường (`{{BASE_URL}}`, `{{API_TOKEN}}`):** Định nghĩa các biến dùng chung cho cả Replay Studio và API Fuzzer để đổi nhanh giữa môi trường `Local`, `Staging`, `Production`.
- **✅ Kiểm Chứng Phản Hồi Tự Động (API Assertions — PASS/FAIL):** Đặt điều kiện kiểm tra phản hồi (`status == 200`, `durationMs < 2000`, `json.success == true`, `body contains ok`) để tự động chấm **PASS / FAIL** mỗi lần bắn.
- **🚀 Bắn Request, 📜 Lịch sử Replay & 🛡️ Quét Bảo Mật CORS:** Bắn trực tiếp từ nhân Node.js, lưu lịch sử để ghim `⚖️ A / ⚖️ B` sang **Diff Viewer**, và chấm điểm an toàn CORS/Security Headers (A–F).

### Vũ khí 4: ⚡ Quét Lỗ Hổng & Kiểm Thử Biên (API Fuzzer)
- Đặt từ khóa **`{{FUZZ}}`** vào vị trí muốn thử nghiệm (trên URL, trong Header, hoặc trong Body JSON).
- Chọn bộ mẫu Payload có sẵn (*Boundary số âm/tràn số*, *SQLi/NoSQLi*, *XSS/SSTI*, *IDOR 1..15*) rồi bấm **`⚡ Chạy Fuzzing & Phân Tích Dị Thường`**.
- Hệ thống tự đo **Baseline** trước, sau đó bắn đa luồng và **tự động tô đỏ các phản hồi bất thường** (khác mã HTTP, lỗi 5xx, lệch kích thước, phản hồi chậm, rò rỉ lỗi nhạy cảm).

### Vũ khí 5: 🕵️‍♂️ Dò API Trang Web + Bắt Sống Bằng Trình Duyệt Ngầm (Headless Chrome/Edge)
- Mở tab **`🕵️‍♂️ Dò API Trang Web`**, dán link trang web bất kỳ và tích chọn **`🌐 Bắt sống XHR/Fetch bằng Trình duyệt ngầm (Chrome/Edge)`**.
- Hệ thống đồng thời:
  1. Mở Chrome/Edge chạy ngầm qua DevTools Protocol (CDP), tự cuộn trang để kích hoạt và **bắt sống 100% các request `XHR / Fetch` thực tế kèm đầy đủ Header & Token thật**.
  2. Tải mã nguồn HTML + các file `.js` bundle để quét toàn bộ `fetch()`, `axios`, `/api/v1/...`, `/graphql`, `OpenAPI/Swagger` và biến `NEXT_PUBLIC_* / VITE_*`.
- Bấm **`🚀 Gọi thử`** để xem JSON ngay tại chỗ, **`🔁 Replay`** để nạp kèm cả Header/Token thật sang Replay, hoặc **`📦 Xuất Postman (.json)`**.

### Vũ khí 6: 🔐 JWT Studio (Chỉnh Sửa, Giả Mạo `alg:none` & Dò Secret Yếu)
- Bấm **`🔐 Mở trong JWT Studio`** trên bất kỳ thẻ JWT nào bắt được (hoặc vào thẳng tab **`🔐 JWT Studio`**):
  - **Chỉnh sửa nhanh:** Bấm **`👑 role=admin`** để nâng quyền trong Payload hoặc **`⏰ +24h exp`** để gia hạn token.
  - **Ký mới hoặc Tấn công `alg: none`:** Ký lại bằng HMAC (`HS256/384/512`) hoặc tạo token không chữ ký (`alg: none`), sau đó bấm **`🔁 Gắn Token Này Sang Replay Studio`**.
  - **🔥 Dò Tìm Secret Key Yếu:** Tự động đối chiếu chữ ký JWT với hơn 30 khóa mặc định phổ biến + danh sách từ khóa riêng của bạn.

### Vũ khí 7: ⚖️ So Sánh 2 Gói Tin (Side-by-Side Diff Viewer)
- Trong màn hình Bắt Gói Tin, bấm **`⚖️ Ghim làm Gói A`** ở gói thứ nhất, sau đó chọn gói thứ hai và bấm **`⚖️ So sánh với A (Gói B)`** (hoặc chọn trực tiếp ở tab **`⚖️ So Sánh Gói Tin (Diff)`**).
- Tự động đối chiếu: **Chênh lệch thời gian/kích thước**, **Các trường JSON bị đổi giá trị (`A → B`)**, **So sánh Headers/Query**, và **Line-by-Line Body Diff** (xanh lá `+` thêm mới, đỏ `-` bị xóa).

### Vũ khí 8: 🌍 Bật Public Tunnel 1-Click, 🔒 Luật HMAC 401, 🔔 Cảnh Báo Telegram/Discord & 💾 Lưu Trữ Bền Vững
- **🌍 Public Tunnel 1-Click:** Ngay góc phải thanh *Endpoint đang chọn*, chọn **`Ngrok`** hoặc **`localhost.run (SSH miễn phí)`** rồi bấm **`🌍 Bật Public Tunnel`**. Hệ thống cấp ngay link `https://...` công khai để nhận Webhook thật từ Internet mà không cần mở Terminal!
- **🔒 Luật điều kiện HMAC (HTTP 401):** Tích chọn *"Tự động từ chối (trả về HTTP 401) nếu gói tin thiếu hoặc sai chữ ký HMAC"* để kiểm thử luồng xác thực chữ ký nghiêm ngặt.
- **🔔 Cảnh báo về Telegram Bot / Discord Webhook:** Tự động đẩy thông báo tóm tắt về Telegram/Discord khi Endpoint nhận gói tin mới (hoặc chỉ khi phát hiện gói tin dị thường / sai chữ ký HMAC).
- **💾 Lưu trữ bền vững (`data/store.json`) & Xuất/Nhập Backup:** Tự động lưu toàn bộ cấu hình và lịch sử xuống ổ cứng, kèm nút **`📥 Xuất Backup (.json)` / `📤 Nhập Backup`**.
