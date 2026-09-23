# Playbook 02 · MCP server bị phát hiện độc, hoặc bị rug pull

**Control liên quan:** SC-01, SC-02, SC-03, SC-04, SC-05, SC-06, ISO-02, ISO-04, NET-01, CRED-01, OBS-01, OBS-03, OBS-04, OBS-05
**Kẻ tấn công:** K2 (Mục 1.2)
**Cập nhật lần cuối:** `<ngày>` · **Người sở hữu:** `<tên>`

## Kích hoạt khi

- Fingerprint của một tool đã duyệt thay đổi (SC-05): mô tả, schema, `annotations` hoặc tên tool khác với lúc duyệt.
- Một tool mới xuất hiện trên server đã duyệt mà chưa qua duyệt.
- Công cụ quét (SC-04) báo tool poisoning hoặc tool shadowing trên một server đang được dùng.
- Cảnh báo bên ngoài: advisory bảo mật, CVE, bài công bố, hoặc package của server bị gỡ khỏi registry công cộng vì độc.
- Cấu hình MCP cấp project trong một repo bị sửa để trỏ tới lệnh hoặc server khác (kiểu MCPoison, CVE-2025-54136).
- Tiến trình của một MCP server có hành vi lạ: kết nối tới đích ngoài allowlist, đọc file ngoài phạm vi, sinh tiến trình con không mong đợi.

## Vai trò

| Vai | Người | Dự phòng |
| :--- | :--- | :--- |
| Chỉ huy sự cố | `<tên>` | `<tên>` |
| Người sở hữu danh mục agent/MCP (SC-01) | `<tên>` | `<tên>` |
| Kỹ thuật (gateway, endpoint management) | `<tên>` | `<tên>` |
| Liên lạc | `<tên>` | `<tên>` |

## Ngăn chặn · 15 phút đầu

1. **Xác định phạm vi từ danh mục.** Tra danh mục (SC-01): server này, ở phiên bản nào, đang được cấu hình trên những máy nào, những runner nào, những repo nào. Nếu không tra được trong vài phút, đó là một phát hiện của sự cố và cần ghi lại.
2. **Giữ bằng chứng trước khi gỡ bất cứ thứ gì.** Lưu bản của server đang chạy (image digest, package tarball kèm lockfile, hoặc snapshot mã nguồn), kết quả `tools/list` hiện tại, và fingerprint đã lưu lúc duyệt. So sánh hai bản fingerprint cho biết chính xác thứ gì đã đổi. Trên máy có tiến trình server local đang chạy, đóng băng nó theo bước 1 của [Playbook 01](01-prompt-injection-exfil.md) trước khi dừng (OBS-05).
3. **Chặn server ở điểm tập trung.** Tùy thứ tổ chức có: gỡ khỏi danh sách được duyệt trong managed policy của client (SC-02), chặn tại gateway MCP, hoặc đánh dấu quarantine image trong registry nội bộ (SC-06), không xóa. Chặn theo danh tính server (digest image, URL chuẩn hóa), không chỉ theo tên, vì nhiều server khác nhau có thể cùng tên.
4. **Với server remote,** chặn đích của nó ở proxy egress.
5. **Dừng các phiên agent đang dùng server** (OBS-04). Với phiên đã gọi tool của server sau thời điểm nghi ngờ, xử lý theo bước đóng băng của [Playbook 01](01-prompt-injection-exfil.md).
6. **Thu hồi credential mà server giữ.** Server chạy local có quyền của user và có thể đã đọc mọi thứ user đọc được nếu không chạy trong sandbox riêng (ISO-02). Liệt kê credential server được cấp chính thức và credential nó có thể đã chạm tới, rồi xoay. Phần này đi theo [Playbook 03](03-credential-bi-lo.md).

## Điều tra

| Câu hỏi | Nguồn trả lời |
| :--- | :--- |
| Thứ gì đã đổi, và đổi từ lúc nào? | So sánh fingerprint (SC-05); lịch sử phát hành của package; lịch sử commit của cấu hình MCP trong repo |
| Bản độc đã chạy trên những máy nào, trong khoảng thời gian nào? | Danh mục (SC-01); log khởi động server; log tool call (OBS-01) |
| Server có chạy trong sandbox riêng không, hay chạy thẳng dưới quyền user? | Cấu hình trên từng máy; log vi phạm sandbox nếu có |
| Server đã kết nối tới đâu? | Log proxy egress, log DNS, theo tiến trình hoặc container của server |
| Mô tả tool độc đã khiến mô hình làm gì với tool của server khác (tool shadowing)? | Log tool call của cùng các phiên, không chỉ tool của server này |
| Server được đưa vào bằng đường nào: người dùng tự cài, cấu hình project trong repo, hay registry nội bộ? | Danh mục; lịch sử của file cấu hình |
| Vì sao phiên bản mới chạy được? Có ghim phiên bản hay digest không? | Cấu hình; kết quả phép kiểm chứng của SC-03 lần gần nhất |

## Khắc phục và phục hồi

- Nếu cần dùng lại server: quay về bản đã duyệt trước đó, ghim theo digest (SC-03), và duyệt lại từ đầu theo SC-02 và SC-04 như một server mới.
- Nếu không tin được nhà phát hành nữa: gỡ khỏi danh sách duyệt, tìm thay thế, thông báo cho người dùng lý do.
- Dọn máy bị ảnh hưởng: xóa cài đặt, kiểm persistence (cấu hình shell, cấu hình của agent, tác vụ định kỳ, extension của IDE). Với máy mà server chạy không có sandbox và có dấu hiệu thực thi code độc, xử lý như máy bị chiếm theo quy trình sự cố endpoint chung, vượt khỏi phạm vi playbook này.
- Kiểm lại toàn bộ cấu hình MCP cấp project trong các repo chung, không chỉ repo có sự cố.

## Báo cáo, liên lạc, quyết định nghiệp vụ

| Việc | Ai | Hạn |
| :--- | :--- | :--- |
| Báo lên theo quy trình sự cố chung | Chỉ huy sự cố | `<hạn>` |
| Thông báo cho mọi người dùng có server trong cấu hình: gỡ gì, vì sao, dùng gì thay | Liên lạc cùng người sở hữu danh mục | `<ví dụ: trong 4 giờ>` |
| Đánh giá dữ liệu mà server có thể đã đọc có chứa dữ liệu cá nhân hay dữ liệu khách hàng không | Kỹ thuật cùng đầu mối bảo vệ dữ liệu | `<hạn>` |
| Quyết định có phải thông báo ra ngoài không | Chủ sở hữu nghiệp vụ các use case bị ảnh hưởng, pháp chế | Theo thời hạn pháp chế đã xác nhận: `<hạn>` |
| Báo nhà phát hành server, registry công cộng, hoặc cộng đồng nếu server độc có mặt công khai | Kỹ thuật | Sau khi đã giữ bằng chứng |

Báo ra cộng đồng giúp tổ chức khác, nhưng chỉ làm sau khi đã giữ bằng chứng và sau khi pháp chế đồng ý với nội dung công bố.

## Sau sự cố

- Danh mục có trả lời được câu hỏi phạm vi trong mười lăm phút không? Nếu không, SC-01 chưa thật sự đạt.
- Server được chạy lại bản mới mà không ai duyệt: SC-03 hay SC-05 là control đã hỏng?
- Server có quyền đọc những thứ nó không cần không? Có nên bắt buộc chạy MCP server local trong sandbox riêng cho mọi use case ở cấp này không?
- Tiêu chí duyệt ở SC-02 có cần thêm điều kiện về nhà phát hành không?

## Diễn tập

**Bối cảnh.** Tổ chức có 40 dev dùng coding agent. Một MCP server cộng đồng để đọc tài liệu API được dùng rộng rãi, cấu hình bằng `npx -y <package>` trong file cấu hình cấp project của repo template chung.

| Mốc | Inject |
| :--- | :--- |
| T+0 | Một advisory công khai cho biết tài khoản npm của tác giả package bị chiếm, bản phát hành đêm qua có mô tả tool chứa chỉ thị ẩn yêu cầu mô hình đọc `~/.aws/credentials` và đưa nội dung vào tham số của lần gọi tool tiếp theo. |
| T+15 phút | Người sở hữu danh mục tra được 23 máy có server trong cấu hình. Cấu hình dùng `npx -y` không kèm phiên bản, nên không biết máy nào đã chạy bản mới. |
| T+30 phút | Log gateway không có gì, vì server chạy local qua stdio, không đi qua gateway. |
| T+45 phút | Log proxy egress cho thấy 4 máy có kết nối tới một domain lạ từ tiến trình `node` trong đêm qua. Kết nối bị chặn vì domain không nằm trong allowlist. |
| T+60 phút | Một dev báo họ đã tắt proxy trên máy cá nhân từ tuần trước vì không cài được package. |

**Câu hỏi thảo luận.**

- Làm sao chặn server trên cả 23 máy trong vòng một giờ? Có managed policy của client không, hay phải nhắn từng người?
- Ở T+15, vì sao không biết máy nào đã chạy bản mới? Phép kiểm chứng của SC-03 và bước 2 của Phụ lục A có chạy trên repo template không?
- Ở T+45, egress chặn được kết nối. Nhưng chỉ thị yêu cầu đưa credential vào *tham số tool*, không phải kết nối trực tiếp. Tham số đó đi tới đâu, và log nào ghi lại nó?
- Ở T+60, máy không có proxy phải được coi là credential đã lộ. Ai quyết định xoay credential cho người đó, và có cần xoay cho cả 23 máy không?
- Cấu hình cấp project trong repo template đã được ai duyệt, và thay đổi trên nó có đi qua review không (SC-02)?

**Tiêu chí đạt.** Nhóm có được danh sách máy bị ảnh hưởng trong mười lăm phút, có cách chặn tập trung, và quyết định được phạm vi xoay credential trước T+90.
