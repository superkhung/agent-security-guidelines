# Playbook 01 · Agent bị prompt injection và có dấu hiệu gửi dữ liệu ra ngoài

**Control liên quan:** NET-01, NET-02, NET-03, NET-06, ISO-02, ISO-03, OBS-01, OBS-03, OBS-04, OBS-05, CRED-01, CRED-03, MEM-01, MEM-02, MEM-05
**Kẻ tấn công:** K1 (Mục 1.2)
**Cập nhật lần cuối:** `<ngày>` · **Người sở hữu:** `<tên>`

## Kích hoạt khi

Một trong các tín hiệu sau, từ rule OBS-03 hoặc từ người dùng báo:

- Số lần egress bị chặn từ một phiên agent tăng đột biến, nhất là tới domain mới đăng ký hoặc IP trần.
- Tham số của tool mạng (HTTP, tạo issue, gửi tin nhắn) chứa chuỗi mã hóa dài (base64, hex) hoặc nội dung trông như key.
- Vi phạm sandbox: phiên agent cố đọc `~/.ssh`, `~/.aws`, file `.env` ngoài workspace, hoặc cố kết nối tới socket của SSH agent.
- Truy vấn DNS với hostname dài bất thường, hoặc nhiều subdomain khác nhau trên cùng một suffix.
- Output của agent chứa ảnh hoặc link markdown trỏ tới domain lạ, có query string dài.
- Người dùng báo agent "tự làm việc không được yêu cầu", đặc biệt sau khi đọc một trang web, issue, email hoặc file từ bên ngoài.

Một tín hiệu đơn lẻ có thể là báo động giả. Hai tín hiệu trong cùng một phiên thì mở playbook.

## Vai trò

| Vai | Người | Dự phòng |
| :--- | :--- | :--- |
| Chỉ huy sự cố | `<tên>` | `<tên>` |
| Kỹ thuật (nền tảng agent) | `<tên>` | `<tên>` |
| Kỹ thuật (mạng, proxy) | `<tên>` | `<tên>` |
| Liên lạc | `<tên>` | `<tên>` |
| Chủ sở hữu nghiệp vụ của use case | `<tên theo use case>` | |

## Ngăn chặn · 15 phút đầu

1. **Đóng băng phiên, chưa giết.** Đóng băng cả nhóm tiến trình của phiên (Linux: ghi `1` vào `cgroup.freeze` của cgroup chứa phiên; container: `docker pause` hoặc tương đương; macOS: `kill -STOP -<pgid>`, có race khi tiến trình con fork kịp, xem OBS-05; Windows: `pssuspend` của Sysinternals). Trong lúc đóng băng, chụp danh sách kết nối và file đang mở của mọi tiến trình trong nhóm (`ss -tanp`; `lsof -p "$(paste -sd, <cgroup>/cgroup.procs)"`). Nếu có quy trình CRIU đã thử trước, chụp trạng thái bộ nhớ. Chi tiết ở OBS-05.
2. **Chặn đích ra ở proxy.** Thêm đích nghi ngờ vào denylist ở proxy egress, và kiểm cùng lúc log DNS để biết dữ liệu đã đi qua DNS hay chưa.
3. **Sao lưu bằng chứng** ra nơi lưu cách ly: workspace, transcript của phiên, log tool call của phiên (OBS-01), log proxy và DNS trong cửa sổ `<N giờ>` trước tín hiệu đầu tiên.
4. **Dừng hẳn.** Giết cả cây tiến trình (Linux: `cgroup.kill`, dùng được cả khi cgroup đang bị đóng băng; container: `docker kill`, thử trước trong diễn tập với container đang pause; Windows: Job Object; Kubernetes: xóa pod sau khi đã sao lưu). Thu hồi mọi lease và phiên phê duyệt đang mở của người dùng đó (OBS-04).
5. **Thu hồi credential trong tầm với.** Liệt kê mọi credential mà phiên đã dùng hoặc có thể đã đọc. Xoay chúng, không chỉ vô hiệu hóa phiên. Nhớ rằng access token đã phát vẫn sống tới lúc hết hạn (CRED-03). Nếu có dấu hiệu credential đã rời khỏi máy, chuyển sang [Playbook 03](03-credential-bi-lo.md) cho phần này.
6. **Tìm nguồn chỉ thị và cô lập nó.** Xác định nội dung bên ngoài mà agent đọc ngay trước hành vi lạ (trang web, issue, email, file, kết quả tool). Nếu nguồn nằm trong hệ thống của mình (issue, wiki, repo chung, kho RAG), gỡ hoặc khóa nó để agent khác không đọc phải.

## Điều tra

| Câu hỏi | Nguồn trả lời |
| :--- | :--- |
| Chỉ thị độc đến từ đâu, agent đọc nó lúc nào? | Transcript của phiên; log tool call (tool đọc web, đọc file, đọc issue) |
| Phiên đã đọc những dữ liệu gì? Có dữ liệu nhạy cảm (cạnh A) không? | Log tool call; log vi phạm sandbox; log truy cập của hệ thống nguồn |
| Có dữ liệu nào đã ra ngoài không? Qua kênh nào? | Log proxy (cả kết nối được phép), log DNS, log của các đích ghi được như GitHub, Slack, email (NET-03); log của trình duyệt hoặc giao diện hiển thị output (NET-06) |
| Chỉ thị có được ghi vào memory dài hạn, file hướng dẫn (`AGENTS.md`, `CLAUDE.md`), hoặc cấu hình agent không? | Diff của workspace và repo; bản ghi memory có nguồn gốc là phiên này (MEM-01) |
| Agent có sinh tiến trình nền, sửa cấu hình shell, cài persistence không? | Snapshot filesystem; danh sách tiến trình lúc đóng băng |
| Những phiên hoặc người dùng khác có đọc cùng nguồn không? | Log tool call toàn tổ chức, lọc theo URL, issue hoặc file nguồn |

Câu hỏi thứ ba quyết định phần lớn phần Báo cáo, liên lạc, quyết định nghiệp vụ. Nếu không trả lời được vì thiếu log, ghi điều đó thành kết luận chứ không suy đoán theo hướng lạc quan.

## Khắc phục và phục hồi

Agent của người dùng này, hoặc use case này, chỉ chạy lại khi:

- Nguồn chỉ thị đã bị gỡ hoặc đã được đánh dấu là không tin cậy.
- Mọi credential trong tầm với đã được xoay.
- Memory và file hướng dẫn đã được rà và dọn những gì phiên này ghi vào (MEM-02, MEM-05).
- Workspace được dựng lại từ nguồn sạch, không dùng lại workspace của phiên sự cố.
- Kênh ra mà dữ liệu đã đi qua (nếu có) đã bị đóng, hoặc đã có quyết định chấp nhận rủi ro ghi thành văn bản.

## Báo cáo, liên lạc, quyết định nghiệp vụ

| Việc | Ai | Hạn |
| :--- | :--- | :--- |
| Báo lên theo quy trình sự cố chung | Chỉ huy sự cố | `<ví dụ: trong 1 giờ>` |
| Báo chủ sở hữu nghiệp vụ của use case | Liên lạc | Ngay khi xác nhận có dữ liệu bị đọc |
| Đánh giá dữ liệu bị lộ có chứa dữ liệu cá nhân hay dữ liệu khách hàng không | Kỹ thuật cùng đầu mối bảo vệ dữ liệu | `<hạn>` |
| Quyết định có phải thông báo cho cơ quan quản lý, khách hàng, đối tác không | Chủ sở hữu nghiệp vụ, pháp chế | Theo thời hạn pháp chế đã xác nhận: `<hạn>` |
| Quyết định tạm dừng use case, hoặc toàn bộ agent cùng loại | Chủ sở hữu nghiệp vụ cùng chỉ huy sự cố | `<hạn>` |
| Báo nhà cung cấp client hoặc MCP server nếu hành vi cho thấy lỗ hổng của sản phẩm | Kỹ thuật | Theo chính sách công bố lỗ hổng của nhà cung cấp |

Đội security không quyết định thay nghiệp vụ việc có thông báo ra ngoài hay không. Việc của đội security là đưa ra sự thật đã xác minh và chỗ nào còn chưa biết.

## Sau sự cố

Trả lời bằng văn bản trong vòng `<N ngày>`:

- Cạnh nào của bộ ba nguy hiểm (Mục 1.3) đã không bị cắt, và use case có còn đúng cấp ASAL không?
- Chỉ thị đi qua được những control nào mà lẽ ra phải chặn? Phép kiểm chứng của những control đó đã chạy và đạt chưa, và vì sao nó không bao được đường đi này?
- Có cần thêm rule phát hiện ở OBS-03 cho dấu hiệu lần này không?
- Mẫu chỉ thị (đã ẩn thông tin nhạy cảm) có nên được đưa vào bộ test red team nội bộ không? Nếu chỉ thị viết bằng tiếng Việt, cân nhắc đóng góp nó cho bộ test cộng đồng (Mục 5.2).

## Diễn tập

**Bối cảnh.** Một dev dùng coding agent sửa repo nội bộ. Agent có MCP server GitHub đọc và comment được issue. Egress đi qua proxy có allowlist, trong đó có `github.com`.

| Mốc | Inject |
| :--- | :--- |
| T+0 | SIEM báo: phiên agent của dev A bị chặn egress 14 lần trong 3 phút tới một domain đăng ký hôm qua. |
| T+10 phút | Log tool call cho thấy ngay trước đó agent đọc issue #482 của một repo public mà đội đang theo dõi. Nội dung issue có một đoạn bị ẩn bằng HTML comment. |
| T+20 phút | Kỹ thuật phát hiện agent đã tạo một comment trên một issue ở repo public khác, nội dung là một chuỗi base64 dài. Kết nối tới `github.com` được allowlist nên không bị chặn. |
| T+35 phút | Giải mã chuỗi base64: là nội dung file `.env` của dự án, có một token truy cập database staging. |
| T+50 phút | Dev B báo agent của họ "cũng làm gì đó lạ" hôm qua. Họ cũng theo dõi repo đó. |

**Câu hỏi thảo luận.**

- Ở T+0, ai nhận cảnh báo, và người đó có quyền đóng băng phiên của dev A không?
- Vì sao egress allowlist không chặn được bước ở T+20? Control nào lẽ ra phải chặn (NET-03, cách cắt cạnh C ở ví dụ Mục 3.1)?
- File `.env` có token nằm trong workspace nghĩa là CRED-01 đã không đạt. Phép kiểm chứng của CRED-01 lần gần nhất chạy lúc nào?
- Comment chứa dữ liệu đang nằm công khai trên GitHub. Ai quyết định yêu cầu gỡ, và gỡ có đủ không?
- Với dev B, sự cố hôm qua đã qua khỏi cửa sổ log của proxy chưa? Log được giữ bao lâu?

**Tiêu chí đạt.** Nhóm trả lời được, không cần tra cứu thêm: ai đóng băng phiên, bằng lệnh gì; ai xoay token database, trong bao lâu; ai quyết định việc thông báo ra ngoài. Nếu có môi trường thử, đo được thời gian từ T+0 tới lúc phiên bị đóng băng.
