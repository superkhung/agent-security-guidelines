# Playbook 03 · Credential mà agent dùng bị lộ

**Control liên quan:** CRED-01, CRED-02, CRED-03, RES-01, ACT-01, OBS-01, OBS-03, OBS-04, OBS-05, MA-02, MEM-05
**Kẻ tấn công:** K1, K2, K3 (Mục 1.2), tùy đường lộ
**Cập nhật lần cuối:** `<ngày>` · **Người sở hữu:** `<tên>`

Playbook này dùng cho mọi credential nằm trong tầm với của agent: API key của LLM provider, token của MCP server, credential cloud, token truy cập repo, credential database, và token mà agent nhận qua ủy quyền. Nó cũng là bước thu hồi credential được gọi từ [Playbook 01](01-prompt-injection-exfil.md) và [Playbook 02](02-mcp-server-doc-hai.md).

## Kích hoạt khi

- Credential xuất hiện ở nơi không nên có: trong tham số tool gửi ra ngoài, trong comment hay issue công khai, trong transcript hay log, trong commit.
- Công cụ quét secret (`gitleaks`, `trufflehog`, secret scanning của nền tảng mã nguồn) báo credential trong repo hoặc trong workspace của agent.
- Nhà cung cấp báo credential bị lộ công khai (nhiều nền tảng tự quét repo public và thông báo).
- Credential được dùng từ địa chỉ, vùng, user agent, hoặc vào thời điểm lạ, theo audit log của hệ thống đích.
- Chi phí LLM của một khóa tăng đột biến (RES-01).
- Playbook 01 hoặc 02 kết luận credential đã nằm trong tầm với của thành phần bị chiếm.

## Vai trò

| Vai | Người | Dự phòng |
| :--- | :--- | :--- |
| Chỉ huy sự cố | `<tên>` | `<tên>` |
| Người quản trị secret / IAM | `<tên>` | `<tên>` |
| Chủ sở hữu hệ thống mà credential truy cập | `<tên theo hệ thống>` | |
| Liên lạc | `<tên>` | `<tên>` |

## Ngăn chặn · 15 phút đầu

0. **Nếu credential lộ qua một phiên agent đang chạy,** đóng băng phiên đó theo bước 1 của [Playbook 01](01-prompt-injection-exfil.md) trước, rồi mới làm các bước dưới đây.
1. **Xác định credential và phạm vi của nó.** Loại gì, cấp cho danh tính nào (agent riêng theo CRED-02, hay của người dùng), scope gì, TTL bao lâu, có refresh token đi kèm không. Nếu credential là của người dùng chứ không phải của agent, phạm vi thiệt hại là toàn bộ quyền của người đó.
2. **Thu hồi và xoay, theo đúng thứ tự.** Tạo credential mới trước nếu hệ thống đang chạy cần nó, cập nhật nơi dùng hợp lệ (MCP server, gateway, broker), rồi thu hồi credential cũ. Với hệ thống không chịu được gián đoạn, quyết định chấp nhận gián đoạn thuộc về chủ sở hữu hệ thống, không thuộc về người xử lý sự cố, nhưng phải quyết định ngay.
3. **Thu hồi cả những thứ sinh ra từ credential đó.** Refresh token; session đang mở; access token đã phát (vẫn sống tới lúc hết hạn nếu hệ thống đích không kiểm lại trạng thái, xem CRED-03); token đã ủy quyền tiếp cho agent khác qua token exchange (MA-02); khóa ảo cấp từ khóa gốc ở gateway LLM. Nếu hệ thống hỗ trợ Shared Signals (CAEP, RISC), phát sự kiện thu hồi.
4. **Ghi lại thời điểm.** Thời điểm credential bắt đầu nằm ở nơi bị lộ (ước lượng sớm nhất), thời điểm phát hiện, và thời điểm thu hồi có hiệu lực thật (request dùng credential cũ bị từ chối). Khoảng giữa mốc đầu và mốc cuối là cửa sổ phải điều tra.
5. **Nếu credential bị đăng công khai,** yêu cầu gỡ nội dung sau khi đã thu hồi, không phải trước. Gỡ không thay được thu hồi, vì nội dung công khai thường bị thu thập trong vài phút.

## Điều tra

| Câu hỏi | Nguồn trả lời |
| :--- | :--- |
| Credential lộ qua đường nào? | Phát hiện ban đầu; log tool call (OBS-01); kết luận của Playbook 01 hoặc 02 nếu có |
| Vì sao agent chạm được credential này? | Nó nằm trong workspace, biến môi trường, hay được cấp chính thức? Kết quả phép kiểm chứng CRED-01 lần gần nhất |
| Credential đã được dùng làm gì trong cửa sổ điều tra? | Audit log của hệ thống đích, lọc theo credential hoặc danh tính; nếu CRED-02 đạt thì tách được hành động của agent khỏi hành động của người |
| Có hành động nào do bên thứ ba thực hiện bằng credential này không? | Audit log của hệ thống đích: địa chỉ nguồn, user agent, thời điểm, không khớp với hạ tầng của agent |
| Kẻ tấn công có dùng credential này để tạo credential khác, hay persistence không? | Audit log IAM: khóa mới, user mới, role mới, OAuth app mới, webhook mới, deploy key mới |
| Credential có trong transcript, log hay memory của agent không? | Tìm trong log tập trung, transcript, memory store; nếu có thì phải dọn cả ở đó (MEM-05) |

Câu hỏi thứ năm hay bị bỏ qua. Thu hồi credential gốc không có tác dụng với credential mà kẻ tấn công đã tự tạo thêm bằng nó.

## Khắc phục và phục hồi

- Thay credential tĩnh bằng credential ngắn hạn cấp qua broker nếu cấp ASAL của use case đòi hỏi (CRED-03 bắt buộc từ ASAL-3), hoặc ít nhất rút ngắn TTL.
- Nếu credential của người dùng đã nằm trong tầm với của agent, cấp danh tính riêng cho agent với scope tối thiểu (CRED-02).
- Dọn credential khỏi mọi bản sao: log, transcript, memory, bản sao lưu, lịch sử git (nếu đã commit, xóa khỏi lịch sử không đủ; credential vẫn phải được coi là đã lộ).
- Cho tool hoặc MCP server tự giữ credential thay vì đưa credential vào môi trường của agent (CRED-01).

## Báo cáo, liên lạc, quyết định nghiệp vụ

| Việc | Ai | Hạn |
| :--- | :--- | :--- |
| Báo lên theo quy trình sự cố chung | Chỉ huy sự cố | `<hạn>` |
| Báo chủ sở hữu hệ thống mà credential truy cập | Liên lạc | Ngay lập tức, trước cả bước thu hồi nếu thu hồi gây gián đoạn |
| Đánh giá có dữ liệu cá nhân hay dữ liệu khách hàng bị truy cập trong cửa sổ điều tra không | Chủ sở hữu hệ thống cùng đầu mối bảo vệ dữ liệu | `<hạn>` |
| Quyết định có phải thông báo ra ngoài không | Chủ sở hữu nghiệp vụ, pháp chế | Theo thời hạn pháp chế đã xác nhận: `<hạn>` |
| Nếu credential của nhà cung cấp (LLM provider, cloud): liên hệ nhà cung cấp về chi phí phát sinh và hoạt động lạ | Người sở hữu tài khoản | `<hạn>` |

## Sau sự cố

- Credential nằm trong tầm với của agent là CRED-01 đã không đạt, hoặc phép kiểm chứng của nó không bao được đường này. Đường nào?
- Thời gian từ lúc thu hồi tới lúc credential thật sự hết dùng được là bao lâu? So với mục tiêu đã cam kết ở OBS-04.
- Nếu không tách được hành động của agent khỏi hành động của người trong audit log, CRED-02 là việc cần làm tiếp.
- Rule phát hiện nào (OBS-03) lẽ ra đã báo sớm hơn?

## Diễn tập

**Bối cảnh.** Một agent nội bộ trả lời câu hỏi về hạ tầng, chạy trên runner CI, có quyền đọc cloud qua một access key tĩnh của một IAM user dùng chung với đội vận hành. Agent có tool đọc web.

| Mốc | Inject |
| :--- | :--- |
| T+0 | Nhà cung cấp cloud gửi email: access key `AKIA...` xuất hiện trong một gist công khai, được tạo 40 phút trước. |
| T+10 phút | Tra ra key thuộc IAM user dùng chung. Ba hệ thống tự động của đội vận hành dùng cùng key đó. Thu hồi key sẽ làm cả ba dừng. |
| T+25 phút | Audit log cloud cho thấy key được dùng từ một địa chỉ lạ, gọi `ListBuckets` rồi `CreateAccessKey` cho chính user đó. |
| T+40 phút | Log tool call của agent cho thấy agent đọc một trang tài liệu bên ngoài, rồi gọi tool tạo gist với nội dung chứa biến môi trường của runner. |
| T+60 phút | Đội vận hành hỏi có thể đợi tới cuối ca để xoay key cho ba hệ thống kia không. |

**Câu hỏi thảo luận.**

- Ở T+10, ai quyết định thu hồi key ngay và chấp nhận ba hệ thống dừng? Người đó có trong phòng không?
- Ở T+25, khóa mới do kẻ tấn công tạo cũng phải bị thu hồi. Có ai nhớ bước này nếu không có playbook không?
- Vì sao agent có tool tạo gist? Tool đó thuộc mức nào trong phân loại ở ACT-01?
- Biến môi trường của runner chứa key tĩnh: CRED-01 đã được kiểm chứng trên runner, hay chỉ trên máy dev?
- Câu trả lời cho T+60 là gì, và ai là người có quyền trả lời?
- Nhà cung cấp cloud thường tự gắn một policy cách ly lên key bị lộ khi gửi email báo. Policy cách ly đó có phải là thu hồi không, và nó có chặn được `CreateAccessKey` đã xảy ra trước đó không?

**Tiêu chí đạt.** Nhóm thu hồi được cả key gốc lẫn key do kẻ tấn công tạo trước T+30, có người có thẩm quyền quyết định về gián đoạn trong phòng, và xác định được cửa sổ điều tra.
