# Playbook sự cố agent

Thư mục này là phần đi kèm của control OBS-06 trong *Hướng dẫn kỹ thuật an ninh cho AI Agent*. Nó được tách khỏi guideline vì playbook thay đổi nhanh hơn, và mỗi tổ chức phải sửa theo hệ thống của mình trước khi dùng.

| File | Kịch bản |
| :--- | :--- |
| [01-prompt-injection-exfil.md](01-prompt-injection-exfil.md) | Agent bị prompt injection và có dấu hiệu gửi dữ liệu ra ngoài |
| [02-mcp-server-doc-hai.md](02-mcp-server-doc-hai.md) | MCP server bị phát hiện độc, hoặc bị rug pull |
| [03-credential-bi-lo.md](03-credential-bi-lo.md) | Credential mà agent dùng bị lộ |
| [break-glass.md](break-glass.md) | Mở quyền khẩn cấp có kiểm soát |

## Trước khi dùng

Playbook ở đây là khung, không phải bản dùng được ngay. Mọi chỗ ghi `<...>` là chỗ tổ chức phải điền. Một playbook còn chỗ `<...>` chưa điền thì chưa được tính là đạt OBS-06.

Những thứ cần có sẵn trước khi viết lại playbook cho tổ chức mình:

- Danh mục agent và MCP server (SC-01), để biết sự cố chạm tới những đâu.
- Cách dừng agent đã diễn tập ít nhất một lần, với thời gian dừng đo được (OBS-04).
- Nơi log tool call tập trung (OBS-01), và người có quyền đọc.
- Quy trình ứng phó sự cố chung của tổ chức. Playbook agent gắn vào quy trình đó, không thay nó.
- Thời hạn thông báo sự cố và danh sách cơ quan hoặc khách hàng phải được báo, đã được pháp chế xác nhận. Playbook không ghi sẵn nghĩa vụ pháp lý vì nó khác nhau theo ngành và thay đổi theo thời gian.

## Cấu trúc chung của mỗi playbook

Mỗi playbook (trừ `break-glass.md`, là một quy trình và được diễn tập kèm Playbook 01 đến 03) đi theo cùng một thứ tự:

1. **Kích hoạt khi.** Tín hiệu nào mở playbook, gắn với rule phát hiện ở OBS-03.
2. **Vai trò.** Ai làm gì. Một người chỉ huy sự cố, một người kỹ thuật, một người liên lạc; ở tổ chức nhỏ một người có thể kiêm, nhưng phải ghi rõ ai kiêm vai nào.
3. **Ngăn chặn.** Việc làm trong mười lăm phút đầu. Khi có phiên agent hoặc tiến trình đang chạy, thứ tự là đóng băng và giữ bằng chứng (OBS-05), rồi dừng (OBS-04), rồi thu hồi. Không xóa gì trước khi đã giữ bằng chứng.
4. **Điều tra.** Câu hỏi cần trả lời, và log nào trả lời câu đó.
5. **Khắc phục và phục hồi.** Điều kiện để cho agent chạy lại.
6. **Báo cáo, liên lạc, quyết định nghiệp vụ.** Ai phải biết, trong bao lâu, và ai quyết định những việc không thuộc về kỹ thuật.
7. **Sau sự cố.** Control nào đã không chặn được, và vì sao.
8. **Diễn tập.** Kịch bản tabletop, câu hỏi thảo luận và tiêu chí đạt.

Bước 6 là bước hay bị bỏ nhất. Playbook chỉ có bước kỹ thuật là lỗi đã nêu ở OBS-06.

## Diễn tập

OBS-06 yêu cầu tabletop exercise ít nhất mỗi năm một lần. Mỗi playbook có một kịch bản diễn tập ở cuối. Cách chạy gợi ý:

- Thời lượng khoảng chín mươi phút cho một kịch bản. Người điều phối đọc từng mốc (inject) theo thời gian, nhóm trả lời sẽ làm gì, ai làm, dùng công cụ gì.
- Người điều phối không phải người trong nhóm ứng phó.
- Có mặt ít nhất: chủ sở hữu nền tảng agent, đầu mối security, một người phía nghiệp vụ của use case bị ảnh hưởng, và người liên lạc.
- Ghi lại mọi chỗ nhóm trả lời "không biết", "phải hỏi", hoặc "chưa có quyền". Đó là kết quả chính của buổi diễn tập, không phải thất bại.
- Nếu tổ chức có môi trường thử, chạy thật bước ngăn chặn (đóng băng, dừng, thu hồi) và đo thời gian. Con số đo được ghi vào chỉ số "Thời gian dừng thực tế đo được trong diễn tập" ở Mục 3.6.

Sau mỗi buổi, sửa playbook trong vòng hai tuần. Một playbook không được sửa sau diễn tập thường là dấu hiệu buổi diễn tập đã không tìm ra gì, hoặc đã tìm ra nhưng không ai chịu trách nhiệm sửa.

## Đóng góp

Kịch bản mới, hoặc kinh nghiệm từ sự cố thật (đã ẩn danh), gửi qua Pull Request. Một kịch bản mới nên có đủ tám phần ở trên và chỉ rõ control nào của guideline liên quan.
