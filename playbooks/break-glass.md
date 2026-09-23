# Break-glass · Mở quyền khẩn cấp có kiểm soát

**Control liên quan:** OBS-06, OBS-01, OBS-02, ACT-07, CRED-03
**Cập nhật lần cuối:** `<ngày>` · **Người sở hữu:** `<tên>`

Break-glass là cách mở một quyền mà bình thường bị chặn, khi việc không mở gây thiệt hại lớn hơn. Với hệ thống agent, hai tình huống hay gặp nhất:

- Trong sự cố, người ứng phó cần một quyền mà control của agent đang chặn: tắt tạm một policy ở gateway, mở một đích egress, truy cập trực tiếp môi trường mà agent chỉ được đề xuất qua ACT-07.
- Quy trình duyệt bên ngoài (review, change management, maker-checker) không có người duyệt kịp, và hành động không thể chờ.

Break-glass không dành cho agent. Agent không bao giờ là bên yêu cầu hay bên được cấp quyền break-glass.

## Nguyên tắc

- **Hai người.** Một người yêu cầu, một người khác duyệt. Người duyệt không được là người yêu cầu, và không được là người vận hành agent đang liên quan tới sự cố.
- **Có hạn.** Quyền tự hết hạn sau `<ví dụ: 60 phút>`. Gia hạn là một lần break-glass mới, có duyệt mới.
- **Hẹp.** Mở đúng quyền cần cho đúng việc, không mở quyền admin chung.
- **Ghi đủ.** Mọi hành động trong thời gian break-glass được ghi log với danh tính người thực hiện, không phải danh tính dùng chung. Ở ASAL-3, log này đi vào chuỗi chống sửa (OBS-02).
- **Tự đóng.** Việc đóng không phụ thuộc vào trí nhớ của ai.

## Chuẩn bị trước

| Việc | Chi tiết của tổ chức |
| :--- | :--- |
| Danh sách quyền có thể mở qua break-glass | `<liệt kê: tắt policy X ở gateway, mở egress tạm, role khẩn cấp trên cloud...>` |
| Ai được yêu cầu | `<vai trò>` |
| Ai được duyệt | `<vai trò; ít nhất hai người để luôn có người trực>` |
| Cơ chế cấp | `<ví dụ: role khẩn cấp có TTL cấp qua broker (CRED-03); công cụ quản lý truy cập đặc quyền; tài khoản khẩn cấp niêm phong>` |
| Nơi ghi log | `<hệ thống log tập trung, tách khỏi máy của người thực hiện>` |
| Kênh báo khi break-glass được dùng | `<kênh có người đọc, ví dụ kênh security và quản lý trực tiếp>` |

Tài khoản khẩn cấp niêm phong (mật khẩu hoặc khóa cất riêng, chia cho nhiều người giữ) chỉ là phương án cuối, khi chính hệ thống cấp quyền bị sự cố. Kiểm định kỳ rằng nó còn dùng được, và xoay sau mỗi lần dùng.

## Quy trình

1. **Yêu cầu.** Người yêu cầu ghi: quyền cần mở, lý do, thời hạn, sự cố hoặc sự việc liên quan.
2. **Duyệt.** Người duyệt kiểm lý do và phạm vi, rồi duyệt trong công cụ cấp quyền. Duyệt bằng lời qua điện thoại chỉ chấp nhận khi công cụ không dùng được, và phải được ghi lại ngay sau đó.
3. **Cấp.** Quyền được cấp cho danh tính cá nhân của người yêu cầu, có TTL.
4. **Báo.** Thông báo tự động tới kênh đã định ngay khi quyền được cấp.
5. **Dùng.** Chỉ làm đúng việc đã ghi. Việc phát sinh ngoài phạm vi là một yêu cầu mới.
6. **Đóng.** Quyền tự hết hạn. Nếu xong việc sớm, người yêu cầu chủ động đóng.
7. **Rà sau.** Trong `<ví dụ: hai ngày làm việc>`, một người không tham gia rà log của lần break-glass: mọi hành động có nằm trong phạm vi đã ghi không, quyền đã thật sự bị thu hồi chưa. Mọi policy hoặc control đã tắt tạm đã được bật lại chưa, kiểm bằng phép kiểm chứng của control đó chứ không chỉ bằng cấu hình.

Bước 7 là bước hay bị quên nhất. Control bị tắt tạm trong sự cố rồi không ai bật lại là cách phổ biến để một tổ chức mất control mà không biết.

## Kiểm chứng

- Thử yêu cầu và tự duyệt chính yêu cầu của mình: phải bị từ chối.
- Cấp một quyền break-glass có TTL ngắn trong môi trường thử, đợi hết hạn, thử dùng: phải bị từ chối.
- Kiểm kênh thông báo đã nhận được sự kiện.
- Chạy lại một lần trong mỗi buổi diễn tập của Playbook 01 đến 03.
