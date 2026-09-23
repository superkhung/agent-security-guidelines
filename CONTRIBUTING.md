# Góp ý và đóng góp

Tài liệu đang ở dạng public draft. Mọi góp ý đi qua Issue hoặc Pull Request trên repo này.

## Góp ý nào có giá trị nhất

1. Phản biện về threat model (Mục 1): kịch bản tấn công mà các control không bao được, hoặc chỗ tài liệu tuyên bố quá mức.
2. Độ khó và công sức thực tế (thang ở Mục 0.4) từ người đã triển khai control đó.
3. Công cụ còn thiếu, hoặc công cụ lấp được một khoảng trống ở Mục 5.2.
4. Kết quả chạy phép kiểm chứng của một control trên nền tảng cụ thể, nhất là khi phép kiểm chứng *không* đạt dù đã làm đúng hướng dẫn.

## Mở Issue

- Ghi mã control hoặc số mục ở đầu tiêu đề, ví dụ `[NET-03] Allowlist theo method không chặn được ...` hoặc `[3.5] Lộ trình thiếu ...`. Nhờ vậy góp ý gom được theo control.
- Nếu là nhận định về hành vi của một client, gateway hay MCP server, ghi phiên bản đã thử. Hành vi của các công cụ này đổi nhanh.
- Không đăng chi tiết khai thác một lỗ hổng chưa được vá của sản phẩm cụ thể. Báo cho nhà cung cấp trước.

## Gửi Pull Request

| Sửa gì | Ở đâu | Ghi chú |
| :--- | :--- | :--- |
| Nội dung guideline | `guideline/agent-security-guidelines.md` | Một PR cho một ý. Sửa thẻ control thì giữ đủ các trường theo Mục 0.3 |
| Công cụ | `TOOLS.md` | Theo hướng dẫn ở cuối file đó |
| Playbook, kịch bản diễn tập | `playbooks/` | Đủ tám phần theo `playbooks/README.md` |
| Companion spec | `companion-spec/` | Tiếng Anh, MUST/SHOULD theo RFC 2119. Thay đổi byte layout cần cập nhật cả Appendix B (test vectors) |
| Công cụ xuất PDF | `pdf/` | Chạy `python3 pdf/build.py` và kiểm tra PDF trước khi gửi |

Không commit PDF. PDF được build và đính kèm khi phát hành.

## Quy ước viết

- Guideline và playbook viết bằng tiếng Việt, xưng "mình". Thuật ngữ kỹ thuật giữ nguyên tiếng Anh khi không có từ tiếng Việt thông dụng (agent, tool, sandbox, egress), và thêm vào bảng thuật ngữ ở Phụ lục F khi dùng lần đầu.
- Mức yêu cầu dùng đúng ba chữ **Bắt buộc**, **Nên**, **Tùy chọn** theo Mục 0.5.
- Không viết tuyên bố mạnh hơn điều phép kiểm chứng chứng minh được.
- Tên công cụ, lệnh, đường dẫn đặt trong `code`.

## Giấy phép của đóng góp

Khi gửi Pull Request, bạn đồng ý rằng phần đóng góp được phát hành theo giấy phép của phần repo tương ứng: CC BY 4.0 cho tài liệu, Apache 2.0 cho mã nguồn (xem README).
