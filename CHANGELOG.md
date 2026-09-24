# Changelog

Phiên bản của guideline theo dạng `MAJOR.MINOR.PATCH`. Mỗi phiên bản phát hành có một git tag `vX.Y.Z` và PDF đính kèm ở trang Releases. Companion spec có phiên bản riêng (`aab-00`, `aab-01`, …), ghi trong bảng tương thích ở Mục 11 của spec.

## [Chưa phát hành]

- `checks/asal.py` v0.1: công cụ đánh giá tư thế agent cho cả tổ chức, gồm `collect`, `probe` (mã probe ổn định), `report` (theo cấp ASAL, với policy và xác nhận tay); ma trận control sinh từ bảng 3.4; tám môi trường cố ý cấu hình sai chạy trong CI. `checks/asal_check.py` vẫn chạy được, dưới dạng tên cũ.
- `examples/claude-code/`: settings của Claude Code đã kiểm thử.
- `TOOLS.md`: bảng "Công cụ đóng boundary nào".

## [0.1.0] · 23/09/2026

Public draft đầu tiên. Nội dung đóng băng để nhận góp ý đến hết 31/12/2026.

- Guideline: mô hình mối đe dọa, sáu nguyên lý thiết kế, bốn cấp ASAL (ASAL-3 chia hai profile 3a và 3b), 47 control trong chín miền D1 đến D9, bản đồ công cụ mã nguồn mở và khoảng trống, các phụ lục A đến F.
- `TOOLS.md`: bản sống của bảng công cụ ở Mục 5.1, có link nguồn.
- `playbooks/`: ba playbook sự cố theo OBS-06 (prompt injection và exfil, MCP server độc hoặc rug pull, credential bị lộ), quy trình break-glass, hướng dẫn diễn tập.
- `companion-spec/`: bản nháp `aab-00` của *Agent Action Binding: Wire Format and Test Vectors*, gồm cấu trúc spec, đề xuất wire format, mã lỗi, danh mục test vectors và các câu hỏi mở. Chưa dùng để cài đặt được.
