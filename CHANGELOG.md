# Changelog

Phiên bản của guideline theo dạng `MAJOR.MINOR.PATCH`. Mỗi phiên bản phát hành có một git tag `vX.Y.Z` và PDF đính kèm ở trang Releases. Companion spec có phiên bản riêng (`aab-00`, `aab-01`, …), ghi trong bảng tương thích ở Mục 11 của spec.

## [Chưa phát hành]

- `checks/asal.py` v0.1: công cụ đánh giá tư thế agent cho cả tổ chức, gồm `collect`, `probe` (mã probe ổn định), `report` (theo cấp ASAL, với policy và xác nhận tay); ma trận control sinh từ bảng 3.4; tám môi trường cố ý cấu hình sai chạy trong CI. `checks/asal_check.py` vẫn chạy được, dưới dạng tên cũ.
- `checks/asal.py` 0.1.1, sửa từ lần chạy trên một máy dev thật:
  - `collect` đọc plugin đang bật của Codex và Claude Code: MCP server, connector và hook của chúng vào danh mục SC-01; plugin bật từ settings cấp project vào SC-02; plugin không đọc được thành *Cần xem*.
  - Lệnh khởi động MCP là đường dẫn tương đối thành *Cần xem* (SC-03), trừ khi `cwd` là đường dẫn tuyệt đối.
  - File cấu hình bị sandbox giấu thành *Chưa kiểm được* thay vì bị coi là không có. Trước đây chạy `collect` trong sandbox cho ISO-02 *Chưa đạt* và SC-01 *Không áp dụng*, cả hai đều sai.
  - Mật khẩu proxy của sandbox (biến có giá trị trùng mật khẩu trong `HTTPS_PROXY` trỏ về localhost) không bị tính là secret ở CRED-01.
  - `report` có thêm phần *Cấp kế tiếp*.
  - Đọc cấu hình MCP của Antigravity và opencode (v1 và v2, JSONC); server tắt (`enabled: false`, `disabled: true`) không tính; file cấu hình rỗng không còn bị báo là không đọc được.
  - File token của chính các agent (Codex, Claude Code trên Linux, Gemini và Antigravity, opencode) vào danh sách credential của ISO-03.
  - Client agent khác có trên máy thành *Cần xem* ở ISO-02; Antigravity CLI tắt sandbox hay chạy tool không hỏi thành *Chưa đạt*.
- `examples/claude-code/`: settings của Claude Code đã kiểm thử.
- `TOOLS.md`: bảng "Công cụ đóng boundary nào".

## [0.1.0] · 23/09/2026

Public draft đầu tiên. Nội dung đóng băng để nhận góp ý đến hết 31/12/2026.

- Guideline: mô hình mối đe dọa, sáu nguyên lý thiết kế, bốn cấp ASAL (ASAL-3 chia hai profile 3a và 3b), 47 control trong chín miền D1 đến D9, bản đồ công cụ mã nguồn mở và khoảng trống, các phụ lục A đến F.
- `TOOLS.md`: bản sống của bảng công cụ ở Mục 5.1, có link nguồn.
- `playbooks/`: ba playbook sự cố theo OBS-06 (prompt injection và exfil, MCP server độc hoặc rug pull, credential bị lộ), quy trình break-glass, hướng dẫn diễn tập.
- `companion-spec/`: bản nháp `aab-00` của *Agent Action Binding: Wire Format and Test Vectors*, gồm cấu trúc spec, đề xuất wire format, mã lỗi, danh mục test vectors và các câu hỏi mở. Chưa dùng để cài đặt được.
