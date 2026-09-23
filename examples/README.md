# Cấu hình mẫu đã kiểm thử

Mỗi thư mục ở đây là một cấu hình dùng được ngay cho một phần của ASAL-0 và ASAL-1. Chỉ những cấu hình đã chạy thử và đã qua phép kiểm chứng bằng [`checks/asal_check.py`](../checks/README.md) mới được đưa vào đây. Mỗi README ghi rõ đã thử trên nền tảng và phiên bản nào.

| Thư mục | Dùng cho | Control | Đã thử |
| :--- | :--- | :--- | :--- |
| [devcontainer/](devcontainer/README.md) | Chạy agent, kể cả chế độ tự động, trong container chỉ có đường ra qua proxy allowlist | ISO-01, ISO-03, ISO-04, NET-01, NET-02 | Docker Desktop 29.6 trên macOS |
| [srt/](srt/README.md) | Bọc agent hoặc MCP server local bằng Anthropic Sandbox Runtime trên máy trạm | ISO-02, ISO-03, NET-01, NET-02 | `srt` 0.0.77 trên macOS |

Cấu hình mẫu là điểm xuất phát, không phải chứng nhận. Sau khi sửa cho hệ thống của mình (allowlist, đường dẫn, client agent), chạy lại phép kiểm chứng: kết quả trên máy bạn mới là kết quả đáng tin.

Có cấu hình đã thử cho nền tảng khác (Linux với bubblewrap hay Landlock, Windows Sandbox, WSL2, Kubernetes)? Gửi Pull Request kèm kết quả `checks/asal_check.py --json` chạy bên trong môi trường đó.
