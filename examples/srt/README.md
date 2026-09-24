# Anthropic Sandbox Runtime (`srt`)

Hai cấu hình cho [`srt`](https://github.com/anthropics/sandbox-runtime), dùng để bọc client agent, MCP server local, hay bất kỳ lệnh nào trên máy trạm (ISO-02, ISO-03, NET-01).

| File | Cách chặn đọc | Khi nào dùng |
| :--- | :--- | :--- |
| `srt-denylist.json` | Cấm đọc các vị trí credential đã biết (danh sách ở ISO-03) | Khi agent cần đọc công cụ và cấu hình ngoài workspace |
| `srt-workspace-only.json` | Cấm đọc cả thư mục home, chỉ mở lại workspace | Chặt hơn; không phụ thuộc vào việc liệt kê đủ danh sách |

`srt` mặc định cho đọc ở mọi nơi trừ đường dẫn trong `denyRead`. Với `srt-denylist.json`, vị trí credential nào không có trong danh sách thì vẫn đọc được. Nếu dùng được, hãy ưu tiên `srt-workspace-only.json`.

Cả hai cấu hình đều:

- chỉ cho ghi vào workspace và `/tmp`, trừ `.env`, `.mcp.json`, `.claude`, `.cursor`, `.vscode`, `.git/hooks`: agent không tự sửa được cấu hình MCP, cấu hình client hay git hook của chính dự án (SC-02, MEM-02);
- chỉ cho mạng tới một allowlist ngắn qua proxy của `srt`;
- giữ mặc định chặn UNIX socket của `srt`, nên SSH agent và Docker socket không tới được.

## Dùng

```bash
npm install -g @anthropic-ai/sandbox-runtime@<phiên-bản-đã-xem>
cd <thư-mục-dự-án>
srt --settings /đường/dẫn/srt-workspace-only.json <lệnh chạy agent hoặc MCP server>
```

Chạy trong thư mục dự án, vì `.` trong cấu hình là thư mục hiện tại. Sửa `allowedDomains` cho đúng client và registry mình dùng. Với lệnh có nhiều cờ, bọc bằng `sh -c '...'` nếu `srt` hiểu nhầm cờ của lệnh là cờ của nó.

## Kết quả kiểm thử

`srt` 0.0.77 trên macOS. Chạy `srt --settings <file> python3 checks/asal.py probe` trong một workspace thử:

| Phép thử | `srt-denylist.json` | `srt-workspace-only.json` |
| :--- | :--- | :--- |
| ISO-03: đọc `~/.ssh`, `~/.docker/config.json`, `~/.config/gh`, lịch sử shell, profile trình duyệt | Đạt: bị chặn | Đạt: bị chặn |
| ISO-03: đọc `~/.ssh` qua symlink trong workspace | Đạt | Đạt |
| ISO-03: ghi vào home ngoài workspace; ghi vào `.mcp.json` trong workspace | Đạt: bị chặn | Đạt: bị chặn |
| ISO-03: SSH agent, Docker socket | Đạt: không kết nối được | Đạt |
| NET-01: TCP thẳng tới domain, IPv4, IPv6; UDP | Đạt: *Operation not permitted* | Đạt |
| NET-01: proxy của `srt` cho CONNECT tới `example.org` | Đạt: 403 | Đạt: 403 |
| NET-02: DNS thẳng qua UDP, TCP, DoT; tự phân giải tên miền | Đạt | Đạt |
| Domain được phép: `api.anthropic.com`, `registry.npmjs.org` | Tới được (404, 200) | Tới được (404, 200) |

Keychain của macOS chưa được thử (cần `--keychain-item` với một item có thật). Chưa thử trên Linux, nơi `srt` dùng bubblewrap và cách khớp đường dẫn khác macOS (xem README của `srt`).
