# Claude Code: settings cho ASAL-0 và phần máy trạm của ASAL-1

`settings.json` bật sandbox của Claude Code và đóng những đường mà sandbox mặc định để hở: đọc credential ngoài workspace, tool file built-in đọc ra ngoài, và chế độ bỏ qua phê duyệt. Cần Claude Code 2.1.257 trở lên.

## Đặt ở đâu

| Mục đích | Vị trí |
| :--- | :--- |
| Cá nhân | `~/.claude/settings.json` (gộp vào file đang có) |
| Tổ chức, áp cho mọi người | `managed-settings.json` trong thư mục hệ thống: macOS `/Library/Application Support/ClaudeCode/`, Linux và WSL `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\` ([managed settings](https://code.claude.com/docs/en/managed-settings.md)) |
| Thử trước khi áp | `claude --settings <đường dẫn tới settings.json>`: chỉ áp cho phiên đó |

**Không đặt ở `.claude/settings.json` của project.** `sandbox.network.strictAllowlist` chỉ được đọc từ settings user hoặc managed, nên repo không bật hay tắt được nó ([settings reference](https://code.claude.com/docs/en/settings-reference.md)). Cũng vì thế, một repo clone về không thể nới lỏng cấu hình này.

## Từng key làm gì

| Key | Tác dụng | Control |
| :--- | :--- | :--- |
| `sandbox.enabled` | Lệnh Bash, PowerShell, Monitor và tiến trình con chạy trong sandbox của hệ điều hành | ISO-02 |
| `sandbox.failIfUnavailable` | Không mở được sandbox (ví dụ Linux thiếu `bubblewrap` hoặc `socat`) thì Claude Code không khởi động, thay vì lặng lẽ chạy không sandbox | ISO-02 |
| `sandbox.allowUnsandboxedCommands: false` | Claude không được chạy lại một lệnh bị chặn ở ngoài sandbox | ISO-02 |
| `sandbox.network.strictAllowlist` và `allowedDomains` | Lệnh trong sandbox chỉ ra được các domain trong danh sách; domain khác bị từ chối chứ không hỏi | NET-01 |
| `permissions.blockReadsOutsideWorkingDirectories` | Tool Read, Grep, Glob, LSP **và** lệnh trong sandbox không đọc được thư mục home và volume ngoài thư mục làm việc. Chặn theo kiểu mặc định cấm, không phụ thuộc vào việc liệt kê đủ vị trí credential | ISO-03 |
| `permissions.disableBypassPermissionsMode` | Từ chối cờ `--dangerously-skip-permissions` và chế độ `bypassPermissions` | ACT-03 |
| `deny`: `Read(./.env)`, `Read(./.env.*)` | Tool file built-in không đọc `.env` trong workspace. Deny rule `Read` cũng chặn Edit và Write trên cùng đường dẫn | CRED-01 |
| `deny`: `Edit(./.mcp.json)`, `Edit(./.claude/**)` | Agent không tự thêm MCP server hay sửa settings, hook của chính project | SC-02, MEM-02 |

Lệnh trong sandbox vốn đã không ghi được vào `.mcp.json`, thư mục `.claude`, file khởi động shell và `.git/hooks` ([protected paths](https://code.claude.com/docs/en/sandboxing.md)). Hai deny rule `Edit` đóng cùng đường đó cho tool file built-in.

## Sửa cho việc của mình

- **`allowedDomains`:** thêm registry và API mà công việc thật cần. Chạy một tuần rồi mới thêm, theo NET-01; không dùng wildcard rộng.
- **Tool cần đọc file trong home**, như `~/.gitconfig` hay `~/.npmrc`: mở lại từng đường dẫn bằng `sandbox.filesystem.allowRead`, đừng tắt `blockReadsOutsideWorkingDirectories`.
- **Tổ chức:** Claude Code gộp các mảng như `allowedDomains` từ mọi scope, nên người dùng vẫn thêm được domain. Muốn chỉ chấp nhận danh sách của tổ chức, xem `sandbox.network.allowManagedDomainsOnly` trong settings reference. Key này chưa được thử ở đây.

## Cấu hình này không bao được gì

- **Hook.** Hook chạy ngoài sandbox, theo tài liệu và theo phép thử ở [`checks/`](../../checks/README.md). Đừng cài hook từ nguồn không tin cậy.
- **MCP server local.** Claude Code không chạy MCP server trong sandbox của nó. Bọc riêng bằng `srt` ([`examples/srt`](../srt/README.md)) hoặc chạy cả client trong container ([`examples/devcontainer`](../devcontainer/README.md)).
- **WebFetch.** Tool này chịu permission rule, không chịu sandbox mạng. Cấu hình này không giới hạn nó và chưa thử nó.
- **Exfil qua domain đã được phép** (NET-03), và mọi việc agent làm trong chính workspace.

## Kết quả kiểm thử

Claude Code 2.1.273 trên macOS. Chạy `claude --settings examples/claude-code/settings.json` trong một workspace thử có một file `.env` giả, cộng một file giả `~/asal-canary.txt` ngoài workspace, để thử tool Read mà không đụng tới secret thật.

| Phép thử | Kết quả |
| :--- | :--- |
| `checks/asal_check.py probe` qua tool Bash: ISO-01, ISO-03, NET-01, NET-02 | Đạt hết. `~/.ssh` (kể cả qua symlink), `~/.config/gh/hosts.yml`, `~/.docker/config.json` và lịch sử shell không đọc được; không ghi được vào home; không tới được SSH agent; không có đường mạng thẳng qua IPv4, IPv6 hay UDP; proxy của sandbox trả 403 cho `example.org` |
| Tool Read đọc `~/asal-canary.txt` (ngoài workspace) | Bị chặn |
| Tool Read đọc `.env` trong workspace | Bị chặn |
| Tạo `.mcp.json` trong workspace | Bị chặn |
| `claude --dangerously-skip-permissions` | Phiên vẫn mở nhưng ở chế độ thường, kèm thông báo "Bypass permissions mode was disabled by settings" |

So sánh: trong cùng máy, một lần thử trước chỉ bật sandbox với `denyRead: ["~/.ssh"]`. Khi đó `~/.ssh` bị chặn nhưng lệnh Bash vẫn đọc được `~/.config/gh/hosts.yml` và `~/.docker/config.json`, vì sandbox mặc định cho đọc mọi nơi ngoài `denyRead`. Đó là lý do cấu hình này dùng `blockReadsOutsideWorkingDirectories` thay vì một danh sách cấm.

Chưa thử: Linux và WSL2, Windows, managed settings thật, `allowManagedDomainsOnly`, WebFetch.
